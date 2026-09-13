"""
Dual-backend async database layer.

    CHRONODNS_DB_BACKEND=sqlite    -> aiosqlite, zero install, perfect for demos
    CHRONODNS_DB_BACKEND=postgres  -> asyncpg pool, the production path

Both backends speak the same tiny interface (`execute`, `executemany`,
`fetch`, `fetchrow`, `fetchval`, `script`). Queries are written once using
`?` placeholders and rewritten to `$1..$n` for PostgreSQL, so the repository
layer above never branches on dialect.
"""

from __future__ import annotations

import asyncio
import sqlite3
from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..config import PROJECT_ROOT, DatabaseConfig, get_config
from ..logging_utils import get_logger

log = get_logger("storage.db")

SQL_DIR = PROJECT_ROOT / "sql"


def _to_pg(sql: str) -> str:
    """Rewrite `?` placeholders into `$1, $2, ...` for asyncpg."""
    out, n = [], 0
    in_str = False
    for ch in sql:
        if ch == "'":
            in_str = not in_str
        if ch == "?" and not in_str:
            n += 1
            out.append(f"${n}")
        else:
            out.append(ch)
    return "".join(out)


def split_statements(script: str) -> list[str]:
    """Split a .sql file into statements, respecting $$ ... $$ function bodies."""
    statements, buf, in_dollar = [], [], False
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.startswith("--") and not in_dollar:
            continue
        if stripped.startswith("\\"):     # psql meta-commands: skip in Python
            continue
        if line.count("$$") % 2 == 1:
            in_dollar = not in_dollar
        buf.append(line)
        if not in_dollar and stripped.endswith(";"):
            stmt = "\n".join(buf).strip()
            if stmt.strip(";").strip():
                statements.append(stmt)
            buf = []
    tail = "\n".join(buf).strip()
    if tail.strip(";").strip():
        statements.append(tail)
    return statements


# --------------------------------------------------------------------------- #
class Database(ABC):
    """Minimal async DB facade shared by both backends."""

    dialect: str = "generic"

    @abstractmethod
    async def connect(self) -> None: ...
    @abstractmethod
    async def close(self) -> None: ...
    @abstractmethod
    async def execute(self, sql: str, *args: Any) -> None: ...
    @abstractmethod
    async def executemany(self, sql: str, rows: Sequence[Sequence[Any]]) -> None: ...
    @abstractmethod
    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]: ...
    @abstractmethod
    async def script(self, sql: str) -> None: ...

    async def fetchrow(self, sql: str, *args: Any) -> dict[str, Any] | None:
        rows = await self.fetch(sql, *args)
        return rows[0] if rows else None

    async def fetchval(self, sql: str, *args: Any) -> Any:
        row = await self.fetchrow(sql, *args)
        return next(iter(row.values())) if row else None

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()


# --------------------------------------------------------------------------- #
class SQLiteDatabase(Database):
    """aiosqlite backend. WAL mode keeps readers unblocked while we write."""

    dialect = "sqlite"

    def __init__(self, path: str) -> None:
        self.path = path
        self._conn: Any = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        import aiosqlite

        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.path, timeout=30.0)
        self._conn.row_factory = aiosqlite.Row
        for pragma in (
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=NORMAL",
            "PRAGMA busy_timeout=5000",
            "PRAGMA cache_size=-32000",
        ):
            await self._conn.execute(pragma)
        await self._conn.commit()
        log.info("SQLite backend ready: %s", self.path)

    async def close(self) -> None:
        if self._conn:
            await self._conn.commit()
            await self._conn.close()
            self._conn = None

    async def execute(self, sql: str, *args: Any) -> None:
        async with self._lock:
            await self._conn.execute(sql, args)
            await self._conn.commit()

    async def executemany(self, sql: str, rows: Sequence[Sequence[Any]]) -> None:
        if not rows:
            return
        async with self._lock:
            await self._conn.executemany(sql, rows)
            await self._conn.commit()

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        async with self._lock:
            cur = await self._conn.execute(sql, args)
            rows = await cur.fetchall()
            await cur.close()
        return [dict(r) for r in rows]

    async def script(self, sql: str) -> None:
        async with self._lock:
            await self._conn.executescript(sql)
            await self._conn.commit()


# --------------------------------------------------------------------------- #
class PostgresDatabase(Database):
    """asyncpg connection-pool backend."""

    dialect = "postgres"

    def __init__(self, cfg: DatabaseConfig) -> None:
        self.cfg = cfg
        self._pool: Any = None

    async def connect(self) -> None:
        import asyncpg

        self._pool = await asyncpg.create_pool(
            dsn=self.cfg.dsn,
            min_size=self.cfg.pool_min,
            max_size=self.cfg.pool_max,
            command_timeout=30,
            server_settings={"search_path": "chrono,public",
                             "application_name": "chrono-dns"},
        )
        log.info("PostgreSQL pool ready: %s:%s/%s",
                 self.cfg.host, self.cfg.port, self.cfg.database)

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None

    async def execute(self, sql: str, *args: Any) -> None:
        async with self._pool.acquire() as con:
            await con.execute(_to_pg(sql), *args)

    async def executemany(self, sql: str, rows: Sequence[Sequence[Any]]) -> None:
        if not rows:
            return
        async with self._pool.acquire() as con:
            await con.executemany(_to_pg(sql), rows)

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        async with self._pool.acquire() as con:
            records = await con.fetch(_to_pg(sql), *args)
        return [dict(r) for r in records]

    async def script(self, sql: str) -> None:
        async with self._pool.acquire() as con:
            await con.execute(sql)

    async def listen(self, channel: str, callback) -> None:
        """PostgreSQL LISTEN/NOTIFY — push alerts with zero polling."""
        con = await self._pool.acquire()
        await con.add_listener(channel, callback)
        log.info("LISTENing on channel %s", channel)


# --------------------------------------------------------------------------- #
def make_database(cfg: DatabaseConfig | None = None) -> Database:
    cfg = cfg or get_config().database
    if cfg.is_postgres:
        return PostgresDatabase(cfg)
    return SQLiteDatabase(cfg.sqlite_path)


async def init_schema(db: Database, seed: bool = True, drop: bool = False) -> list[str]:
    """Apply the migration files for whichever dialect is active."""
    folder = SQL_DIR / ("postgres" if db.dialect == "postgres" else "sqlite")
    files = sorted(folder.glob("*.sql"))
    if not seed:
        files = [f for f in files if "seed" not in f.name]
    applied: list[str] = []

    if drop:
        await _drop_all(db)

    for path in files:
        body = path.read_text(encoding="utf-8")
        try:
            if db.dialect == "postgres":
                await db.script(body)
            else:
                await db.script(body)
            applied.append(path.name)
            log.info("applied %s", path.name)
        except Exception as exc:                 # noqa: BLE001
            # Seed files use INSERT OR IGNORE / ON CONFLICT, so duplicates are
            # never fatal; anything else is worth surfacing.
            log.warning("migration %s: %s", path.name, exc)
    return applied


async def _drop_all(db: Database) -> None:
    if db.dialect == "postgres":
        await db.script("DROP SCHEMA IF EXISTS chrono CASCADE;")
    else:
        for table in ("dns_events", "threat_intel", "allowlist", "domain_baseline",
                      "alerts", "model_registry", "gateway_stats"):
            await db.execute(f"DROP TABLE IF EXISTS {table}")
        for view in ("v_recent_threats", "v_host_velocity", "v_tunnel_candidates",
                     "v_beacon_candidates", "v_top_talkers", "v_hourly_rollup"):
            await db.execute(f"DROP VIEW IF EXISTS {view}")


def sync_sqlite_query(path: str, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
    """Blocking helper for CLI report commands that do not need an event loop."""
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(sql, args).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()
