"""
Repository layer — every SQL statement the application runs lives here.

Two design decisions worth calling out at interview time:

1. **Batched writes.** The gateway must answer a DNS query in single-digit
   milliseconds; it cannot wait on a database round-trip. Detections are
   pushed onto an in-memory queue and flushed by a background task in
   configurable batches. A DNS resolver that blocks on I/O is a DNS outage.

2. **One dialect-neutral SQL surface.** Queries use `?` placeholders and
   ANSI-ish syntax; `db.py` rewrites them for asyncpg. Only the timestamp
   representation differs (REAL epoch on SQLite, TIMESTAMPTZ on PostgreSQL),
   handled by `_ts()`.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hashlib
import time
from collections.abc import Iterable, Sequence
from typing import Any

from ..logging_utils import get_logger
from ..types import Detection
from .db import Database

log = get_logger("storage.repo")

EVENT_COLUMNS = [
    "query_id", "ts", "source_ip", "qname", "registrable", "subdomain", "tld",
    "qtype", "transport", "qname_length", "label_count", "entropy", "sub_entropy",
    "score", "supervised_score", "anomaly_score", "heuristic_score", "verdict",
    "threat_class", "intel_hit", "reasons", "latency_ms", "is_blocked",
    "truth_label", "family",
]

_INSERT_EVENT = (
    f"INSERT INTO dns_events ({', '.join(EVENT_COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in EVENT_COLUMNS)})"
)


class Repository:
    """High-level data access + the write-behind buffer."""

    def __init__(self, db: Database, batch_size: int = 200,
                 flush_interval: float = 1.0) -> None:
        self.db = db
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._buffer: list[tuple] = []
        self._lock = asyncio.Lock()
        self._alerts: dict[str, dict[str, Any]] = {}
        self._alert_lock = asyncio.Lock()
        self._flusher: asyncio.Task | None = None
        self._closed = False
        self.written = 0
        # Hot caches — an inline resolver cannot hit the DB on every packet.
        self._intel_cache: dict[str, dict[str, Any] | None] = {}
        self._allow_cache: dict[str, bool] = {}
        self._allow_rules: list[tuple[str, str]] = []
        self._intel_by_type: dict[str, dict[str, dict[str, Any]]] = {}

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        await self.refresh_caches()
        self._flusher = asyncio.create_task(self._flush_loop())

    async def close(self) -> None:
        self._closed = True
        if self._flusher:
            self._flusher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._flusher
        await self.flush()
        await self.flush_alerts()

    def _ts(self, epoch: float) -> Any:
        if self.db.dialect == "postgres":
            return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
        return float(epoch)

    # ------------------------------------------------------------------ #
    # writes
    # ------------------------------------------------------------------ #
    async def record(self, detection: Detection) -> None:
        row = detection.to_row()
        row["ts"] = self._ts(row["ts"])
        values = tuple(row[c] for c in EVENT_COLUMNS)
        async with self._lock:
            self._buffer.append(values)
            full = len(self._buffer) >= self.batch_size
        if full:
            await self.flush()

    async def record_many(self, detections: Iterable[Detection]) -> None:
        for d in detections:
            await self.record(d)

    async def flush(self) -> int:
        async with self._lock:
            if not self._buffer:
                return 0
            batch, self._buffer = self._buffer, []
        try:
            await self.db.executemany(_INSERT_EVENT, batch)
            self.written += len(batch)
            return len(batch)
        except Exception as exc:                            # noqa: BLE001
            log.error("flush failed (%d rows dropped): %s", len(batch), exc)
            return 0

    async def _flush_loop(self) -> None:
        while not self._closed:
            await asyncio.sleep(self.flush_interval)
            await self.flush()
            await self.flush_alerts()

    async def record_stats(self, queries: int, blocked: int, suspicious: int,
                           cache_hits: int, latencies: Sequence[float]) -> None:
        lat = sorted(latencies) or [0.0]
        def pct(p: float) -> float:
            return float(lat[min(int(len(lat) * p), len(lat) - 1)])
        await self.db.execute(
            "INSERT INTO gateway_stats "
            "(ts, queries, blocked, suspicious, cache_hits, p50_latency, p95_latency, p99_latency) "
            "VALUES (?,?,?,?,?,?,?,?)",
            self._ts(time.time()), queries, blocked, suspicious, cache_hits,
            pct(0.50), pct(0.95), pct(0.99),
        )

    async def register_model(self, version: str, algorithm: str, feature_count: int,
                             train_rows: int, metrics: dict[str, float],
                             notes: str = "") -> None:
        await self.db.execute(
            "INSERT INTO model_registry (model_version, algorithm, feature_count, "
            "train_rows, accuracy, precision_val, recall_val, f1, roc_auc, notes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            version, algorithm, feature_count, train_rows,
            metrics.get("accuracy"), metrics.get("precision"), metrics.get("recall"),
            metrics.get("f1"), metrics.get("roc_auc"), notes,
        )

    async def upsert_baseline(self, zone: str, entropy: float, qname_len: int) -> None:
        if self.db.dialect == "postgres":
            await self.db.execute("SELECT fn_upsert_baseline(?,?,?,?)",
                                  zone, float(entropy), int(qname_len), "")
        else:
            await self.db.execute(
                "INSERT INTO domain_baseline "
                "  (registrable, query_count, unique_subdomains, mean_entropy, mean_qname_len) "
                "VALUES (?, 1, 1, ?, ?) "
                "ON CONFLICT(registrable) DO UPDATE SET "
                "  query_count    = query_count + 1, "
                "  last_seen      = strftime('%s','now'), "
                "  mean_entropy   = mean_entropy + (? - mean_entropy)/(query_count+1), "
                "  mean_qname_len = mean_qname_len + (? - mean_qname_len)/(query_count+1)",
                zone, float(entropy), int(qname_len), float(entropy), int(qname_len),
            )

    async def raise_alert(self, source_ip: str, zone: str, threat_class: str,
                          score: float, bytes_exfil: int = 0, summary: str = "") -> None:
        """Aggregate in memory; the flush loop writes one batch per interval.

        Alerts are inherently repetitive — a single tunnelling session produces
        hundreds of malicious queries that all belong to *one* incident. Doing a
        database round-trip per query would be both slow and wrong: the analyst
        wants one row that says "412 hits", not 412 rows. So we deduplicate by
        fingerprint in memory and upsert the aggregate.
        """
        fp = hashlib.sha256(f"{source_ip}|{zone}|{threat_class}".encode()).hexdigest()
        async with self._alert_lock:
            agg = self._alerts.get(fp)
            if agg is None:
                self._alerts[fp] = {
                    "fingerprint": fp, "source_ip": source_ip, "registrable": zone,
                    "threat_class": threat_class, "hits": 1,
                    "max_score": float(score), "bytes": int(bytes_exfil),
                    "summary": summary[:400],
                }
            else:
                agg["hits"] += 1
                agg["max_score"] = max(agg["max_score"], float(score))
                agg["bytes"] += int(bytes_exfil)

    async def flush_alerts(self) -> int:
        async with self._alert_lock:
            if not self._alerts:
                return 0
            pending = list(self._alerts.values())
            self._alerts = {}
        rows = [
            (a["fingerprint"], a["source_ip"], a["registrable"], a["threat_class"],
             max(1, min(10, int(a["max_score"] * 10))), a["hits"], a["max_score"],
             a["bytes"], a["summary"],
             a["hits"], a["max_score"], a["bytes"],
             max(1, min(10, int(a["max_score"] * 10))))
            for a in pending
        ]
        if self.db.dialect == "postgres":
            sql = (
                "INSERT INTO alerts (fingerprint, source_ip, registrable, threat_class, "
                "severity, hit_count, max_score, bytes_exfil, summary) "
                "VALUES (?,?::inet,?,?,?,?,?,?,?) "
                "ON CONFLICT (fingerprint) DO UPDATE SET "
                "  hit_count = alerts.hit_count + ?, updated_at = now(), "
                "  max_score = GREATEST(alerts.max_score, ?), "
                "  bytes_exfil = alerts.bytes_exfil + ?, "
                "  severity = GREATEST(alerts.severity, ?)"
            )
        else:
            sql = (
                "INSERT INTO alerts (fingerprint, source_ip, registrable, threat_class, "
                "severity, hit_count, max_score, bytes_exfil, summary) "
                "VALUES (?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(fingerprint) DO UPDATE SET "
                "  hit_count = hit_count + ?, updated_at = strftime('%s','now'), "
                "  max_score = MAX(max_score, ?), bytes_exfil = bytes_exfil + ?, "
                "  severity  = MAX(severity, ?)"
            )
        try:
            await self.db.executemany(sql, rows)
            return len(rows)
        except Exception as exc:                            # noqa: BLE001
            log.error("alert flush failed (%d): %s", len(rows), exc)
            return 0

    # ------------------------------------------------------------------ #
    # threat intelligence (cached)
    # ------------------------------------------------------------------ #
    async def refresh_caches(self) -> None:
        """Pull the whole allowlist and IOC set into memory.

        An inline resolver cannot afford a database round-trip per packet, and
        it does not need one: even a large curated feed is a few hundred
        thousand strings, which is a few tens of MB of Python dict. Lookups
        then cost a hash, not a query. `chronodns intel add` refreshes this.
        """
        try:
            rules = await self.db.fetch("SELECT pattern, match_type FROM allowlist")
            self._allow_rules = [(r["pattern"], r["match_type"]) for r in rules]
            self._allow_cache.clear()

            rows = await self.db.fetch(
                "SELECT indicator, ioc_type, category, severity, source "
                "FROM threat_intel ORDER BY severity ASC")
            self._intel_by_type = {"domain": {}, "zone": {}, "tld": {}, "ip": {}}
            for r in rows:
                bucket = self._intel_by_type.setdefault(r["ioc_type"], {})
                bucket[r["indicator"]] = dict(r)     # higher severity overwrites
            self._intel_cache.clear()
            log.info("caches refreshed: %d allowlist rules, %d indicators",
                     len(self._allow_rules), len(rows))
        except Exception as exc:                            # noqa: BLE001
            log.warning("cache refresh skipped: %s", exc)

    def intel_lookup_sync(self, qname: str, registrable: str, tld: str
                          ) -> dict[str, Any] | None:
        """In-memory IOC lookup — no I/O, safe to call on the hot path."""
        by = self._intel_by_type
        return (by.get("domain", {}).get(qname)
                or by.get("zone", {}).get(registrable)
                or by.get("tld", {}).get(tld))

    def is_allowlisted(self, qname: str) -> bool:
        cached = self._allow_cache.get(qname)
        if cached is not None:
            return cached
        hit = False
        for pattern, kind in self._allow_rules:
            if kind == "exact" and qname == pattern or kind == "suffix" and (qname == pattern or qname.endswith("." + pattern)):
                hit = True
            if hit:
                break
        if len(self._allow_cache) < 50_000:
            self._allow_cache[qname] = hit
        return hit

    async def intel_lookup(self, qname: str, registrable: str, tld: str
                           ) -> dict[str, Any] | None:
        """Async form, kept for the REST API. The gateway uses the sync form."""
        if self._intel_by_type:
            return self.intel_lookup_sync(qname, registrable, tld)
        key = registrable or qname
        if key in self._intel_cache:
            return self._intel_cache[key]
        rows = await self.db.fetch(
            "SELECT indicator, ioc_type, category, severity, source FROM threat_intel "
            "WHERE (ioc_type='domain' AND indicator=?) "
            "   OR (ioc_type='zone'   AND indicator=?) "
            "   OR (ioc_type='tld'    AND indicator=?) "
            "ORDER BY severity DESC LIMIT 1",
            qname, registrable, tld,
        )
        result = rows[0] if rows else None
        if len(self._intel_cache) < 100_000:
            self._intel_cache[key] = result
        return result

    async def add_intel(self, indicator: str, ioc_type: str = "domain",
                        category: str = "malware", severity: int = 7,
                        source: str = "manual", notes: str = "") -> None:
        conflict = ("ON CONFLICT (indicator, ioc_type) DO UPDATE SET severity = EXCLUDED.severity"
                    if self.db.dialect == "postgres"
                    else "ON CONFLICT(indicator, ioc_type) DO UPDATE SET severity = excluded.severity")
        await self.db.execute(
            "INSERT INTO threat_intel (indicator, ioc_type, category, severity, source, notes) "
            f"VALUES (?,?,?,?,?,?) {conflict}",
            indicator.lower().strip(), ioc_type, category, int(severity), source, notes,
        )
        self._intel_cache.pop(indicator.lower().strip(), None)

    async def add_allowlist(self, pattern: str, match_type: str = "suffix",
                            reason: str = "") -> None:
        await self.db.execute(
            "INSERT INTO allowlist (pattern, match_type, reason) VALUES (?,?,?) "
            "ON CONFLICT(pattern) DO NOTHING"
            if self.db.dialect != "postgres" else
            "INSERT INTO allowlist (pattern, match_type, reason) VALUES (?,?,?) "
            "ON CONFLICT (pattern) DO NOTHING",
            pattern.lower().strip(), match_type, reason,
        )
        await self.refresh_caches()

    # ------------------------------------------------------------------ #
    # reads — these power the CLI reports and the web dashboard
    # ------------------------------------------------------------------ #
    def _since(self, minutes: int) -> Any:
        """Window start. `minutes <= 0` means "everything on record".

        A forensic store is usually queried over whatever it holds, not over
        the last N minutes of wall clock — and a replayed capture can carry
        timestamps from any point in the past.
        """
        if minutes <= 0:
            return self._ts(0.0)
        return self._ts(time.time() - minutes * 60)

    async def summary(self, minutes: int = 1440) -> dict[str, Any]:
        row = await self.db.fetchrow(
            "SELECT COUNT(*) AS events, "
            "       COALESCE(SUM(is_blocked),0) AS blocked, "
            "       COUNT(DISTINCT source_ip) AS hosts, "
            "       COUNT(DISTINCT registrable) AS zones, "
            "       COALESCE(AVG(score),0) AS avg_score, "
            "       COALESCE(MAX(score),0) AS max_score, "
            "       COALESCE(AVG(latency_ms),0) AS avg_latency "
            "FROM dns_events WHERE ts >= ?",
            self._since(minutes),
        )
        return row or {}

    async def class_breakdown(self, minutes: int = 1440) -> list[dict[str, Any]]:
        return await self.db.fetch(
            "SELECT threat_class, COUNT(*) AS n, COALESCE(SUM(is_blocked),0) AS blocked, "
            "       ROUND(AVG(score),4) AS avg_score "
            "FROM dns_events WHERE ts >= ? GROUP BY threat_class ORDER BY n DESC",
            self._since(minutes),
        )

    async def top_threats(self, limit: int = 20, minutes: int = 1440) -> list[dict[str, Any]]:
        return await self.db.fetch(
            "SELECT ts, source_ip, qname, qtype, ROUND(score,3) AS score, "
            "       threat_class, verdict, ROUND(entropy,2) AS entropy, reasons "
            "FROM dns_events WHERE ts >= ? ORDER BY score DESC, ts DESC LIMIT ?",
            self._since(minutes), limit,
        )

    async def top_talkers(self, limit: int = 15, minutes: int = 1440) -> list[dict[str, Any]]:
        return await self.db.fetch(
            "SELECT source_ip, COUNT(*) AS queries, COUNT(DISTINCT registrable) AS zones, "
            "       COALESCE(SUM(is_blocked),0) AS blocked, ROUND(AVG(score),3) AS avg_score, "
            "       ROUND(MAX(score),3) AS max_score "
            "FROM dns_events WHERE ts >= ? GROUP BY source_ip "
            "ORDER BY queries DESC LIMIT ?",
            self._since(minutes), limit,
        )

    async def tunnel_candidates(self, limit: int = 15, minutes: int = 1440
                                ) -> list[dict[str, Any]]:
        return await self.db.fetch(
            "SELECT registrable, COUNT(*) AS queries, "
            "       COUNT(DISTINCT subdomain) AS unique_subs, "
            "       SUM(LENGTH(subdomain)) AS bytes_uploaded, "
            "       ROUND(AVG(sub_entropy),3) AS avg_sub_entropy, "
            "       COUNT(DISTINCT source_ip) AS hosts, "
            "       ROUND(MAX(score),3) AS peak_score "
            "FROM dns_events WHERE ts >= ? GROUP BY registrable "
            "HAVING COUNT(*) >= 5 AND AVG(sub_entropy) > 2.5 "
            "ORDER BY bytes_uploaded DESC LIMIT ?",
            self._since(minutes), limit,
        )

    async def beacon_candidates(self, limit: int = 15) -> list[dict[str, Any]]:
        """Window-function beacon hunt — works on both dialects."""
        if self.db.dialect == "postgres":
            sql = (
                "WITH gaps AS (SELECT source_ip, registrable, "
                "  EXTRACT(EPOCH FROM (ts - LAG(ts) OVER (PARTITION BY source_ip, registrable "
                "  ORDER BY ts))) AS gap FROM dns_events) "
                "SELECT source_ip, registrable, COUNT(*) AS samples, "
                "  ROUND(AVG(gap)::numeric,2) AS interval_s, "
                "  ROUND(STDDEV_POP(gap)::numeric,3) AS jitter_s, "
                "  ROUND((STDDEV_POP(gap)/NULLIF(AVG(gap),0))::numeric,4) AS cv "
                "FROM gaps WHERE gap IS NOT NULL AND gap > 0 "
                "GROUP BY source_ip, registrable HAVING COUNT(*) >= 5 "
                "ORDER BY cv ASC LIMIT ?"
            )
        else:
            sql = (
                "WITH gaps AS (SELECT source_ip, registrable, "
                "  ts - LAG(ts) OVER (PARTITION BY source_ip, registrable ORDER BY ts) AS gap "
                "  FROM dns_events) "
                "SELECT source_ip, registrable, COUNT(*) AS samples, "
                "  ROUND(AVG(gap),2) AS interval_s, "
                "  ROUND(CASE WHEN AVG(gap*gap)-AVG(gap)*AVG(gap) > 0 "
                "        THEN (AVG(gap*gap)-AVG(gap)*AVG(gap)) ELSE 0 END, 4) AS variance_s2, "
                "  ROUND(CASE WHEN AVG(gap) > 0 AND AVG(gap*gap)-AVG(gap)*AVG(gap) > 0 "
                "        THEN (AVG(gap*gap)-AVG(gap)*AVG(gap))/(AVG(gap)*AVG(gap)) "
                "        ELSE 0 END, 5) AS cv_squared "
                "FROM gaps WHERE gap IS NOT NULL AND gap > 0 "
                "GROUP BY source_ip, registrable HAVING COUNT(*) >= 5 "
                "ORDER BY cv_squared ASC LIMIT ?"
            )
        return await self.db.fetch(sql, limit)

    async def host_velocity(self, source_ip: str, limit: int = 50) -> list[dict[str, Any]]:
        if self.db.dialect == "postgres":
            sql = (
                "SELECT ts, qname, ROUND(score::numeric,3) AS score, threat_class, verdict, "
                "  ROUND(AVG(score) OVER (ORDER BY ts ROWS BETWEEN 9 PRECEDING AND CURRENT ROW)::numeric,3) AS score_ma10, "
                "  ROUND(EXTRACT(EPOCH FROM (ts - LAG(ts) OVER (ORDER BY ts)))::numeric,2) AS gap_s "
                "FROM dns_events WHERE source_ip = ?::inet ORDER BY ts DESC LIMIT ?"
            )
        else:
            sql = (
                "SELECT ts, qname, ROUND(score,3) AS score, threat_class, verdict, "
                "  ROUND(AVG(score) OVER (ORDER BY ts ROWS BETWEEN 9 PRECEDING AND CURRENT ROW),3) AS score_ma10, "
                "  ROUND(ts - LAG(ts) OVER (ORDER BY ts), 2) AS gap_s "
                "FROM dns_events WHERE source_ip = ? ORDER BY ts DESC LIMIT ?"
            )
        return await self.db.fetch(sql, source_ip, limit)

    async def open_alerts(self, limit: int = 25) -> list[dict[str, Any]]:
        return await self.db.fetch(
            "SELECT source_ip, registrable, threat_class, severity, hit_count, "
            "       ROUND(max_score,3) AS max_score, bytes_exfil, status, summary "
            "FROM alerts WHERE status='open' "
            "ORDER BY severity DESC, hit_count DESC LIMIT ?",
            limit,
        )

    async def timeline(self, minutes: int = 60, buckets: int = 60) -> list[dict[str, Any]]:
        """Per-bucket counts for the dashboard sparkline."""
        if self.db.dialect == "postgres":
            sql = (
                "SELECT date_trunc('minute', ts) AS bucket, COUNT(*) AS events, "
                "       COALESCE(SUM(is_blocked),0) AS blocked, "
                "       ROUND(AVG(score)::numeric,3) AS avg_score "
                "FROM dns_events WHERE ts >= ? GROUP BY 1 ORDER BY 1"
            )
        else:
            sql = (
                "SELECT CAST(ts/60 AS INTEGER)*60 AS bucket, COUNT(*) AS events, "
                "       COALESCE(SUM(is_blocked),0) AS blocked, "
                "       ROUND(AVG(score),3) AS avg_score "
                "FROM dns_events WHERE ts >= ? GROUP BY bucket ORDER BY bucket"
            )
        return await self.db.fetch(sql, self._since(minutes))

    async def confusion(self) -> list[dict[str, Any]]:
        return await self.db.fetch(
            "SELECT truth_label, threat_class, COUNT(*) AS n FROM dns_events "
            "WHERE truth_label IS NOT NULL GROUP BY truth_label, threat_class "
            "ORDER BY n DESC"
        )

    async def search(self, pattern: str, limit: int = 50) -> list[dict[str, Any]]:
        return await self.db.fetch(
            "SELECT ts, source_ip, qname, qtype, ROUND(score,3) AS score, "
            "       threat_class, verdict FROM dns_events "
            "WHERE qname LIKE ? ORDER BY ts DESC LIMIT ?",
            f"%{pattern.lower()}%", limit,
        )

    async def purge_events(self) -> None:
        await self.db.execute("DELETE FROM dns_events")
        await self.db.execute("DELETE FROM alerts")
