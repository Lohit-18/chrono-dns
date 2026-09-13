"""
Central configuration for Chrono-DNS.

Everything is driven by environment variables (12-factor style) with sane,
zero-cost defaults so the project runs out of the box with **no** external
services:

    * storage  -> SQLite  (file on disk, no server)   [default]
    * storage  -> Postgres (set CHRONODNS_DB_BACKEND=postgres)
    * upstream -> Cloudflare 1.1.1.1 (free)

Load order:  built-in defaults  <  .env file  <  real environment variables.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODEL_DIR = PROJECT_ROOT / "models"
SQL_DIR = PROJECT_ROOT / "sql"
LOG_DIR = PROJECT_ROOT / "data" / "logs"

for _d in (DATA_DIR, MODEL_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# .env loader (dependency-free — we do not want python-dotenv as a hard dep)
# --------------------------------------------------------------------------- #
def load_dotenv(path: Path | None = None, override: bool = False) -> dict[str, str]:
    """Parse a KEY=VALUE .env file into os.environ. Returns what was loaded."""
    path = path or (PROJECT_ROOT / ".env")
    loaded: dict[str, str] = {}
    if not path.exists():
        return loaded
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if override or key not in os.environ:
            os.environ[key] = value
        loaded[key] = value
    return loaded


load_dotenv()


def _env(key: str, default: Any, cast: type = str) -> Any:
    raw = os.environ.get(f"CHRONODNS_{key}")
    if raw is None:
        return default
    if cast is bool:
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if cast is list:
        return [x.strip() for x in raw.split(",") if x.strip()]
    try:
        return cast(raw)
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- #
# Config sections
# --------------------------------------------------------------------------- #
@dataclass
class GatewayConfig:
    """The inline DNS proxy that endpoints point at."""

    listen_host: str = field(default_factory=lambda: _env("LISTEN_HOST", "127.0.0.1"))
    listen_port: int = field(default_factory=lambda: _env("LISTEN_PORT", 5353, int))
    enable_tcp: bool = field(default_factory=lambda: _env("ENABLE_TCP", True, bool))
    upstream: list[str] = field(
        default_factory=lambda: _env("UPSTREAM", ["1.1.1.1", "9.9.9.9", "8.8.8.8"], list)
    )
    upstream_port: int = field(default_factory=lambda: _env("UPSTREAM_PORT", 53, int))
    upstream_timeout: float = field(default_factory=lambda: _env("UPSTREAM_TIMEOUT", 2.5, float))
    cache_ttl_floor: int = field(default_factory=lambda: _env("CACHE_TTL_FLOOR", 30, int))
    cache_max_entries: int = field(default_factory=lambda: _env("CACHE_MAX", 20_000, int))
    sinkhole_ip: str = field(default_factory=lambda: _env("SINKHOLE_IP", "0.0.0.0"))
    sinkhole_ipv6: str = field(default_factory=lambda: _env("SINKHOLE_IPV6", "::"))
    max_concurrent: int = field(default_factory=lambda: _env("MAX_CONCURRENT", 512, int))


@dataclass
class DatabaseConfig:
    """Dual backend: SQLite (default, zero-install) or PostgreSQL (production)."""

    backend: str = field(default_factory=lambda: _env("DB_BACKEND", "sqlite").lower())
    sqlite_path: str = field(
        default_factory=lambda: _env("SQLITE_PATH", str(DATA_DIR / "chronodns.db"))
    )
    host: str = field(default_factory=lambda: _env("PG_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env("PG_PORT", 5432, int))
    user: str = field(default_factory=lambda: _env("PG_USER", "chronodns"))
    password: str = field(default_factory=lambda: _env("PG_PASSWORD", "chronodns"))
    database: str = field(default_factory=lambda: _env("PG_DATABASE", "chronodns"))
    pool_min: int = field(default_factory=lambda: _env("PG_POOL_MIN", 2, int))
    pool_max: int = field(default_factory=lambda: _env("PG_POOL_MAX", 10, int))
    batch_size: int = field(default_factory=lambda: _env("DB_BATCH_SIZE", 200, int))
    flush_interval: float = field(default_factory=lambda: _env("DB_FLUSH_INTERVAL", 1.0, float))

    @property
    def dsn(self) -> str:
        return (
            f"postgresql://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.database}"
        )

    @property
    def is_postgres(self) -> bool:
        return self.backend in ("postgres", "postgresql", "pg")


@dataclass
class DetectionConfig:
    """Thresholds & policy for the verdict engine."""

    # Ensemble fusion weights (supervised vs unsupervised).
    w_supervised: float = field(default_factory=lambda: _env("W_SUPERVISED", 0.65, float))
    w_anomaly: float = field(default_factory=lambda: _env("W_ANOMALY", 0.20, float))
    w_heuristic: float = field(default_factory=lambda: _env("W_HEURISTIC", 0.15, float))

    # Verdict bands on the fused 0..1 threat score.
    threshold_suspicious: float = field(default_factory=lambda: _env("T_SUSPICIOUS", 0.45, float))
    threshold_malicious: float = field(default_factory=lambda: _env("T_MALICIOUS", 0.70, float))

    # Debouncing: how many consecutive malicious verdicts before we actually
    # block, so a single noisy query never takes down a legitimate domain.
    debounce_hits: int = field(default_factory=lambda: _env("DEBOUNCE_HITS", 2, int))
    debounce_window_s: float = field(default_factory=lambda: _env("DEBOUNCE_WINDOW", 60.0, float))

    # Stateful temporal analysis.
    window_size: int = field(default_factory=lambda: _env("WINDOW_SIZE", 64, int))
    beacon_min_samples: int = field(default_factory=lambda: _env("BEACON_MIN_SAMPLES", 6, int))
    beacon_cv_threshold: float = field(default_factory=lambda: _env("BEACON_CV", 0.12, float))

    # Rate limiting / volumetric exfil detection.
    qps_alarm: float = field(default_factory=lambda: _env("QPS_ALARM", 40.0, float))
    nxdomain_burst: int = field(default_factory=lambda: _env("NXDOMAIN_BURST", 25, int))

    fail_open: bool = field(default_factory=lambda: _env("FAIL_OPEN", True, bool))
    enforce: bool = field(default_factory=lambda: _env("ENFORCE", True, bool))


@dataclass
class MLConfig:
    model_dir: str = field(default_factory=lambda: _env("MODEL_DIR", str(MODEL_DIR)))
    # Forest sizes are an inference-latency decision, not just an accuracy one:
    # every tree is a Python-level call on the DNS hot path. 200/96 measured
    # within 0.001 F1 of 400/256 on this dataset while being ~3x faster.
    rf_estimators: int = field(default_factory=lambda: _env("RF_ESTIMATORS", 200, int))
    rf_max_depth: int = field(default_factory=lambda: _env("RF_MAX_DEPTH", 18, int))
    iforest_estimators: int = field(default_factory=lambda: _env("IF_ESTIMATORS", 96, int))
    iforest_contamination: float = field(default_factory=lambda: _env("IF_CONTAM", 0.06, float))
    test_size: float = field(default_factory=lambda: _env("TEST_SIZE", 0.25, float))
    random_state: int = field(default_factory=lambda: _env("SEED", 1337, int))
    n_jobs: int = field(default_factory=lambda: _env("N_JOBS", -1, int))


@dataclass
class APIConfig:
    host: str = field(default_factory=lambda: _env("API_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env("API_PORT", 8088, int))
    refresh_ms: int = field(default_factory=lambda: _env("API_REFRESH_MS", 2000, int))


@dataclass
class Config:
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    api: APIConfig = field(default_factory=APIConfig)
    log_level: str = field(default_factory=lambda: _env("LOG_LEVEL", "INFO").upper())
    log_file: str = field(default_factory=lambda: _env("LOG_FILE", str(LOG_DIR / "chronodns.log")))

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


_config: Config | None = None


def get_config(reload: bool = False) -> Config:
    """Process-wide singleton config."""
    global _config
    if _config is None or reload:
        _config = Config()
    return _config
