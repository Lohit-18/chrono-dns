-- ===========================================================================
--  Chrono-DNS :: SQLite schema (zero-install development / demo backend)
--  Mirrors the PostgreSQL schema 1:1 so queries port with minimal edits.
--  Timestamps are stored as REAL unix epoch for cheap arithmetic.
-- ===========================================================================

PRAGMA journal_mode = WAL;        -- concurrent readers while the gateway writes
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA temp_store   = MEMORY;
PRAGMA cache_size   = -32000;     -- 32 MB page cache

CREATE TABLE IF NOT EXISTS dns_events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    query_id          TEXT    NOT NULL,
    ts                REAL    NOT NULL,
    source_ip         TEXT    NOT NULL,
    qname             TEXT    NOT NULL,
    registrable       TEXT    NOT NULL,
    subdomain         TEXT    NOT NULL DEFAULT '',
    tld               TEXT    NOT NULL DEFAULT '',
    qtype             TEXT    NOT NULL DEFAULT 'A',
    transport         TEXT    NOT NULL DEFAULT 'udp',
    qname_length      INTEGER NOT NULL DEFAULT 0,
    label_count       INTEGER NOT NULL DEFAULT 0,
    entropy           REAL    NOT NULL DEFAULT 0,
    sub_entropy       REAL    NOT NULL DEFAULT 0,
    score             REAL    NOT NULL DEFAULT 0,
    supervised_score  REAL    NOT NULL DEFAULT 0,
    anomaly_score     REAL    NOT NULL DEFAULT 0,
    heuristic_score   REAL    NOT NULL DEFAULT 0,
    verdict           TEXT    NOT NULL DEFAULT 'ALLOW'
                      CHECK (verdict IN ('ALLOW','MONITOR','SUSPICIOUS','BLOCK','ERROR')),
    threat_class      TEXT    NOT NULL DEFAULT 'benign',
    intel_hit         TEXT,
    reasons           TEXT,
    latency_ms        REAL    NOT NULL DEFAULT 0,
    is_blocked        INTEGER NOT NULL DEFAULT 0,
    truth_label       TEXT,
    family            TEXT
);

CREATE TABLE IF NOT EXISTS threat_intel (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator   TEXT    NOT NULL,
    ioc_type    TEXT    NOT NULL DEFAULT 'domain',
    category    TEXT    NOT NULL DEFAULT 'malware',
    severity    INTEGER NOT NULL DEFAULT 5,
    confidence  REAL    NOT NULL DEFAULT 0.8,
    source      TEXT    NOT NULL DEFAULT 'local',
    first_seen  REAL    NOT NULL DEFAULT (strftime('%s','now')),
    last_seen   REAL    NOT NULL DEFAULT (strftime('%s','now')),
    expires_at  REAL,
    notes       TEXT,
    UNIQUE (indicator, ioc_type)
);

CREATE TABLE IF NOT EXISTS allowlist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern    TEXT NOT NULL UNIQUE,
    match_type TEXT NOT NULL DEFAULT 'suffix',
    reason     TEXT,
    added_by   TEXT DEFAULT 'system',
    added_at   REAL NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS domain_baseline (
    registrable       TEXT PRIMARY KEY,
    first_seen        REAL NOT NULL DEFAULT (strftime('%s','now')),
    last_seen         REAL NOT NULL DEFAULT (strftime('%s','now')),
    query_count       INTEGER NOT NULL DEFAULT 0,
    unique_subdomains INTEGER NOT NULL DEFAULT 0,
    mean_entropy      REAL NOT NULL DEFAULT 0,
    std_entropy       REAL NOT NULL DEFAULT 0,
    mean_qname_len    REAL NOT NULL DEFAULT 0,
    mean_iat_s        REAL NOT NULL DEFAULT 0,
    distinct_hosts    INTEGER NOT NULL DEFAULT 0,
    is_trusted        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint  TEXT NOT NULL UNIQUE,
    opened_at    REAL NOT NULL DEFAULT (strftime('%s','now')),
    updated_at   REAL NOT NULL DEFAULT (strftime('%s','now')),
    source_ip    TEXT NOT NULL,
    registrable  TEXT NOT NULL,
    threat_class TEXT NOT NULL,
    severity     INTEGER NOT NULL DEFAULT 5,
    hit_count    INTEGER NOT NULL DEFAULT 1,
    max_score    REAL NOT NULL DEFAULT 0,
    bytes_exfil  INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'open',
    summary      TEXT
);

CREATE TABLE IF NOT EXISTS model_registry (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    model_version TEXT NOT NULL UNIQUE,
    trained_at    REAL NOT NULL DEFAULT (strftime('%s','now')),
    algorithm     TEXT NOT NULL,
    feature_count INTEGER NOT NULL,
    train_rows    INTEGER NOT NULL,
    accuracy      REAL,
    precision_val REAL,
    recall_val    REAL,
    f1            REAL,
    roc_auc       REAL,
    notes         TEXT
);

CREATE TABLE IF NOT EXISTS gateway_stats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL DEFAULT (strftime('%s','now')),
    queries     INTEGER NOT NULL DEFAULT 0,
    blocked     INTEGER NOT NULL DEFAULT 0,
    suspicious  INTEGER NOT NULL DEFAULT 0,
    cache_hits  INTEGER NOT NULL DEFAULT 0,
    p50_latency REAL NOT NULL DEFAULT 0,
    p95_latency REAL NOT NULL DEFAULT 0,
    p99_latency REAL NOT NULL DEFAULT 0
);
