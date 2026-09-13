-- ===========================================================================
--  Chrono-DNS :: PostgreSQL schema
--  ---------------------------------------------------------------------
--  Forensic DNS event store + local threat-intelligence warehouse.
--  Designed for high write throughput (COPY/executemany batches) and
--  analyst-speed reads (BRIN on time, partial indexes on the hot predicate).
-- ===========================================================================

CREATE SCHEMA IF NOT EXISTS chrono;
SET search_path TO chrono, public;

-- ---------------------------------------------------------------------------
-- 1. dns_events — the immutable forensic stream (one row per DNS question)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dns_events (
    id                BIGSERIAL     PRIMARY KEY,
    query_id          TEXT          NOT NULL,
    ts                TIMESTAMPTZ   NOT NULL DEFAULT now(),
    source_ip         INET          NOT NULL,
    qname             TEXT          NOT NULL,
    registrable       TEXT          NOT NULL,
    subdomain         TEXT          NOT NULL DEFAULT '',
    tld               TEXT          NOT NULL DEFAULT '',
    qtype             TEXT          NOT NULL DEFAULT 'A',
    transport         TEXT          NOT NULL DEFAULT 'udp',
    qname_length      SMALLINT      NOT NULL DEFAULT 0,
    label_count       SMALLINT      NOT NULL DEFAULT 0,
    entropy           REAL          NOT NULL DEFAULT 0,
    sub_entropy       REAL          NOT NULL DEFAULT 0,
    score             REAL          NOT NULL DEFAULT 0,
    supervised_score  REAL          NOT NULL DEFAULT 0,
    anomaly_score     REAL          NOT NULL DEFAULT 0,
    heuristic_score   REAL          NOT NULL DEFAULT 0,
    verdict           TEXT          NOT NULL DEFAULT 'ALLOW',
    threat_class      TEXT          NOT NULL DEFAULT 'benign',
    intel_hit         TEXT,
    reasons           TEXT,
    latency_ms        REAL          NOT NULL DEFAULT 0,
    is_blocked        SMALLINT      NOT NULL DEFAULT 0,
    truth_label       TEXT,
    family            TEXT,
    CONSTRAINT verdict_domain CHECK (
        verdict IN ('ALLOW','MONITOR','SUSPICIOUS','BLOCK','ERROR')
    )
);

COMMENT ON TABLE  dns_events IS 'Append-only forensic record of every DNS question seen by the gateway.';
COMMENT ON COLUMN dns_events.score IS 'Fused 0..1 threat score from the ML ensemble.';

-- ---------------------------------------------------------------------------
-- 2. threat_intel — local reputation warehouse (domains, zones, IPs)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_intel (
    id           BIGSERIAL    PRIMARY KEY,
    indicator    TEXT         NOT NULL,
    ioc_type     TEXT         NOT NULL DEFAULT 'domain',   -- domain|zone|ip|tld|regex
    category     TEXT         NOT NULL DEFAULT 'malware',  -- malware|c2|phishing|tunnel|dga|adware
    severity     SMALLINT     NOT NULL DEFAULT 5,          -- 1..10
    confidence   REAL         NOT NULL DEFAULT 0.8,
    source       TEXT         NOT NULL DEFAULT 'local',
    first_seen   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    notes        TEXT,
    UNIQUE (indicator, ioc_type)
);

-- ---------------------------------------------------------------------------
-- 3. allowlist — the false-positive kill switch every real SOC needs
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS allowlist (
    id          BIGSERIAL   PRIMARY KEY,
    pattern     TEXT        NOT NULL UNIQUE,
    match_type  TEXT        NOT NULL DEFAULT 'suffix',  -- exact|suffix|regex
    reason      TEXT,
    added_by    TEXT        DEFAULT 'system',
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- 4. domain_baseline — learned "normal" per zone, used for drift detection
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS domain_baseline (
    registrable       TEXT        PRIMARY KEY,
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
    query_count       BIGINT      NOT NULL DEFAULT 0,
    unique_subdomains BIGINT      NOT NULL DEFAULT 0,
    mean_entropy      REAL        NOT NULL DEFAULT 0,
    std_entropy       REAL        NOT NULL DEFAULT 0,
    mean_qname_len    REAL        NOT NULL DEFAULT 0,
    mean_iat_s        REAL        NOT NULL DEFAULT 0,
    distinct_hosts    INTEGER     NOT NULL DEFAULT 0,
    is_trusted        BOOLEAN     NOT NULL DEFAULT FALSE
);

-- ---------------------------------------------------------------------------
-- 5. alerts — deduplicated, analyst-facing incidents (not raw events)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id            BIGSERIAL    PRIMARY KEY,
    fingerprint   TEXT         NOT NULL UNIQUE,  -- sha1(source_ip|registrable|class)
    opened_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    source_ip     INET         NOT NULL,
    registrable   TEXT         NOT NULL,
    threat_class  TEXT         NOT NULL,
    severity      SMALLINT     NOT NULL DEFAULT 5,
    hit_count     INTEGER      NOT NULL DEFAULT 1,
    max_score     REAL         NOT NULL DEFAULT 0,
    bytes_exfil   BIGINT       NOT NULL DEFAULT 0,
    status        TEXT         NOT NULL DEFAULT 'open',  -- open|triaged|closed|fp
    summary       TEXT
);

-- ---------------------------------------------------------------------------
-- 6. model_registry — which model scored which event (reproducible forensics)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS model_registry (
    id             BIGSERIAL   PRIMARY KEY,
    model_version  TEXT        NOT NULL UNIQUE,
    trained_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    algorithm      TEXT        NOT NULL,
    feature_count  INTEGER     NOT NULL,
    train_rows     INTEGER     NOT NULL,
    accuracy       REAL,
    precision_val  REAL,
    recall_val     REAL,
    f1             REAL,
    roc_auc        REAL,
    notes          TEXT
);

-- ---------------------------------------------------------------------------
-- 7. gateway_stats — one row per flush interval, powers the dashboard sparkline
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS gateway_stats (
    id            BIGSERIAL    PRIMARY KEY,
    ts            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    queries       INTEGER      NOT NULL DEFAULT 0,
    blocked       INTEGER      NOT NULL DEFAULT 0,
    suspicious    INTEGER      NOT NULL DEFAULT 0,
    cache_hits    INTEGER      NOT NULL DEFAULT 0,
    p50_latency   REAL         NOT NULL DEFAULT 0,
    p95_latency   REAL         NOT NULL DEFAULT 0,
    p99_latency   REAL         NOT NULL DEFAULT 0
);
