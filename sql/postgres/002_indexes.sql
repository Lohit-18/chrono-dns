-- ===========================================================================
--  Chrono-DNS :: PostgreSQL indexes
--  Every index here exists because a specific hunting query needs it.
-- ===========================================================================
SET search_path TO chrono, public;

-- BRIN is ~1000x smaller than B-tree for an append-only time column and is
-- perfect for "last 15 minutes" scans on a monotonically increasing timestamp.
CREATE INDEX IF NOT EXISTS idx_events_ts_brin
    ON dns_events USING BRIN (ts) WITH (pages_per_range = 32);

-- Primary hunting axis: "show me everything host X did, newest first".
CREATE INDEX IF NOT EXISTS idx_events_src_ts
    ON dns_events (source_ip, ts DESC);

-- Zone pivot: "how much traffic went to this zone, and from how many hosts".
CREATE INDEX IF NOT EXISTS idx_events_zone_ts
    ON dns_events (registrable, ts DESC);

-- PARTIAL index — only ~1% of rows are blocked, so this index stays tiny
-- while making the SOC's most-run query effectively instant.
CREATE INDEX IF NOT EXISTS idx_events_blocked
    ON dns_events (ts DESC) WHERE is_blocked = 1;

-- Second partial index for the triage queue.
CREATE INDEX IF NOT EXISTS idx_events_high_score
    ON dns_events (score DESC, ts DESC) WHERE score >= 0.45;

CREATE INDEX IF NOT EXISTS idx_events_class
    ON dns_events (threat_class, ts DESC);

CREATE INDEX IF NOT EXISTS idx_events_qtype
    ON dns_events (qtype) WHERE qtype IN ('TXT','NULL','ANY','CNAME');

-- Trigram index for fuzzy analyst search: qname ILIKE '%cobalt%'
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_events_qname_trgm
    ON dns_events USING GIN (qname gin_trgm_ops);

-- Threat intel: exact lookups happen on every single query, so this is the
-- hottest index in the system.
CREATE INDEX IF NOT EXISTS idx_intel_indicator
    ON threat_intel (indicator, ioc_type);
CREATE INDEX IF NOT EXISTS idx_intel_active
    ON threat_intel (ioc_type, severity DESC)
    WHERE expires_at IS NULL OR expires_at > now();

CREATE INDEX IF NOT EXISTS idx_alerts_open
    ON alerts (severity DESC, updated_at DESC) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_alerts_src
    ON alerts (source_ip, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_baseline_lastseen
    ON domain_baseline (last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_stats_ts
    ON gateway_stats (ts DESC);
