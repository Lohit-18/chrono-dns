-- ===========================================================================
--  Chrono-DNS :: SQLite indexes (partial indexes supported since 3.8)
-- ===========================================================================

CREATE INDEX IF NOT EXISTS idx_events_ts          ON dns_events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ts      ON dns_events (source_ip, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_zone_ts     ON dns_events (registrable, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_class       ON dns_events (threat_class, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_qname       ON dns_events (qname);

-- Partial indexes: tiny, and they cover the two queries the SOC runs all day.
CREATE INDEX IF NOT EXISTS idx_events_blocked
    ON dns_events (ts DESC) WHERE is_blocked = 1;
CREATE INDEX IF NOT EXISTS idx_events_high_score
    ON dns_events (score DESC, ts DESC) WHERE score >= 0.45;

CREATE INDEX IF NOT EXISTS idx_intel_indicator    ON threat_intel (indicator, ioc_type);
CREATE INDEX IF NOT EXISTS idx_alerts_status      ON alerts (status, severity DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_src         ON alerts (source_ip, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_baseline_lastseen  ON domain_baseline (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_stats_ts           ON gateway_stats (ts DESC);
