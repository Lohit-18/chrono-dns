-- ===========================================================================
--  Chrono-DNS :: PostgreSQL views & materialized views
--  This is where the window functions earn their keep.
-- ===========================================================================
SET search_path TO chrono, public;

-- ---------------------------------------------------------------------------
-- v_recent_threats — the live triage queue
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_recent_threats AS
SELECT
    e.ts,
    e.source_ip,
    e.qname,
    e.registrable,
    e.qtype,
    ROUND(e.score::numeric, 3)   AS score,
    ROUND(e.entropy::numeric, 2) AS entropy,
    e.threat_class,
    e.verdict,
    e.intel_hit,
    e.reasons
FROM dns_events e
WHERE e.score >= 0.45
ORDER BY e.ts DESC;

-- ---------------------------------------------------------------------------
-- v_host_velocity — moving average request rate per host.
-- Window function over an ordered partition: exactly the analytic pattern
-- that separates "I can write SQL" from "I can write *SQL*".
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_host_velocity AS
SELECT
    source_ip,
    ts,
    qname,
    score,
    COUNT(*)  OVER w_60                                        AS queries_last_60,
    AVG(score) OVER w_20                                       AS avg_score_20,
    EXTRACT(EPOCH FROM (ts - LAG(ts) OVER w_host))             AS iat_seconds,
    STDDEV_POP(EXTRACT(EPOCH FROM ts)) OVER w_20               AS ts_stddev_20,
    ROW_NUMBER() OVER w_host                                   AS seq_in_host
FROM dns_events
WINDOW
    w_host AS (PARTITION BY source_ip ORDER BY ts),
    w_20   AS (PARTITION BY source_ip ORDER BY ts ROWS BETWEEN 19 PRECEDING AND CURRENT ROW),
    w_60   AS (PARTITION BY source_ip ORDER BY ts
               RANGE BETWEEN INTERVAL '60 seconds' PRECEDING AND CURRENT ROW);

-- ---------------------------------------------------------------------------
-- v_tunnel_candidates — zones behaving like a tunnel endpoint.
-- High unique-subdomain ratio + high mean entropy + sustained volume.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_tunnel_candidates AS
SELECT
    registrable,
    COUNT(*)                                       AS queries,
    COUNT(DISTINCT subdomain)                      AS unique_subs,
    ROUND((COUNT(DISTINCT subdomain)::numeric
           / NULLIF(COUNT(*), 0)), 3)              AS novelty_ratio,
    ROUND(AVG(sub_entropy)::numeric, 3)            AS avg_sub_entropy,
    ROUND(AVG(qname_length)::numeric, 1)           AS avg_qname_len,
    SUM(LENGTH(subdomain))                         AS bytes_uploaded,
    COUNT(DISTINCT source_ip)                      AS distinct_hosts,
    MIN(ts)                                        AS first_seen,
    MAX(ts)                                        AS last_seen,
    ROUND(EXTRACT(EPOCH FROM (MAX(ts) - MIN(ts)))::numeric, 1) AS span_seconds
FROM dns_events
GROUP BY registrable
HAVING COUNT(*) >= 10
   AND (COUNT(DISTINCT subdomain)::numeric / NULLIF(COUNT(*), 0)) > 0.80
   AND AVG(sub_entropy) > 3.0
ORDER BY bytes_uploaded DESC;

-- ---------------------------------------------------------------------------
-- v_beacon_candidates — near-zero jitter = malware, not a human.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_beacon_candidates AS
WITH gaps AS (
    SELECT
        source_ip,
        registrable,
        EXTRACT(EPOCH FROM (ts - LAG(ts) OVER (
            PARTITION BY source_ip, registrable ORDER BY ts))) AS gap
    FROM dns_events
)
SELECT
    source_ip,
    registrable,
    COUNT(*)                              AS samples,
    ROUND(AVG(gap)::numeric, 2)           AS mean_interval_s,
    ROUND(STDDEV_POP(gap)::numeric, 3)    AS jitter_s,
    ROUND((STDDEV_POP(gap) / NULLIF(AVG(gap), 0))::numeric, 4) AS cv
FROM gaps
WHERE gap IS NOT NULL AND gap > 0
GROUP BY source_ip, registrable
HAVING COUNT(*) >= 6
   AND (STDDEV_POP(gap) / NULLIF(AVG(gap), 0)) < 0.15
ORDER BY cv ASC;

-- ---------------------------------------------------------------------------
-- v_top_talkers — who is generating the noise
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_top_talkers AS
SELECT
    source_ip,
    COUNT(*)                                             AS queries,
    COUNT(DISTINCT registrable)                          AS zones,
    SUM(is_blocked)                                      AS blocked,
    ROUND(AVG(score)::numeric, 3)                        AS avg_score,
    ROUND(MAX(score)::numeric, 3)                        AS max_score,
    ROUND((100.0 * SUM(is_blocked) / COUNT(*))::numeric, 2) AS block_pct,
    MAX(ts)                                              AS last_seen
FROM dns_events
GROUP BY source_ip
ORDER BY queries DESC;

-- ---------------------------------------------------------------------------
-- mv_hourly_rollup — materialized for dashboard speed. REFRESH from cron.
-- ---------------------------------------------------------------------------
DROP MATERIALIZED VIEW IF EXISTS mv_hourly_rollup;
CREATE MATERIALIZED VIEW mv_hourly_rollup AS
SELECT
    date_trunc('hour', ts)                 AS bucket,
    threat_class,
    COUNT(*)                               AS events,
    SUM(is_blocked)                        AS blocked,
    ROUND(AVG(score)::numeric, 4)          AS avg_score,
    ROUND(AVG(entropy)::numeric, 3)        AS avg_entropy,
    COUNT(DISTINCT source_ip)              AS hosts,
    COUNT(DISTINCT registrable)            AS zones
FROM dns_events
GROUP BY 1, 2
WITH NO DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_hourly
    ON mv_hourly_rollup (bucket, threat_class);
