-- ===========================================================================
--  Chrono-DNS :: SQLite views
--  SQLite 3.25+ supports window functions, so the analytics translate almost
--  verbatim from PostgreSQL — only the timestamp arithmetic differs.
-- ===========================================================================

DROP VIEW IF EXISTS v_recent_threats;
CREATE VIEW v_recent_threats AS
SELECT ts, source_ip, qname, registrable, qtype,
       ROUND(score, 3)   AS score,
       ROUND(entropy, 2) AS entropy,
       threat_class, verdict, intel_hit, reasons
FROM dns_events
WHERE score >= 0.45
ORDER BY ts DESC;

DROP VIEW IF EXISTS v_host_velocity;
CREATE VIEW v_host_velocity AS
SELECT
    source_ip, ts, qname, score,
    COUNT(*)   OVER w20                       AS queries_window_20,
    AVG(score) OVER w20                       AS avg_score_20,
    ts - LAG(ts) OVER whost                   AS iat_seconds,
    ROW_NUMBER() OVER whost                   AS seq_in_host
FROM dns_events
WINDOW
    whost AS (PARTITION BY source_ip ORDER BY ts),
    w20   AS (PARTITION BY source_ip ORDER BY ts ROWS BETWEEN 19 PRECEDING AND CURRENT ROW);

DROP VIEW IF EXISTS v_tunnel_candidates;
CREATE VIEW v_tunnel_candidates AS
SELECT
    registrable,
    COUNT(*)                                            AS queries,
    COUNT(DISTINCT subdomain)                           AS unique_subs,
    ROUND(CAST(COUNT(DISTINCT subdomain) AS REAL) / COUNT(*), 3) AS novelty_ratio,
    ROUND(AVG(sub_entropy), 3)                          AS avg_sub_entropy,
    ROUND(AVG(qname_length), 1)                         AS avg_qname_len,
    SUM(LENGTH(subdomain))                              AS bytes_uploaded,
    COUNT(DISTINCT source_ip)                           AS distinct_hosts,
    MIN(ts)                                             AS first_seen,
    MAX(ts)                                             AS last_seen,
    ROUND(MAX(ts) - MIN(ts), 1)                         AS span_seconds
FROM dns_events
GROUP BY registrable
HAVING COUNT(*) >= 10
   AND CAST(COUNT(DISTINCT subdomain) AS REAL) / COUNT(*) > 0.80
   AND AVG(sub_entropy) > 3.0
ORDER BY bytes_uploaded DESC;

DROP VIEW IF EXISTS v_beacon_candidates;
CREATE VIEW v_beacon_candidates AS
WITH gaps AS (
    SELECT source_ip, registrable,
           ts - LAG(ts) OVER (PARTITION BY source_ip, registrable ORDER BY ts) AS gap
    FROM dns_events
),
agg AS (
    SELECT source_ip, registrable,
           COUNT(*)  AS samples,
           AVG(gap)  AS mean_gap,
           -- SQLite has no STDDEV(); compute it from E[x^2] - E[x]^2.
           AVG(gap * gap) - AVG(gap) * AVG(gap) AS var_gap
    FROM gaps
    WHERE gap IS NOT NULL AND gap > 0
    GROUP BY source_ip, registrable
    HAVING COUNT(*) >= 6
)
SELECT source_ip, registrable, samples,
       ROUND(mean_gap, 2)                                      AS mean_interval_s,
       ROUND(CASE WHEN var_gap > 0 THEN var_gap ELSE 0 END, 5) AS variance_s2,
       ROUND(
         CASE WHEN mean_gap > 0 AND var_gap > 0
              THEN (var_gap / (mean_gap * mean_gap))
              ELSE 0 END, 5)                                   AS cv_squared
FROM agg
WHERE mean_gap > 0
  AND (CASE WHEN var_gap > 0 THEN var_gap / (mean_gap * mean_gap) ELSE 0 END) < 0.0225
ORDER BY cv_squared ASC;

DROP VIEW IF EXISTS v_top_talkers;
CREATE VIEW v_top_talkers AS
SELECT source_ip,
       COUNT(*)                     AS queries,
       COUNT(DISTINCT registrable)  AS zones,
       SUM(is_blocked)              AS blocked,
       ROUND(AVG(score), 3)         AS avg_score,
       ROUND(MAX(score), 3)         AS max_score,
       ROUND(100.0 * SUM(is_blocked) / COUNT(*), 2) AS block_pct,
       MAX(ts)                      AS last_seen
FROM dns_events
GROUP BY source_ip
ORDER BY queries DESC;

DROP VIEW IF EXISTS v_hourly_rollup;
CREATE VIEW v_hourly_rollup AS
SELECT
    CAST(ts / 3600 AS INTEGER) * 3600 AS bucket,
    threat_class,
    COUNT(*)                    AS events,
    SUM(is_blocked)             AS blocked,
    ROUND(AVG(score), 4)        AS avg_score,
    ROUND(AVG(entropy), 3)      AS avg_entropy,
    COUNT(DISTINCT source_ip)   AS hosts,
    COUNT(DISTINCT registrable) AS zones
FROM dns_events
GROUP BY bucket, threat_class;
