-- ===========================================================================
--  HUNT #2 :: "Which host is calling home on a timer?"
--  ---------------------------------------------------------------------
--  Humans are irregular. Malware is a metronome. We compute the coefficient
--  of variation (sigma/mu) of inter-arrival times per (host, zone) pair using
--  LAG() over an ordered partition -- a textbook window-function problem.
--
--     CV -> 0.00   perfect beacon   (scheduled task / implant sleep timer)
--     CV ~ 0.10    beacon + jitter  (Cobalt-Strike style 10% jitter)
--     CV > 1.00    human browsing
-- ===========================================================================
SET search_path TO chrono, public;

WITH gaps AS (
    SELECT
        source_ip,
        registrable,
        ts,
        EXTRACT(EPOCH FROM (ts - LAG(ts) OVER (
            PARTITION BY source_ip, registrable ORDER BY ts
        ))) AS gap_s
    FROM dns_events
    WHERE ts > now() - INTERVAL '6 hours'
),
scored AS (
    SELECT
        source_ip,
        registrable,
        COUNT(*)                                        AS samples,
        AVG(gap_s)                                      AS mean_gap,
        STDDEV_POP(gap_s)                               AS jitter,
        STDDEV_POP(gap_s) / NULLIF(AVG(gap_s), 0)       AS cv,
        MIN(gap_s)                                      AS min_gap,
        MAX(gap_s)                                      AS max_gap
    FROM gaps
    WHERE gap_s IS NOT NULL AND gap_s BETWEEN 0.5 AND 3600
    GROUP BY source_ip, registrable
    HAVING COUNT(*) >= 6
)
SELECT
    source_ip                                        AS host,
    registrable                                      AS zone,
    samples,
    ROUND(mean_gap::numeric, 2)                      AS interval_s,
    ROUND(jitter::numeric, 3)                        AS jitter_s,
    ROUND(cv::numeric, 4)                            AS cv,
    ROUND((100 * (1 - LEAST(cv / 0.5, 1)))::numeric, 1) AS beacon_confidence_pct,
    CASE
        WHEN cv < 0.02 THEN 'LOCKSTEP  - scheduled implant'
        WHEN cv < 0.10 THEN 'BEACON    - low jitter C2'
        WHEN cv < 0.25 THEN 'PERIODIC  - jittered C2 or poller'
        ELSE                'IRREGULAR - likely human'
    END                                              AS assessment
FROM scored
WHERE cv < 0.25
ORDER BY cv ASC
LIMIT 30;
