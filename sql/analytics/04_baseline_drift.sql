-- ===========================================================================
--  HUNT #4 :: "Did a zone we trust suddenly start behaving differently?"
--  ---------------------------------------------------------------------
--  Attackers love hijacking or sub-leasing a zone that already has a clean
--  reputation. The tell is a sudden jump in entropy or query length relative
--  to that zone's own learned baseline -- a z-score, computed in SQL.
-- ===========================================================================
SET search_path TO chrono, public;

WITH recent AS (
    SELECT
        registrable,
        COUNT(*)              AS n,
        AVG(sub_entropy)      AS cur_entropy,
        AVG(qname_length)     AS cur_len,
        MAX(ts)               AS last_seen
    FROM dns_events
    WHERE ts > now() - INTERVAL '1 hour'
    GROUP BY registrable
    HAVING COUNT(*) >= 5
)
SELECT
    r.registrable                                        AS zone,
    r.n                                                  AS queries_last_hour,
    ROUND(b.mean_entropy::numeric, 3)                    AS baseline_entropy,
    ROUND(r.cur_entropy::numeric, 3)                     AS current_entropy,
    ROUND((r.cur_entropy - b.mean_entropy)::numeric, 3)  AS entropy_delta,
    -- z-score against the learned standard deviation (floored so a zone with
    -- zero historical variance cannot divide by zero)
    ROUND(((r.cur_entropy - b.mean_entropy)
           / GREATEST(b.std_entropy, 0.25))::numeric, 2) AS z_score,
    ROUND(b.mean_qname_len::numeric, 1)                  AS baseline_len,
    ROUND(r.cur_len::numeric, 1)                         AS current_len,
    b.is_trusted,
    CASE
        WHEN (r.cur_entropy - b.mean_entropy) / GREATEST(b.std_entropy, 0.25) > 4
            THEN 'ALARM  - zone behaviour changed radically'
        WHEN (r.cur_entropy - b.mean_entropy) / GREATEST(b.std_entropy, 0.25) > 2
            THEN 'WATCH  - drifting'
        ELSE 'NORMAL'
    END                                                  AS drift_state
FROM recent r
JOIN domain_baseline b USING (registrable)
WHERE b.query_count >= 50
ORDER BY z_score DESC
LIMIT 25;
