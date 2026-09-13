-- ===========================================================================
--  HUNT #3 :: "Which host is burning through algorithmically generated names?"
--  ---------------------------------------------------------------------
--  A DGA implant generates hundreds of candidate domains per day and most
--  of them are unregistered -> NXDOMAIN. The signature is therefore a
--  *burst of failures across many unrelated zones from a single host*.
--
--  Uses a moving 5-minute RANGE window to find the peak of the storm.
-- ===========================================================================
SET search_path TO chrono, public;

WITH windowed AS (
    SELECT
        source_ip,
        ts,
        qname,
        registrable,
        threat_class,
        COUNT(*) FILTER (WHERE threat_class = 'dga') OVER w5m AS dga_in_5m,
        COUNT(*) OVER w5m                                    AS queries_in_5m,
        COUNT(DISTINCT registrable) OVER w5m                 AS zones_in_5m
    FROM dns_events
    WHERE ts > now() - INTERVAL '12 hours'
    WINDOW w5m AS (
        PARTITION BY source_ip ORDER BY ts
        RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW
    )
)
SELECT
    source_ip                                    AS host,
    MAX(dga_in_5m)                               AS peak_dga_per_5min,
    MAX(zones_in_5m)                             AS peak_distinct_zones,
    COUNT(*)                                     AS total_queries,
    COUNT(DISTINCT registrable)                  AS total_zones,
    ROUND((100.0 * COUNT(*) FILTER (WHERE threat_class = 'dga')
           / COUNT(*))::numeric, 1)              AS dga_pct,
    CASE
        WHEN MAX(dga_in_5m) >= 40 THEN 'CRITICAL - active DGA implant'
        WHEN MAX(dga_in_5m) >= 15 THEN 'HIGH     - probable DGA'
        WHEN MAX(dga_in_5m) >= 5  THEN 'MEDIUM   - investigate'
        ELSE                           'LOW'
    END                                          AS triage
FROM windowed
GROUP BY source_ip
HAVING MAX(dga_in_5m) >= 5
ORDER BY peak_dga_per_5min DESC
LIMIT 25;
