-- ===========================================================================
--  HUNT #8 :: "Campaign clustering -- which hosts share the same infrastructure?"
--  ---------------------------------------------------------------------
--  If five endpoints all talk to the same rare zone, that is a campaign, not
--  a coincidence. A self-join on dns_events builds the host-to-host adjacency,
--  and rarity weighting keeps google.com out of the results.
-- ===========================================================================
SET search_path TO chrono, public;

WITH zone_pop AS (            -- how common is each zone across the estate?
    SELECT registrable,
           COUNT(DISTINCT source_ip) AS hosts,
           COUNT(*)                  AS hits,
           MAX(score)                AS peak_score
    FROM dns_events
    WHERE ts > now() - INTERVAL '7 days'
    GROUP BY registrable
),
rare_zones AS (               -- rare + suspicious = campaign infrastructure
    SELECT registrable, hosts, hits, peak_score
    FROM zone_pop
    WHERE hosts BETWEEN 2 AND 20
      AND peak_score >= 0.45
),
pairs AS (
    SELECT
        a.source_ip AS host_a,
        b.source_ip AS host_b,
        COUNT(DISTINCT a.registrable) AS shared_zones,
        STRING_AGG(DISTINCT a.registrable, ', ' ORDER BY a.registrable) AS zones
    FROM dns_events a
    JOIN dns_events b
      ON a.registrable = b.registrable
     AND a.source_ip < b.source_ip          -- each unordered pair exactly once
    JOIN rare_zones rz ON rz.registrable = a.registrable
    WHERE a.ts > now() - INTERVAL '7 days'
    GROUP BY a.source_ip, b.source_ip
)
SELECT
    host_a,
    host_b,
    shared_zones,
    LEFT(zones, 120) AS shared_infrastructure,
    CASE
        WHEN shared_zones >= 3 THEN 'STRONG - same implant family likely'
        WHEN shared_zones = 2  THEN 'MODERATE'
        ELSE                        'WEAK'
    END AS cluster_confidence
FROM pairs
WHERE shared_zones >= 1
ORDER BY shared_zones DESC, host_a
LIMIT 50;
