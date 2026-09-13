-- ===========================================================================
--  HUNT #5 :: "Join the live stream against local threat intelligence."
--  ---------------------------------------------------------------------
--  Demonstrates a three-way relational join: events x threat_intel x alerts,
--  matching on FQDN, registrable zone AND TLD in a single pass, with the
--  allowlist applied as an anti-join so trusted CDNs never raise noise.
-- ===========================================================================
SET search_path TO chrono, public;

SELECT
    e.ts,
    e.source_ip                                AS host,
    e.qname,
    e.qtype,
    ROUND(e.score::numeric, 3)                 AS ml_score,
    ti.indicator                               AS matched_ioc,
    ti.ioc_type,
    ti.category,
    ti.severity                                AS intel_severity,
    ti.source                                  AS intel_source,
    a.hit_count                                AS alert_hits,
    a.status                                   AS alert_status,
    -- Fused priority: ML confidence and curated intel both vote.
    ROUND((0.6 * e.score + 0.4 * (ti.severity / 10.0))::numeric, 3) AS priority
FROM dns_events e
JOIN threat_intel ti
      ON (ti.ioc_type = 'domain' AND ti.indicator = e.qname)
      OR (ti.ioc_type = 'zone'   AND ti.indicator = e.registrable)
      OR (ti.ioc_type = 'tld'    AND ti.indicator = e.tld)
LEFT JOIN alerts a
      ON a.source_ip = e.source_ip
     AND a.registrable = e.registrable
WHERE e.ts > now() - INTERVAL '24 hours'
  AND (ti.expires_at IS NULL OR ti.expires_at > now())
  AND NOT EXISTS (                       -- allowlist anti-join
        SELECT 1 FROM allowlist al
        WHERE (al.match_type = 'exact'  AND e.qname = al.pattern)
           OR (al.match_type = 'suffix' AND (e.qname = al.pattern
                                         OR e.qname LIKE '%.' || al.pattern))
  )
ORDER BY priority DESC, e.ts DESC
LIMIT 50;
