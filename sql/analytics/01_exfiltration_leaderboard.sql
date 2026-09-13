-- ===========================================================================
--  HUNT #1 :: "Who is pushing the most data out over DNS?"
--  ---------------------------------------------------------------------
--  Every byte an attacker exfiltrates has to appear in a subdomain label.
--  So the total length of subdomains sent to a zone IS the upload volume.
--  We rank zones by that, then qualify them with entropy and novelty so a
--  chatty-but-legitimate CDN does not top the chart.
--
--  Dialect: PostgreSQL. For SQLite replace NUMERIC casts with CAST(x AS REAL)
--  and EXTRACT(EPOCH FROM (MAX(ts)-MIN(ts))) with (MAX(ts)-MIN(ts)).
-- ===========================================================================
SET search_path TO chrono, public;

WITH zone_stats AS (
    SELECT
        registrable,
        COUNT(*)                                  AS queries,
        COUNT(DISTINCT subdomain)                 AS unique_subs,
        COUNT(DISTINCT source_ip)                 AS hosts,
        SUM(LENGTH(subdomain))                    AS raw_bytes,
        AVG(sub_entropy)                          AS avg_entropy,
        MAX(score)                                AS peak_score,
        MIN(ts)                                   AS first_seen,
        MAX(ts)                                   AS last_seen,
        EXTRACT(EPOCH FROM (MAX(ts) - MIN(ts)))   AS span_s
    FROM dns_events
    WHERE ts > now() - INTERVAL '24 hours'
    GROUP BY registrable
)
SELECT
    registrable                                                  AS zone,
    queries,
    hosts,
    ROUND((raw_bytes / 1024.0)::numeric, 2)                      AS kib_uploaded,
    -- Base32 carries 5 bits per character, so the real payload is ~62.5%
    -- of the character count. This converts "chars seen" into "bytes stolen".
    ROUND((raw_bytes * 0.625 / 1024.0)::numeric, 2)              AS est_kib_payload,
    ROUND((raw_bytes / NULLIF(span_s, 0))::numeric, 1)           AS bytes_per_sec,
    ROUND(avg_entropy::numeric, 2)                               AS avg_entropy,
    ROUND((unique_subs::numeric / NULLIF(queries, 0)), 3)        AS novelty,
    ROUND(peak_score::numeric, 3)                                AS peak_score,
    ROUND(span_s::numeric, 0)                                    AS span_seconds
FROM zone_stats
WHERE queries >= 10
ORDER BY raw_bytes DESC
LIMIT 25;
