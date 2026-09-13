-- ===========================================================================
--  HUNT #7 :: "Reconstruct the incident timeline for one host."
--  ---------------------------------------------------------------------
--  Incident response question: given a compromised endpoint, show me its
--  whole DNS story in order, flagging the moment behaviour changed.
--  Uses LAG/LEAD, a running block counter, and FIRST_VALUE to anchor the
--  session -- the kind of narrative output an analyst can paste into a report.
--
--  Usage:  psql -v host="'10.10.42.77'" -f 07_kill_chain_timeline.sql
-- ===========================================================================
SET search_path TO chrono, public;

\set host '10.10.42.77'

WITH story AS (
    SELECT
        ts,
        qname,
        qtype,
        threat_class,
        verdict,
        score,
        FIRST_VALUE(ts) OVER w                                     AS session_start,
        EXTRACT(EPOCH FROM (ts - LAG(ts) OVER w))                  AS gap_s,
        SUM(is_blocked)  OVER (PARTITION BY source_ip ORDER BY ts) AS blocks_so_far,
        AVG(score) OVER (PARTITION BY source_ip ORDER BY ts
                         ROWS BETWEEN 9 PRECEDING AND CURRENT ROW) AS score_ma10,
        LEAD(qname) OVER w                                         AS next_query
    FROM dns_events
    WHERE source_ip = :'host'::inet
    WINDOW w AS (PARTITION BY source_ip ORDER BY ts)
)
SELECT
    ROUND(EXTRACT(EPOCH FROM (ts - session_start))::numeric, 1)   AS t_plus_s,
    to_char(ts, 'HH24:MI:SS')                                     AS clock,
    LEFT(qname, 58)                                               AS query,
    qtype,
    threat_class,
    verdict,
    ROUND(score::numeric, 3)                                      AS score,
    ROUND(score_ma10::numeric, 3)                                 AS score_ma10,
    ROUND(COALESCE(gap_s, 0)::numeric, 2)                         AS gap_s,
    blocks_so_far,
    CASE
        WHEN score_ma10 > 0.7 AND LAG(score_ma10) OVER (ORDER BY ts) <= 0.7
            THEN '<<< BEHAVIOUR SHIFT'
        ELSE ''
    END                                                           AS marker
FROM story
ORDER BY ts
LIMIT 200;
