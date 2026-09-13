-- ===========================================================================
--  HUNT #6 :: "Is the model still any good?"  (live confusion matrix)
--  ---------------------------------------------------------------------
--  When replaying a labelled dataset, dns_events.truth_label holds ground
--  truth. This query computes precision / recall / F1 per threat class
--  entirely in SQL -- useful for drift monitoring in production where you
--  back-fill truth_label from analyst triage decisions.
-- ===========================================================================
SET search_path TO chrono, public;

WITH cm AS (
    SELECT
        COALESCE(truth_label, 'unlabelled')                  AS actual,
        threat_class                                          AS predicted,
        COUNT(*)                                              AS n
    FROM dns_events
    WHERE truth_label IS NOT NULL
    GROUP BY 1, 2
),
per_class AS (
    SELECT
        c.actual                                              AS class,
        SUM(c.n) FILTER (WHERE c.predicted = c.actual)        AS tp,
        SUM(c.n) FILTER (WHERE c.predicted <> c.actual)       AS fn,
        (SELECT COALESCE(SUM(n), 0) FROM cm x
          WHERE x.predicted = c.actual AND x.actual <> c.actual) AS fp,
        SUM(c.n)                                              AS support
    FROM cm c
    GROUP BY c.actual
)
SELECT
    class,
    support,
    tp, fp, fn,
    ROUND((tp::numeric / NULLIF(tp + fp, 0)), 4)              AS precision,
    ROUND((tp::numeric / NULLIF(tp + fn, 0)), 4)              AS recall,
    ROUND((2.0 * tp / NULLIF(2 * tp + fp + fn, 0))::numeric, 4) AS f1
FROM per_class
ORDER BY support DESC;

-- Overall accuracy + the all-important false-positive rate on benign traffic.
SELECT
    COUNT(*)                                                            AS labelled_events,
    ROUND((100.0 * COUNT(*) FILTER (WHERE threat_class = truth_label)
           / COUNT(*))::numeric, 3)                                     AS accuracy_pct,
    ROUND((100.0 * COUNT(*) FILTER (WHERE truth_label = 'benign'
                                      AND is_blocked = 1)
           / NULLIF(COUNT(*) FILTER (WHERE truth_label = 'benign'), 0))::numeric, 4)
                                                                        AS false_positive_pct,
    ROUND((100.0 * COUNT(*) FILTER (WHERE truth_label <> 'benign'
                                      AND is_blocked = 1)
           / NULLIF(COUNT(*) FILTER (WHERE truth_label <> 'benign'), 0))::numeric, 3)
                                                                        AS true_block_pct
FROM dns_events
WHERE truth_label IS NOT NULL;
