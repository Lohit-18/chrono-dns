-- ===========================================================================
--  Chrono-DNS :: stored functions, triggers and alert deduplication
--  Pushing logic into the database keeps the hot path in Python tiny.
-- ===========================================================================
SET search_path TO chrono, public;

-- ---------------------------------------------------------------------------
-- fn_intel_lookup(domain) -> the most severe matching indicator
-- Checks exact FQDN, then the registrable zone, then the TLD, in one call.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_intel_lookup(p_qname TEXT)
RETURNS TABLE (indicator TEXT, category TEXT, severity SMALLINT, source TEXT)
LANGUAGE sql STABLE AS $$
    WITH parts AS (
        SELECT
            p_qname                                           AS fqdn,
            regexp_replace(p_qname, '^.*?([^.]+\.[^.]+)$', '\1') AS zone,
            regexp_replace(p_qname, '^.*\.', '')              AS tld
    )
    SELECT ti.indicator, ti.category, ti.severity, ti.source
    FROM threat_intel ti, parts p
    WHERE (ti.expires_at IS NULL OR ti.expires_at > now())
      AND (
            (ti.ioc_type = 'domain' AND ti.indicator = p.fqdn)
         OR (ti.ioc_type = 'zone'   AND ti.indicator = p.zone)
         OR (ti.ioc_type = 'tld'    AND ti.indicator = p.tld)
      )
    ORDER BY ti.severity DESC
    LIMIT 1;
$$;

-- ---------------------------------------------------------------------------
-- fn_is_allowlisted(domain) -> boolean
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_is_allowlisted(p_qname TEXT)
RETURNS BOOLEAN
LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM allowlist a
        WHERE (a.match_type = 'exact'  AND p_qname = a.pattern)
           OR (a.match_type = 'suffix' AND (p_qname = a.pattern
                                        OR p_qname LIKE '%.' || a.pattern))
           OR (a.match_type = 'regex'  AND p_qname ~ a.pattern)
    );
$$;

-- ---------------------------------------------------------------------------
-- fn_upsert_baseline() — incrementally learn what "normal" looks like
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_upsert_baseline(
    p_zone TEXT, p_entropy REAL, p_len INTEGER, p_sub TEXT
) RETURNS VOID
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO domain_baseline AS b
        (registrable, query_count, unique_subdomains, mean_entropy, mean_qname_len)
    VALUES (p_zone, 1, 1, p_entropy, p_len)
    ON CONFLICT (registrable) DO UPDATE SET
        query_count    = b.query_count + 1,
        last_seen      = now(),
        -- Welford-style online mean, so we never re-scan history.
        mean_entropy   = b.mean_entropy + (p_entropy - b.mean_entropy) / (b.query_count + 1),
        mean_qname_len = b.mean_qname_len + (p_len - b.mean_qname_len) / (b.query_count + 1);
END;
$$;

-- ---------------------------------------------------------------------------
-- fn_raise_alert() — deduplicating incident writer
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_raise_alert(
    p_src INET, p_zone TEXT, p_class TEXT, p_score REAL,
    p_bytes BIGINT DEFAULT 0, p_summary TEXT DEFAULT NULL
) RETURNS BIGINT
LANGUAGE plpgsql AS $$
DECLARE
    v_fp TEXT;
    v_id BIGINT;
BEGIN
    v_fp := encode(sha256((host(p_src) || '|' || p_zone || '|' || p_class)::bytea), 'hex');
    INSERT INTO alerts AS a
        (fingerprint, source_ip, registrable, threat_class,
         severity, max_score, bytes_exfil, summary)
    VALUES
        (v_fp, p_src, p_zone, p_class,
         LEAST(10, GREATEST(1, (p_score * 10)::SMALLINT)), p_score, p_bytes, p_summary)
    ON CONFLICT (fingerprint) DO UPDATE SET
        hit_count   = a.hit_count + 1,
        updated_at  = now(),
        max_score   = GREATEST(a.max_score, p_score),
        bytes_exfil = a.bytes_exfil + p_bytes,
        severity    = GREATEST(a.severity, LEAST(10, GREATEST(1, (p_score * 10)::SMALLINT)))
    RETURNING a.id INTO v_id;
    RETURN v_id;
END;
$$;

-- ---------------------------------------------------------------------------
-- Trigger: automatically open/refresh an alert whenever a BLOCK lands.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_event_to_alert() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.is_blocked = 1 OR NEW.score >= 0.70 THEN
        PERFORM fn_raise_alert(
            NEW.source_ip, NEW.registrable, NEW.threat_class, NEW.score,
            LENGTH(NEW.subdomain)::BIGINT,
            left(coalesce(NEW.reasons, NEW.qname), 400)
        );
        -- Wake any LISTENing dashboard instantly — no polling required.
        PERFORM pg_notify('chrono_alerts',
            json_build_object(
                'ip', host(NEW.source_ip), 'zone', NEW.registrable,
                'class', NEW.threat_class, 'score', NEW.score
            )::text);
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tr_event_to_alert ON dns_events;
CREATE TRIGGER tr_event_to_alert
    AFTER INSERT ON dns_events
    FOR EACH ROW EXECUTE FUNCTION trg_event_to_alert();

-- ---------------------------------------------------------------------------
-- fn_prune(days) — retention policy
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_prune(p_days INTEGER DEFAULT 30)
RETURNS BIGINT
LANGUAGE plpgsql AS $$
DECLARE v_n BIGINT;
BEGIN
    DELETE FROM dns_events WHERE ts < now() - (p_days || ' days')::INTERVAL;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    DELETE FROM alerts WHERE status = 'closed' AND updated_at < now() - INTERVAL '90 days';
    RETURN v_n;
END;
$$;
