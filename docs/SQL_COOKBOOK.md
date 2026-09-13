# SQL cookbook

Eight threat-hunting queries, what each one answers, and why it is written that way.

Run them against PostgreSQL:

```bash
psql -h 127.0.0.1 -U chronodns -d chronodns -f sql/analytics/02_beacon_detection.sql
```

…or hit the pre-wired versions through the CLI:

```bash
chronodns hunt tunnels    beacons    talkers    threats    alerts
chronodns hunt host 10.20.4.88
chronodns hunt search cobalt
```

---

## 1 · Exfiltration leaderboard

**File:** [`01_exfiltration_leaderboard.sql`](../sql/analytics/01_exfiltration_leaderboard.sql)
**Question:** *who is pushing the most data out over DNS?*

Every byte an attacker exfiltrates has to appear in a subdomain label. So
`SUM(LENGTH(subdomain))` grouped by zone **is** the upload volume — no deep packet inspection
required.

```sql
SUM(LENGTH(subdomain))                        AS raw_bytes,
ROUND((raw_bytes * 0.625 / 1024.0)::numeric, 2) AS est_kib_payload
```

The `0.625` converts characters to bytes: base32 packs 5 bits per character, so the real payload is
about 62.5% of what you see on the wire.

> **Read the results carefully.** Antivirus and RBL reputation services legitimately encode hashes
> into subdomains and will rank high here. The query qualifies each zone with mean entropy and
> subdomain novelty precisely so a chatty-but-legitimate service does not top the chart on volume
> alone.

---

## 2 · Beacon detection

**File:** [`02_beacon_detection.sql`](../sql/analytics/02_beacon_detection.sql)
**Question:** *which host is calling home on a timer?*

`LAG()` over `PARTITION BY source_ip, registrable ORDER BY ts` turns a table of events into a table
of gaps. The coefficient of variation of those gaps is the whole detector:

| CV | Interpretation |
|---|---|
| < 0.02 | Lockstep — a scheduled task or an implant with no jitter |
| < 0.10 | Beacon — Cobalt-Strike-style 10% jitter |
| < 0.25 | Periodic — jittered C2, or a poller |
| > 1.00 | Human browsing |

```sql
STDDEV_POP(gap_s) / NULLIF(AVG(gap_s), 0) AS cv
```

`NULLIF` rather than a `CASE`: a zone touched once has a zero mean, and dividing by it should
produce NULL (excluded), not an exception.

> Legitimate software polls on a timer too. macOS update checks and NTP will appear in these
> results. This query produces **leads**; the ML ensemble produces verdicts.

---

## 3 · DGA storm

**File:** [`03_dga_nxdomain_storm.sql`](../sql/analytics/03_dga_nxdomain_storm.sql)
**Question:** *which host is burning through algorithmically generated names?*

A DGA implant generates hundreds of candidate domains and most are unregistered, so the signature is
a burst of failures across many unrelated zones from one host. That needs a **time-based** window,
not a row-based one:

```sql
COUNT(*) FILTER (WHERE threat_class = 'dga') OVER (
    PARTITION BY source_ip ORDER BY ts
    RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW
) AS dga_in_5m
```

`RANGE BETWEEN INTERVAL` is the piece worth knowing: `ROWS` would count the previous N rows
regardless of when they happened, which measures nothing useful about a burst.

---

## 4 · Baseline drift

**File:** [`04_baseline_drift.sql`](../sql/analytics/04_baseline_drift.sql)
**Question:** *did a zone we already trust suddenly start behaving differently?*

Attackers love a zone that already has a clean reputation. The tell is a jump in entropy or query
length relative to that zone's **own learned history** — a z-score computed in SQL:

```sql
(r.cur_entropy - b.mean_entropy) / GREATEST(b.std_entropy, 0.25) AS z_score
```

The `GREATEST(..., 0.25)` floor matters: a zone with zero historical variance would otherwise divide
by zero and every tiny change would read as infinitely significant.

The baseline itself is maintained incrementally by `fn_upsert_baseline()` using a Welford-style
online mean, so no historical rescan is ever needed:

```sql
mean_entropy = b.mean_entropy + (p_entropy - b.mean_entropy) / (b.query_count + 1)
```

---

## 5 · Intel enrichment join

**File:** [`05_intel_join_enrichment.sql`](../sql/analytics/05_intel_join_enrichment.sql)
**Question:** *which live events match curated intelligence?*

A three-way join that matches on FQDN, registrable zone **and** TLD in a single pass, with the
allowlist applied as an anti-join so trusted CDNs never generate noise:

```sql
JOIN threat_intel ti
      ON (ti.ioc_type = 'domain' AND ti.indicator = e.qname)
      OR (ti.ioc_type = 'zone'   AND ti.indicator = e.registrable)
      OR (ti.ioc_type = 'tld'    AND ti.indicator = e.tld)
...
AND NOT EXISTS (SELECT 1 FROM allowlist al WHERE ...)
```

The final column fuses both sources of evidence into one triage order:

```sql
ROUND((0.6 * e.score + 0.4 * (ti.severity / 10.0))::numeric, 3) AS priority
```

---

## 6 · Model performance

**File:** [`06_model_performance.sql`](../sql/analytics/06_model_performance.sql)
**Question:** *is the model still any good?*

Precision, recall and F1 per class, computed entirely in SQL from `truth_label`. In a replay that
column holds ground truth; in production you back-fill it from analyst triage decisions, which turns
this query into a live drift monitor.

```sql
SUM(c.n) FILTER (WHERE c.predicted = c.actual)  AS tp,
SUM(c.n) FILTER (WHERE c.predicted <> c.actual) AS fn,
(SELECT COALESCE(SUM(n),0) FROM cm x
  WHERE x.predicted = c.actual AND x.actual <> c.actual) AS fp
```

The second statement reports the number that actually matters operationally: **false-positive rate
on benign traffic**. An accuracy figure hides it; a security team lives and dies by it.

---

## 7 · Kill-chain timeline

**File:** [`07_kill_chain_timeline.sql`](../sql/analytics/07_kill_chain_timeline.sql)
**Question:** *tell me the whole story for one compromised host.*

Incident-response output: every query in order with a moving-average threat score and a marker on
the moment behaviour changed.

```sql
FIRST_VALUE(ts) OVER w                                        AS session_start,
AVG(score) OVER (PARTITION BY source_ip ORDER BY ts
                 ROWS BETWEEN 9 PRECEDING AND CURRENT ROW)    AS score_ma10,
SUM(is_blocked) OVER (PARTITION BY source_ip ORDER BY ts)     AS blocks_so_far
```

The `<<< BEHAVIOUR SHIFT` marker fires on the row where the 10-query moving average crosses 0.7 —
usually the exact moment an ordinary workstation became an exfiltration node.

---

## 8 · Campaign clustering

**File:** [`08_zone_fanout_graph.sql`](../sql/analytics/08_zone_fanout_graph.sql)
**Question:** *which hosts share infrastructure?*

If five endpoints all talk to the same rare zone, that is a campaign, not a coincidence. A self-join
builds host-to-host adjacency; rarity weighting keeps `google.com` out of the results:

```sql
JOIN dns_events b
  ON a.registrable = b.registrable
 AND a.source_ip < b.source_ip        -- each unordered pair exactly once
```

`a.source_ip < b.source_ip` is the trick that avoids both self-pairs and duplicate mirrored rows.

---

## Schema notes worth keeping

### Indexing

```sql
-- Append-only timestamps: BRIN is ~1000x smaller than a B-tree here.
CREATE INDEX idx_events_ts_brin ON dns_events USING BRIN (ts)
  WITH (pages_per_range = 32);

-- ~1% of rows are blocked, so this index is tiny and the SOC's
-- most-run query becomes effectively instant.
CREATE INDEX idx_events_blocked ON dns_events (ts DESC) WHERE is_blocked = 1;

-- Fuzzy analyst search: qname ILIKE '%cobalt%'
CREATE INDEX idx_events_qname_trgm ON dns_events USING GIN (qname gin_trgm_ops);
```

### Push instead of poll

```sql
PERFORM pg_notify('chrono_alerts', json_build_object(
    'ip', host(NEW.source_ip), 'zone', NEW.registrable,
    'class', NEW.threat_class, 'score', NEW.score)::text);
```

Fired from the `AFTER INSERT` trigger on `dns_events`, so a dashboard can `LISTEN chrono_alerts` and
update the instant a block happens — no polling loop at all.

### Retention

```sql
SELECT fn_prune(30);   -- delete events older than 30 days, close stale alerts
```

DNS logs are personal data in many jurisdictions. Pick the number with your privacy team, then put
that call in cron.

---

## Porting to SQLite

The SQLite dialect ([`sql/sqlite/`](../sql/sqlite/)) mirrors the schema, and SQLite 3.25+ supports
window functions, so most of these translate almost verbatim. Two differences:

| PostgreSQL | SQLite |
|---|---|
| `ts TIMESTAMPTZ`, `EXTRACT(EPOCH FROM (a - b))` | `ts REAL` (unix epoch), plain `a - b` |
| `STDDEV_POP(x)` | `AVG(x*x) - AVG(x)*AVG(x)` then take the root |
| BRIN, GIN-trigram, plpgsql, `LISTEN/NOTIFY`, materialized views | not available |
