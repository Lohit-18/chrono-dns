# Architecture

How a DNS packet becomes a decision, and why each layer is shaped the way it is.

---

## 1. The request path

```
  client                gateway              engine                 storage         upstream
    │                      │                    │                      │               │
    ├── UDP query ────────►│                    │                      │               │
    │                      ├── parse (dnslib)   │                      │               │
    │                      ├── DNSQuery ───────►│                      │               │
    │                      │                    ├─ extract 104 feats   │               │
    │                      │                    ├─ RF   (fast path)    │               │
    │                      │                    ├─ iForest (if needed) │               │
    │                      │                    ├─ heuristics          │               │
    │                      │                    ├─ allowlist (memory)  │               │
    │                      │                    ├─ intel     (memory)  │               │
    │                      │                    ├─ policy → Verdict    │               │
    │                      │◄── Detection ──────┤                      │               │
    │                      │                    └── queue row ────────►│ (write-behind)│
    │                      ├─ BLOCK? ── sinkhole reply ────────────────┼───────────────┤
    │                      ├─ cache hit? ── retag txid ────────────────┼───────────────┤
    │                      ├─ else ── forward ─────────────────────────┼──────────────►│
    │◄── reply ────────────┤                                           │◄──────────────┤
```

Total inline budget: **~3 ms p50**. Nothing on this path performs blocking I/O.

---

## 2. Module map

| Package | Responsibility | Key invariant |
|---|---|---|
| `chronodns.types` | `DNSQuery`, `Detection`, `Verdict`, `ThreatClass` | The only vocabulary shared across layers |
| `chronodns.features` | 104-dimension extraction | Vector **order is frozen**; adding a feature is a model-version bump |
| `chronodns.ml` | Ensemble, heuristics, training | Offline metrics come from the same scorer the gateway uses |
| `chronodns.engine` | Verdict engine + policy | One `analyse()`; never raises; fail-open |
| `chronodns.gateway` | asyncio UDP/TCP proxy, cache, upstream | Never blocks; always answers |
| `chronodns.storage` | Dual-backend DB + repository | Every SQL statement lives here |
| `chronodns.datagen` | Traffic simulators | Reserved TLDs only; no network activity |
| `chronodns.api` | FastAPI dashboard + REST | Thin client; SQL does the analytics |
| `chronodns.cli` | 16 Rich commands | The demo surface |

---

## 3. The single-seam principle

The gateway, the replay tool, the benchmark and the test suite all call
`ChronoEngine.analyse()`. There is no separate "research pipeline".

Why this matters: the classic failure mode of ML security projects is a notebook that reports 99%
and a production service that behaves differently, because feature computation drifted between
them. Here that is structurally impossible — `chronodns replay` and `chronodns serve` execute the
same function on the same extractor.

The one deliberate exception is `analyse_batch_fast()`, used by the benchmark, which vectorises
scoring across a matrix. It produces identical scores; only the sklearn call shape differs.

---

## 4. Statefulness

Two rolling state machines live in `features/temporal.py`:

```
TemporalTracker
├── hosts:  {source_ip           → HostWindow}   bounded at 4,096, LRU-evicted
└── zones:  {(source_ip, zone)   → ZoneWindow}   bounded at 32,768, LRU-evicted
```

`ZoneWindow` holds a 256-entry deque of timestamps and inter-arrival times, a 512-entry deque of
subdomains, a set of unique subdomains, a qtype counter and an uploaded-byte total.

This is the part a stateless "score one string" detector cannot have — and it is where beaconing and
sustained exfiltration are actually visible. It also makes the extractor **order-dependent**, which
is why training uses a chronological split: shuffling would leak future state into past rows.

**Bounded memory is a requirement, not an optimisation.** An attacker who sends a million unique
source IPs must not be able to OOM the resolver, so both maps evict their oldest quarter when they
exceed their cap.

---

## 5. The three-voter ensemble

```
score_fused = 0.65·P(threat | RF) + 0.20·anomaly(iForest) + 0.15·heuristic_evidence
```

| Voter | Sees | Strength | Blind spot |
|---|---|---|---|
| Random Forest | Labelled attacks | Precise on known families | Anything genuinely new |
| Isolation Forest | **Benign only** | Flags novelty | Noisy alone; no notion of "attack" |
| Heuristics | Nothing (deterministic) | Auditable, works day zero | Bypassable in isolation |

Keeping them separate rather than stacking is an operational choice: every block carries a reason
string naming which voter objected and on what evidence.

### The cascade shortcut

Because `anomaly ∈ [0,1]` with fixed weight `w`, the fused score before running the Isolation
Forest is bounded:

```
lo = w_sup·supervised + w_heur·heuristic
hi = lo + w_anom
```

If `band(lo) == band(hi)`, the anomaly voter cannot move the query across a threshold, so it is
skipped and the verdict is **provably identical** to a full evaluation. Measured skip rate on a
realistic traffic mix: **89.3%**.

`tests/test_ml.py::test_cascade_shortcut_never_changes_the_verdict_band` asserts the invariant.

---

## 6. The policy layer

A score is not a decision. Between `0.72` and `NXDOMAIN` sits:

```
1. allowlist            → ALLOW, always, no matter the score
2. intel severity ≥ 8   → BLOCK, outranks the model
3. rate-limit note      → annotate (does not decide)
4. score bands          → ALLOW / MONITOR / (malicious)
5. debounce             → N hits in a window before enforcing
6. enforce flag         → monitor-only mode blocks nothing
```

**The debounce key is class-aware.** `(host, zone)` is right for tunnelling and C2, where one zone is
hit repeatedly. It is exactly wrong for DGA, where every query is a brand-new zone and a per-zone
counter never reaches two. DGA therefore debounces on `(host, class)`. This bug was found by looking
at a replay where 643 DGA queries were detected and zero were blocked.

---

## 7. Storage

### Write-behind

```
engine ──► repo.record()  ──► in-memory buffer (200 rows)
                                    │
                        flush loop ─┴─► executemany()  every 1.0s
```

Alerts follow the same pattern but aggregate first: a tunnelling session produces hundreds of
malicious queries belonging to **one incident**, so they are deduplicated by
`sha256(host|zone|class)` in memory and upserted as a single row with a hit counter.

### In-memory intelligence

The whole allowlist and IOC set is loaded at startup. Even a large curated feed is a few hundred
thousand strings — tens of MB of Python dict — and lookups then cost a hash instead of a query.
`chronodns intel add` refreshes it.

### Dialect neutrality

Queries are written once with `?` placeholders; `storage/db.py::_to_pg()` rewrites them to `$1..$n`
for asyncpg, skipping question marks inside string literals. Only two things differ between
backends: timestamp representation (REAL epoch vs `TIMESTAMPTZ`) and the handful of
PostgreSQL-exclusive features (BRIN, GIN-trigram, plpgsql triggers, `LISTEN/NOTIFY`, materialized
views).

---

## 8. Failure modes and what happens

| Failure | Behaviour |
|---|---|
| Engine raises | `fail_open=true` → query resolves normally, error counted, logged |
| Model file missing | Heuristics-only mode, warning logged, gateway still functional |
| Database unreachable | Buffer flush logs an error and drops the batch; **resolution continues** |
| Upstream resolver down | Next upstream in the list; failures tracked and de-prioritised |
| All upstreams down | SERVFAIL returned (fast) rather than a hang |
| Malformed packet | Counted and dropped; no reply, no crash |
| Memory pressure | LRU eviction on host/zone maps, answer cache, and alert buffer |
| scikit-learn version change | Fast inference path self-verifies at load and falls back permanently |

---

## 9. Threat model

**In scope:** an endpoint inside the perimeter, already compromised, attempting to exfiltrate data
or reach C2 via DNS resolution that transits this gateway.

**Out of scope:** DoH/DoT to a public resolver (never reaches us), an attacker with the ability to
change the endpoint's resolver configuration, physical exfiltration paths, and DNS traffic that
does not route through this resolver.

**Assumed adversary capability:** can read this repository, knows the feature set, and will
deliberately shape traffic to evade it. `chronodns evade` exists to quantify how that goes —
see the README's honesty section for the number.
