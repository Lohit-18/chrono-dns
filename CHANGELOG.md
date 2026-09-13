# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-09-13

First public release.

### Added

**Detection engine**
- 104-feature extraction pipeline: 46 lexical, 27 structural, 31 temporal, in a frozen vector order
- Three-voter ensemble — Random Forest (supervised, 4-class), Isolation Forest (unsupervised,
  trained on benign traffic only), and 12 deterministic expert rules — fused by weighted sum
- Per-verdict explainability: which voter objected, on what evidence, with the most anomalous
  feature values
- Policy layer with allowlist precedence, threat-intel escalation, class-aware debouncing, sliding
  window rate limiting, monitor-only mode and fail-open error handling

**Gateway**
- asyncio DNS proxy on UDP and TCP, built on `dnslib`
- Upstream forwarding with automatic failover and failure-weighted resolver ordering
- TTL-aware LRU answer cache with transaction-ID retagging
- Sinkhole responses: `0.0.0.0` / `::` for address queries, NXDOMAIN for TXT/NULL/CNAME tunnels

**Storage**
- Dual backend: SQLite (zero install, default) and PostgreSQL (production)
- Single dialect-neutral query surface; `?` placeholders rewritten to `$1..$n` for asyncpg
- Seven tables, BRIN and partial indexes, GIN-trigram fuzzy search, six analytical views, a
  materialized hourly rollup, four plpgsql functions and an alert-raising trigger with `pg_notify`
- Write-behind buffering for events; in-memory aggregation and deduplication for alerts
- Whole allowlist and IOC set cached in memory — no database round-trip on the packet path
- Eight fully commented threat-hunting queries in `sql/analytics/`

**Data generation**
- Benign traffic simulator with Zipf-distributed popularity, bursty human timing, and deliberate
  hard negatives (CDN edges, cloud buckets, AV/RBL hash lookups, DKIM, reverse DNS, SRV, telemetry)
- Six DGA family archetypes: arithmetic, hash-based, dictionary, permutation, Markov, base36
- Four tunnelling tool profiles: iodine, dnscat2, dns2tcp, low-and-slow exfiltration
- C2 beacon generator with configurable interval and jitter
- Evasive ("hard mode") generator that deliberately targets each detection axis

**Interfaces**
- 16-command Rich CLI: `init`, `dataset`, `train`, `evade`, `ablate`, `explain`, `replay`, `live`,
  `serve`, `dashboard`, `hunt`, `report`, `bench`, `features`, `intel`, `demo`
- FastAPI dashboard with 12 REST endpoints and a single-file dark SOC console
- Seven Bash automation scripts: setup, database provisioning, guided demo, training runs,
  benchmark sweep, health check, attack simulation

**Engineering**
- 78 tests asserting mathematical properties, not just execution
- GitHub Actions matrix: Python 3.10/3.11/3.12, a live PostgreSQL service, Docker build, ShellCheck
- Multi-stage Dockerfile with a non-root user, plus a full `docker compose` stack
- Makefile with 24 targets

### Performance
- Feature extraction: 1,829 queries/second (0.547 ms each)
- Ensemble scoring, batched: 35,606 queries/second
- Full inline path including the database write: 272 queries/second, p50 2.96 ms
- Exact cascade shortcut skips the Isolation Forest on 89.3% of queries with identical verdicts
- Fast single-row Random Forest path, self-verified against scikit-learn at load time

### Detection results
On a held-out chronological split of 3,269 synthetic queries: accuracy 0.9920, weighted F1 0.9919,
ROC-AUC 1.0000, false-positive rate 0.00000. Against adversarially evasive traffic, a model trained
on standard data alone reaches 0.376 recall; `--harden` raises it to 1.000 at the same
false-positive rate.

### Known limitations
Documented in full in the README's *What this does not do* section. The short list: evaluation data
is synthetic, DoH/DoT bypasses the gateway entirely, the first beacon of any session is
undetectable by construction, and a patient adversary defeats any single-query analysis.

---

## Unreleased

See the roadmap in the README.
