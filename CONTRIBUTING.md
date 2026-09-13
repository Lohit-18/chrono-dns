# Contributing to Chrono-DNS

Thanks for being here. This project is defensive security tooling, and contributions that make it
harder to fool are the most valuable kind.

## What is especially wanted

1. **Evasion techniques that beat the current detector.** Open an issue with a reproducible
   generator and the recall it achieves. **Breaking this project is a contribution** — every evasion
   that lands becomes a test case and a hardening sample.
2. **Real, anonymised DNS captures** for evaluation. Synthetic data flatters detectors; a
   production capture is worth more than any amount of generator tuning. Strip or hash source IPs
   before sharing anything.
3. **Additional DGA family models** — the six archetypes in `chronodns/datagen/dga.py` cover the
   published shapes, but there are more.
4. **False positives.** If a legitimate service is being blocked, that is a bug of the highest
   severity. Tell us the hostname pattern and why it is legitimate.
5. **PostgreSQL query optimisation.** If you can make a hunting query faster, `EXPLAIN ANALYZE`
   before and after is welcome.

## Setup

```bash
git clone https://github.com/<you>/chrono-dns.git && cd chrono-dns
./scripts/setup.sh
source .venv/bin/activate
pip install -e ".[dev,web]"
```

## Before you open a PR

```bash
make lint            # ruff + mypy, must be clean
make test            # the whole suite, must pass
make healthcheck     # runtime verification, exit code 0
```

If you touched detection logic, also run:

```bash
chronodns train --harden
chronodns evade --count 300     # did recall move?
chronodns ablate                # did one feature group become a crutch?
```

## Code style

- **Ruff** with the config in `pyproject.toml`. 100-column lines.
- **Type hints on public functions.** `from __future__ import annotations` at the top of every
  module.
- **Comments explain *why*, never *what*.** `# increment counter` is noise. `# BRIN because this
  column is append-only and 1000x smaller than a B-tree` is the kind of comment this codebase wants.
- **Every SQL statement lives in `chronodns/storage/repository.py` or `sql/`.** Nowhere else.
- **Nothing blocks on the hot path.** If your change adds I/O to `ChronoEngine.analyse()`, it needs
  a very good reason and a benchmark.

## Adding a feature to the extractor

The feature vector order is **frozen** — a model trained last month must still line up with today's
gateway. So:

1. Add the computation in `features/lexical.py`, `structural.py` or `temporal.py`.
2. Add a one-line description to the `docs` dict in `features/extractor.py` — `chronodns features`
   and `docs/FEATURES.md` are generated from it, and an undocumented feature fails review.
3. Add a test asserting the *mathematical property* you are claiming, not just that it runs.
4. Retrain: `chronodns train --harden`. The feature count in the model version hash changes, which
   is exactly the signal that old models are now incompatible.
5. Regenerate `docs/FEATURES.md`.

## Testing philosophy

Tests here assert behaviour that matters, not coverage percentage:

```python
def test_perfect_beacon_has_near_zero_cv():
    ...
    assert feats["iat_cv"] < 0.01           # the detector's core claim

def test_no_nan_or_inf_for_pathological_inputs():
    ...                                      # a NaN in the vector is a crash in production
```

Mark anything that trains a model with `@pytest.mark.slow`.

## Commit messages

```
feat(features): add Kolmogorov complexity estimator for subdomains
fix(policy): debounce DGA on (host, class) — per-zone never fires
perf(ml): skip Isolation Forest when bounds share a verdict band
docs(sql): explain the RANGE vs ROWS window choice
test(gateway): cover malformed-packet handling
```

## What will not be merged

- **Offensive tooling.** Working tunnel clients, C2 frameworks, exfiltration utilities. The
  simulators here generate *strings* for training against reserved TLDs and establish no channel;
  that line does not move.
- Anything that makes the gateway fail closed by default.
- Features that require a paid service or API key to work.
- Telemetry, analytics or any outbound call the operator did not ask for.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Short version: be decent.

## Licence

Contributions are accepted under the [MIT Licence](LICENSE).
