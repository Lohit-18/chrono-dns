"""
The ML ensemble.

Three independent voters, fused into one 0..1 threat score:

  1. **Random Forest (supervised, multi-class)** — learns the boundary between
     benign / tunneling / dga / c2_beacon from labelled traffic. Excellent on
     known attack shapes, blind to anything genuinely new.

  2. **Isolation Forest (unsupervised, trained on BENIGN ONLY)** — learns the
     manifold of normal traffic. Anything far from it scores high, including
     attack families that did not exist at training time. This is the
     zero-day voter.

  3. **Expert heuristics** — deterministic, auditable, and immune to model
     drift (see heuristics.py).

Fusion is a weighted sum, then a policy layer maps the score to a verdict.
Keeping the voters separate (rather than stacking into one opaque model) is a
deliberate operational choice: when the gateway blocks something, an analyst
can see *which* voter objected and why.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from ..logging_utils import get_logger
from .heuristics import classify_by_rules, heuristic_score

log = get_logger("ml.detectors")

CLASSES = ["benign", "tunneling", "dga", "c2_beacon"]


@dataclass
class EnsembleScores:
    supervised: float = 0.0
    anomaly: float = 0.0
    heuristic: float = 0.0
    fused: float = 0.0
    anomaly_evaluated: bool = True
    threat_class: str = "benign"
    class_probs: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    top_features: list[tuple[str, float]] = field(default_factory=list)


class ThreatEnsemble:
    """Loads/holds the trained models and scores feature vectors."""

    ARTIFACT = "chronodns_model.joblib"

    def __init__(self, weights: tuple[float, float, float] = (0.65, 0.20, 0.15)) -> None:
        self.w_sup, self.w_anom, self.w_heur = weights
        self.rf: Any = None
        self.iforest: Any = None
        self.scaler: Any = None
        self.feature_names: list[str] = []
        self.classes_: list[str] = list(CLASSES)
        self.importances: np.ndarray | None = None
        self.benign_median: np.ndarray | None = None
        self.benign_iqr: np.ndarray | None = None
        self.version: str = "untrained"
        self.metrics: dict[str, float] = {}
        self._anom_lo: float = -0.5
        self._anom_hi: float = 0.5
        # Ablation mask: 1.0 = feature active, 0.0 = feature suppressed.
        # Used by `chronodns ablate` to prove the model does not depend on any
        # single shortcut (e.g. the TLD) to reach its accuracy.
        self.feature_mask: np.ndarray | None = None
        # Verdict bands + the benign baseline anomaly score, used by the
        # cascade shortcut in score_vector(). See _bounds_same_band().
        self.band_suspicious: float = 0.45
        self.band_malicious: float = 0.70
        self.baseline_anomaly: float = 0.30
        self.cascade_skips: int = 0
        self.cascade_calls: int = 0
        self._fast_path_ok: bool = False

    # ------------------------------------------------------------------ #
    @property
    def is_trained(self) -> bool:
        return self.rf is not None

    def load(self, model_dir: str | Path) -> bool:
        path = Path(model_dir) / self.ARTIFACT
        if not path.exists():
            log.warning("no model at %s — running in heuristics-only mode", path)
            return False
        import joblib

        bundle = joblib.load(path)
        self.rf = bundle["rf"]
        self.iforest = bundle["iforest"]
        # Inference is single-row on the DNS hot path: joblib's thread pool
        # costs more than it saves there, so force serial prediction.
        for est in (self.rf, self.iforest):
            with contextlib.suppress(Exception):
                est.n_jobs = 1
        self.scaler = bundle["scaler"]
        self.feature_names = bundle["feature_names"]
        self.classes_ = list(bundle["classes"])
        self.importances = bundle.get("importances")
        self.benign_median = bundle.get("benign_median")
        self.benign_iqr = bundle.get("benign_iqr")
        self.version = bundle.get("version", "unknown")
        self.metrics = bundle.get("metrics", {})
        self._anom_lo = bundle.get("anom_lo", -0.5)
        self._anom_hi = bundle.get("anom_hi", 0.5)
        self.feature_mask = bundle.get("feature_mask")
        self.baseline_anomaly = bundle.get("baseline_anomaly", 0.30)
        log.info("model %s loaded (%d features, acc=%.4f)",
                 self.version, len(self.feature_names),
                 self.metrics.get("accuracy", 0.0))
        return True

    def save(self, model_dir: str | Path) -> Path:
        import joblib

        path = Path(model_dir)
        path.mkdir(parents=True, exist_ok=True)
        target = path / self.ARTIFACT
        joblib.dump({
            "rf": self.rf, "iforest": self.iforest, "scaler": self.scaler,
            "feature_names": self.feature_names, "classes": self.classes_,
            "importances": self.importances,
            "benign_median": self.benign_median, "benign_iqr": self.benign_iqr,
            "version": self.version, "metrics": self.metrics,
            "anom_lo": self._anom_lo, "anom_hi": self._anom_hi,
            "feature_mask": self.feature_mask,
            "baseline_anomaly": self.baseline_anomaly,
        }, target, compress=3)
        (path / "model_card.json").write_text(json.dumps({
            "version": self.version,
            "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "classes": self.classes_,
            "feature_count": len(self.feature_names),
            "metrics": self.metrics,
            "weights": {"supervised": self.w_sup, "anomaly": self.w_anom,
                        "heuristic": self.w_heur},
        }, indent=2))
        return target

    @staticmethod
    def make_version(feature_names: list[str], n_rows: int) -> str:
        digest = hashlib.sha1(
            ("|".join(feature_names) + f"|{n_rows}").encode()
        ).hexdigest()[:10]
        return f"v1-{time.strftime('%Y%m%d')}-{digest}"

    # ------------------------------------------------------------------ #
    def apply_mask(self, matrix: np.ndarray) -> np.ndarray:
        """Zero out ablated features so a masked model never sees them."""
        if self.feature_mask is None:
            return matrix
        return matrix * self.feature_mask

    def _band(self, score: float) -> int:
        if score < self.band_suspicious:
            return 0
        if score < self.band_malicious:
            return 1
        return 2

    def _bounds_same_band(self, lo: float, hi: float) -> bool:
        return self._band(min(lo, 1.0)) == self._band(min(hi, 1.0))

    def set_bands(self, suspicious: float, malicious: float) -> None:
        self.band_suspicious, self.band_malicious = suspicious, malicious

    def _fast_proba(self, x: np.ndarray) -> np.ndarray:
        """Single-row Random Forest probability without sklearn's overhead.

        `RandomForestClassifier.predict_proba` re-validates the input and spins
        up a joblib dispatcher for *every* call. On a batch that cost is
        amortised; on the DNS hot path, where we score one 102-float row at a
        time, it dominates — measured at ~40 ms/query against ~1 ms for the
        trees themselves. Walking the fitted trees directly gives numerically
        identical output at a fraction of the cost.
        """
        if not self._fast_path_ok:
            return self.rf.predict_proba(x)[0]
        trees = self.rf.estimators_
        total = np.zeros(len(self.classes_), dtype=np.float64)
        for est in trees:
            total += est.predict_proba(x, check_input=False)[0]
        return total / len(trees)

    def _verify_fast_path(self, sample: np.ndarray) -> bool:
        """Trust but verify.

        The fast path bypasses scikit-learn's public API, so a future version
        could change tree internals underneath it. Rather than silently
        returning wrong scores, we compare against `predict_proba` once at load
        time and fall back permanently if they disagree.
        """
        try:
            x = np.ascontiguousarray(sample, dtype=np.float32).reshape(1, -1)
            self._fast_path_ok = True
            fast = self._fast_proba(x)
            self._fast_path_ok = False
            ref = self.rf.predict_proba(x)[0]
            ok = bool(np.allclose(fast, ref, atol=1e-6))
            self._fast_path_ok = ok
            if not ok:
                log.warning("fast inference path disagrees with scikit-learn — "
                            "falling back to predict_proba")
            return ok
        except Exception as exc:                           # noqa: BLE001
            log.warning("fast inference path unavailable (%s) — using sklearn", exc)
            self._fast_path_ok = False
            return False

    def _normalize_anomaly(self, raw: np.ndarray) -> np.ndarray:
        """Map IsolationForest decision_function to 0..1 (1 = most anomalous)."""
        span = max(self._anom_hi - self._anom_lo, 1e-9)
        return np.clip((self._anom_hi - raw) / span, 0.0, 1.0)

    def score_vector(self, vec: np.ndarray, features: dict[str, float]
                     ) -> EnsembleScores:
        """Score a single query. This runs on the DNS hot path — keep it tight."""
        out = EnsembleScores()

        # -- voter 3: heuristics (always available) -------------------------
        out.heuristic, out.reasons = heuristic_score(features)

        if not self.is_trained:
            out.fused = out.heuristic
            out.threat_class = classify_by_rules(features)
            return out

        x = self.apply_mask(np.ascontiguousarray(vec, dtype=np.float32).reshape(1, -1))

        # -- voter 1: supervised -------------------------------------------
        probs = self._fast_proba(x)
        out.class_probs = {c: float(p) for c, p in zip(self.classes_, probs, strict=False)}
        benign_idx = self.classes_.index("benign") if "benign" in self.classes_ else 0
        out.supervised = float(1.0 - probs[benign_idx])
        # Threat class = most likely non-benign class, when anything is likely.
        mal = {c: p for c, p in out.class_probs.items() if c != "benign"}
        out.threat_class = max(mal, key=mal.get) if mal else "benign"

        # -- voter 2: anomaly, evaluated only when it can change the answer --
        #
        # The anomaly score is bounded in [0, 1] and carries a fixed weight, so
        # the fused score is bounded by [base, base + w_anom] before we ever
        # run the Isolation Forest. If both bounds fall inside the same verdict
        # band, the anomaly voter provably cannot change the decision, and we
        # skip the most expensive stage. This is exact, not an approximation:
        # the verdict is identical to a full evaluation. In practice it skips
        # the forest on the large majority of queries, which is where the
        # inline latency budget is won.
        base = self.w_sup * out.supervised + self.w_heur * out.heuristic
        if self._bounds_same_band(base, base + self.w_anom):
            out.anomaly = self.baseline_anomaly
            out.anomaly_evaluated = False
            self.cascade_skips += 1
        else:
            xs = self.scaler.transform(x)
            raw = float(self.iforest.decision_function(xs)[0])
            out.anomaly = float(self._normalize_anomaly(np.array([raw]))[0])
            self.cascade_calls += 1

        # -- fusion -----------------------------------------------------------
        out.fused = float(min(max(base + self.w_anom * out.anomaly, 0.0), 1.0))

        if out.fused < 0.35:
            out.threat_class = "benign"

        out.top_features = self.explain(vec)
        return out

    def score_batch(self, matrix: np.ndarray, feature_dicts: list[dict[str, float]]
                    ) -> list[EnsembleScores]:
        """Vectorised scoring for replay / benchmarking — far faster than a loop."""
        n = len(feature_dicts)
        results = [EnsembleScores() for _ in range(n)]

        for i, fd in enumerate(feature_dicts):
            results[i].heuristic, results[i].reasons = heuristic_score(fd)

        if not self.is_trained:
            for i, fd in enumerate(feature_dicts):
                results[i].fused = results[i].heuristic
                results[i].threat_class = classify_by_rules(fd)
            return results

        matrix = self.apply_mask(matrix)
        probs = self.rf.predict_proba(matrix)
        benign_idx = self.classes_.index("benign")
        anom_raw = self.iforest.decision_function(self.scaler.transform(matrix))
        anom = self._normalize_anomaly(anom_raw)

        for i in range(n):
            r = results[i]
            r.class_probs = {c: float(p) for c, p in zip(self.classes_, probs[i], strict=False)}
            r.supervised = float(1.0 - probs[i][benign_idx])
            r.anomaly = float(anom[i])
            r.fused = float(min(max(
                self.w_sup * r.supervised + self.w_anom * r.anomaly
                + self.w_heur * r.heuristic, 0.0), 1.0))
            mal = {c: p for c, p in r.class_probs.items() if c != "benign"}
            r.threat_class = max(mal, key=mal.get) if mal and r.fused >= 0.35 else "benign"
        return results

    # ------------------------------------------------------------------ #
    def explain(self, vec: np.ndarray, top_k: int = 5) -> list[tuple[str, float]]:
        """Which features pushed this query away from normal?

        Contribution = global importance x robust z-distance from the benign
        median. Cheap, model-agnostic, and it produces the kind of sentence an
        analyst can act on — unlike a bare probability.
        """
        if self.importances is None or self.benign_median is None:
            return []
        iqr = self.benign_iqr if self.benign_iqr is not None else np.ones_like(vec)
        deviation = np.abs(vec - self.benign_median) / np.maximum(iqr, 1e-6)
        contribution = self.importances * np.tanh(deviation / 3.0)
        idx = np.argsort(contribution)[::-1][:top_k]
        return [(self.feature_names[i], float(contribution[i]))
                for i in idx if contribution[i] > 1e-4]

    def global_importances(self, top_k: int = 20) -> list[tuple[str, float]]:
        if self.importances is None:
            return []
        idx = np.argsort(self.importances)[::-1][:top_k]
        return [(self.feature_names[i], float(self.importances[i])) for i in idx]
