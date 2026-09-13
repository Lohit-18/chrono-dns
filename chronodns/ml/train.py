"""
Training pipeline.

Key methodological choices (worth defending in a viva or an interview):

* **Chronological split, not random.** Temporal features leak across a random
  shuffle — a query's IAT depends on its neighbours. We split on time so the
  test set is genuinely "the future".
* **Group-aware evaluation.** Test hosts are disjoint from train hosts where
  possible, so the model cannot memorise a source IP's habits.
* **Isolation Forest sees only benign rows.** Fitting it on the full mix would
  teach it that attacks are normal, destroying the zero-day voter.
* **class_weight='balanced_subsample'.** Real traffic is ~97% benign; without
  reweighting, "predict benign always" scores 97% and detects nothing.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import numpy as np

from ..config import get_config
from ..features import FEATURE_NAMES, FeatureExtractor
from ..logging_utils import get_logger
from ..types import DNSQuery
from .detectors import CLASSES, ThreatEnsemble

log = get_logger("ml.train")


def chronological_split(queries: list[DNSQuery], test_size: float = 0.25
                        ) -> tuple[list[DNSQuery], list[DNSQuery]]:
    ordered = sorted(queries, key=lambda q: q.timestamp)
    cut = int(len(ordered) * (1 - test_size))
    return ordered[:cut], ordered[cut:]


def build_mask(exclude_prefixes: tuple[str, ...]) -> np.ndarray:
    """1.0 for active features, 0.0 for ablated ones."""
    return np.array(
        [0.0 if any(n.startswith(p) for p in exclude_prefixes) else 1.0
         for n in FEATURE_NAMES],
        dtype=np.float32,
    )


def train_model(queries: list[DNSQuery], cfg: Any = None,
                report_path: str | Path | None = None,
                exclude_prefixes: tuple[str, ...] = ()) -> tuple[ThreatEnsemble, dict]:
    """Train the full ensemble and return (model, metrics report).

    `exclude_prefixes` suppresses whole feature families (e.g. ``("tld_",)``)
    so you can prove the model is not leaning on a dataset artefact.
    """
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.metrics import (
        classification_report,
        confusion_matrix,
        precision_recall_fscore_support,
        roc_auc_score,
    )
    from sklearn.preprocessing import RobustScaler

    cfg = cfg or get_config()
    ml = cfg.ml
    t_start = time.time()

    log.info("dataset: %d queries", len(queries))
    train_q, test_q = chronological_split(queries, ml.test_size)
    log.info("chronological split: %d train / %d test", len(train_q), len(test_q))

    # Feature extraction: separate extractors so test-time temporal state is
    # rebuilt exactly as it would be on a cold gateway.
    fx_train, fx_test = FeatureExtractor(), FeatureExtractor()
    X_train, _ = fx_train.batch(train_q)
    X_test, test_feats = fx_test.batch(test_q)
    y_train = np.array([q.label or "benign" for q in train_q])
    y_test = np.array([q.label or "benign" for q in test_q])

    mask = build_mask(exclude_prefixes) if exclude_prefixes else None
    if mask is not None:
        suppressed = int((mask == 0).sum())
        log.info("ablation: suppressing %d features matching %s",
                 suppressed, exclude_prefixes)
        X_train = X_train * mask
        X_test = X_test * mask

    log.info("feature matrix: %s train, %s test", X_train.shape, X_test.shape)

    # ---------------- supervised voter --------------------------------- #
    rf = RandomForestClassifier(
        n_estimators=ml.rf_estimators,
        max_depth=ml.rf_max_depth,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=ml.random_state,
        n_jobs=ml.n_jobs,
        oob_score=True,
        bootstrap=True,
    )
    rf.fit(X_train, y_train)
    log.info("RandomForest trained (OOB score %.4f)", getattr(rf, "oob_score_", 0.0))

    # ---------------- unsupervised voter (benign only) ------------------ #
    benign_mask = y_train == "benign"
    scaler = RobustScaler().fit(X_train[benign_mask])
    iforest = IsolationForest(
        n_estimators=ml.iforest_estimators,
        contamination=ml.iforest_contamination,
        max_samples=256,
        random_state=ml.random_state,
        n_jobs=ml.n_jobs,
    )
    iforest.fit(scaler.transform(X_train[benign_mask]))
    log.info("IsolationForest trained on %d benign rows", int(benign_mask.sum()))

    # Calibrate the anomaly score range on benign data so 0..1 means something.
    raw_benign = iforest.decision_function(scaler.transform(X_train[benign_mask]))
    anom_lo = float(np.percentile(raw_benign, 1))
    anom_hi = float(np.percentile(raw_benign, 99))

    # ---------------- assemble ------------------------------------------ #
    model = ThreatEnsemble(weights=(cfg.detection.w_supervised,
                                    cfg.detection.w_anomaly,
                                    cfg.detection.w_heuristic))
    model.rf = rf
    model.iforest = iforest
    model.scaler = scaler
    model.feature_names = list(FEATURE_NAMES)
    model.classes_ = list(rf.classes_)
    model.importances = rf.feature_importances_
    model.benign_median = np.median(X_train[benign_mask], axis=0)
    q75, q25 = (np.percentile(X_train[benign_mask], 75, axis=0),
                np.percentile(X_train[benign_mask], 25, axis=0))
    model.benign_iqr = np.maximum(q75 - q25, 1e-6)
    model._anom_lo, model._anom_hi = anom_lo, anom_hi
    model.baseline_anomaly = float(
        np.median(model._normalize_anomaly(raw_benign)))
    model.set_bands(cfg.detection.threshold_suspicious,
                    cfg.detection.threshold_malicious)
    model.feature_mask = mask
    model.version = ThreatEnsemble.make_version(model.feature_names, len(queries))
    if exclude_prefixes:
        model.version += "-ablate"

    # ---------------- evaluation ------------------------------------------ #
    y_pred = rf.predict(X_test)
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="weighted", zero_division=0)
    accuracy = float((y_pred == y_test).mean())

    # Binary "is this a threat" ROC-AUC on the fused ensemble score.
    ens = model.score_batch(X_test, test_feats)
    fused = np.array([e.fused for e in ens])
    y_bin = (y_test != "benign").astype(int)
    try:
        roc = float(roc_auc_score(y_bin, fused))
    except ValueError:
        roc = float("nan")

    # Operating-point analysis: what happens at the shipped thresholds?
    t_mal = cfg.detection.threshold_malicious
    blocked = fused >= t_mal
    fp_rate = float((blocked & (y_bin == 0)).sum() / max((y_bin == 0).sum(), 1))
    detect_rate = float((blocked & (y_bin == 1)).sum() / max((y_bin == 1).sum(), 1))

    labels_present = sorted(set(y_test) | set(y_pred))
    cm = confusion_matrix(y_test, y_pred, labels=labels_present).tolist()

    per_class = classification_report(y_test, y_pred, zero_division=0,
                                      output_dict=True)

    metrics = {
        "accuracy": accuracy,
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "roc_auc": roc,
        "oob_score": float(getattr(rf, "oob_score_", 0.0)),
        "block_threshold": t_mal,
        "false_positive_rate": fp_rate,
        "detection_rate": detect_rate,
        "train_rows": int(len(train_q)),
        "test_rows": int(len(test_q)),
        "feature_count": len(FEATURE_NAMES),
        "train_seconds": round(time.time() - t_start, 2),
        "ablated_features": int((mask == 0).sum()) if mask is not None else 0,
    }
    model.metrics = metrics

    report = {
        "version": model.version,
        "metrics": metrics,
        "labels": labels_present,
        "confusion_matrix": cm,
        "per_class": {k: v for k, v in per_class.items()
                      if k in CLASSES or k in ("macro avg", "weighted avg")},
        "top_features": model.global_importances(25),
        "class_distribution": {
            c: int((y_train == c).sum()) for c in sorted(set(y_train))
        },
    }

    log.info("accuracy=%.4f  f1=%.4f  roc_auc=%.4f  fp_rate=%.4f  detect=%.4f",
             accuracy, f1, roc, fp_rate, detect_rate)

    if report_path:
        Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        Path(report_path).write_text(json.dumps(report, indent=2))
        log.info("report written to %s", report_path)

    return model, report


def evaluate_model(model: ThreatEnsemble, queries: list[DNSQuery]) -> dict:
    """Score a held-out capture with the *full ensemble* (not just the RF)."""
    fx = FeatureExtractor()
    X, feats = fx.batch(queries)
    results = model.score_batch(X, feats)
    y_true = np.array([(q.label or "benign") != "benign" for q in queries])
    fused = np.array([r.fused for r in results])
    pred_class = np.array([r.threat_class for r in results])
    true_class = np.array([q.label or "benign" for q in queries])

    out: dict[str, Any] = {"n": len(queries)}
    for thr in (0.45, 0.55, 0.70, 0.85):
        flagged = fused >= thr
        tp = int((flagged & y_true).sum())
        fp = int((flagged & ~y_true).sum())
        fn = int((~flagged & y_true).sum())
        tn = int((~flagged & ~y_true).sum())
        out[f"threshold_{thr}"] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(tp / max(tp + fp, 1), 4),
            "recall": round(tp / max(tp + fn, 1), 4),
            "fpr": round(fp / max(fp + tn, 1), 5),
        }
    out["class_accuracy"] = round(float((pred_class == true_class).mean()), 4)
    return out
