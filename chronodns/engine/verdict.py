"""
The Chrono Engine — the single object that turns a DNSQuery into a Detection.

This is the seam the whole project is built around: the gateway, the CLI
replay tool, the benchmark harness and the test suite all call the same
`analyse()`. There is exactly one code path that decides whether traffic is
malicious, so what you measure offline is literally what runs inline.
"""

from __future__ import annotations

import time
from typing import Any

from ..config import Config, get_config
from ..features import FeatureExtractor
from ..logging_utils import get_logger
from ..ml import ThreatEnsemble
from ..storage import Repository
from ..types import Detection, DNSQuery, ThreatClass, Verdict
from .policy import PolicyEngine

log = get_logger("engine")


class ChronoEngine:
    """Feature extraction -> ensemble scoring -> policy -> persistence."""

    def __init__(self, cfg: Config | None = None, repo: Repository | None = None,
                 model: ThreatEnsemble | None = None) -> None:
        self.cfg = cfg or get_config()
        self.repo = repo
        self.extractor = FeatureExtractor(window_size=self.cfg.detection.window_size)
        self.model = model or ThreatEnsemble(weights=(
            self.cfg.detection.w_supervised,
            self.cfg.detection.w_anomaly,
            self.cfg.detection.w_heuristic,
        ))
        self.policy = PolicyEngine(self.cfg.detection)
        self.latencies: list[float] = []
        self.counters = {"analysed": 0, "blocked": 0, "errors": 0}

    # ------------------------------------------------------------------ #
    def load_model(self) -> bool:
        ok = self.model.load(self.cfg.ml.model_dir)
        if ok:
            self.model.set_bands(self.cfg.detection.threshold_suspicious,
                                 self.cfg.detection.threshold_malicious)
            self._warmup()
        return ok

    def _warmup(self) -> None:
        """Run one throwaway prediction.

        scikit-learn lazily builds internal caches on the first call, so the
        first real query would otherwise show a ~80 ms latency spike that has
        nothing to do with steady-state performance. Paying it at startup
        keeps the measured p99 honest.
        """
        import numpy as np

        try:
            dummy = np.zeros((1, self.extractor.count), dtype=np.float32)
            self.model._verify_fast_path(dummy[0])
            self.model.score_vector(dummy[0], {})
            self.model.cascade_skips = self.model.cascade_calls = 0
        except Exception:                                  # noqa: BLE001
            pass

    @property
    def model_ready(self) -> bool:
        return self.model.is_trained

    # ------------------------------------------------------------------ #
    async def analyse(self, query: DNSQuery, nxdomain: bool = False,
                      persist: bool = True) -> Detection:
        """Full pipeline for one query. Never raises — fail-open by design."""
        t0 = time.perf_counter()
        detection = Detection(query=query)
        try:
            features, vector = self.extractor.extract_vector(query, nxdomain=nxdomain)
            detection.features = features

            scores = self.model.score_vector(vector, features)
            detection.supervised_score = scores.supervised
            detection.anomaly_score = scores.anomaly
            detection.heuristic_score = scores.heuristic
            detection.score = scores.fused
            detection.top_features = scores.top_features

            allowlisted = self.repo.is_allowlisted(query.qname) if self.repo else False
            intel = None
            if self.repo and not allowlisted:
                intel = self.repo.intel_lookup_sync(
                    query.qname, query.registrable, query.tld)
            if intel:
                detection.intel_hit = f"{intel['indicator']}:{intel['category']}"

            verdict, notes = self.policy.decide(
                score=scores.fused, threat_class=scores.threat_class,
                source_ip=query.source_ip, zone=query.registrable,
                ts=query.timestamp, intel=intel, allowlisted=allowlisted,
            )
            detection.verdict = verdict
            detection.reasons = notes + scores.reasons

            if allowlisted:
                detection.threat_class = ThreatClass.BENIGN
            elif intel and verdict is Verdict.BLOCK and scores.fused < 0.35:
                detection.threat_class = self._intel_to_class(intel["category"])
            else:
                detection.threat_class = self.policy.classify(scores.threat_class)

            self.counters["analysed"] += 1
            if verdict.is_blocked:
                self.counters["blocked"] += 1

        except Exception as exc:                          # noqa: BLE001
            self.counters["errors"] += 1
            log.exception("analysis failed for %s: %s", query.qname, exc)
            detection.verdict = (Verdict.ALLOW if self.cfg.detection.fail_open
                                 else Verdict.ERROR)
            detection.reasons = [f"engine error (fail-{'open' if self.cfg.detection.fail_open else 'closed'}): {exc}"]

        detection.latency_ms = (time.perf_counter() - t0) * 1000.0
        self.latencies.append(detection.latency_ms)
        if len(self.latencies) > 10_000:
            self.latencies = self.latencies[-5_000:]

        if persist and self.repo:
            await self.repo.record(detection)
            if detection.verdict in (Verdict.BLOCK, Verdict.SUSPICIOUS):
                await self.repo.raise_alert(
                    query.source_ip, query.registrable,
                    detection.threat_class.value, detection.score,
                    len(query.subdomain), "; ".join(detection.reasons[:3]),
                )
        return detection

    @staticmethod
    def _intel_to_class(category: str) -> ThreatClass:
        return {
            "tunnel": ThreatClass.TUNNELING,
            "c2": ThreatClass.C2_BEACON,
            "dga": ThreatClass.DGA,
        }.get(category, ThreatClass.UNKNOWN)

    # ------------------------------------------------------------------ #
    async def analyse_many(self, queries: list[DNSQuery], persist: bool = True,
                           progress: Any = None) -> list[Detection]:
        """Replay a capture through the *exact* inline code path."""
        out: list[Detection] = []
        for i, q in enumerate(queries):
            out.append(await self.analyse(q, persist=persist))
            if progress and i % 250 == 0:
                progress(i, len(queries))
        return out

    def analyse_batch_fast(self, queries: list[DNSQuery]) -> list[Detection]:
        """Vectorised path for benchmarking — same maths, no per-row model call.

        Used by `chronodns bench` to measure raw pipeline throughput without
        the database or the event loop in the way.
        """
        matrix, feats = self.extractor.batch(queries, reset=True)
        scored = self.model.score_batch(matrix, feats)
        out: list[Detection] = []
        for q, f, s in zip(queries, feats, scored, strict=False):
            d = Detection(query=q, features=f)
            d.supervised_score, d.anomaly_score = s.supervised, s.anomaly
            d.heuristic_score, d.score = s.heuristic, s.fused
            d.top_features = s.top_features
            allow = self.repo.is_allowlisted(q.qname) if self.repo else False
            v, notes = self.policy.decide(
                s.fused, s.threat_class, q.source_ip, q.registrable,
                q.timestamp, None, allow)
            d.verdict = v
            d.reasons = notes + s.reasons
            d.threat_class = (ThreatClass.BENIGN if allow
                              else self.policy.classify(s.threat_class))
            out.append(d)
        return out

    # ------------------------------------------------------------------ #
    def snapshot(self) -> dict[str, Any]:
        lat = sorted(self.latencies) or [0.0]
        def pct(p: float) -> float:
            return round(lat[min(int(len(lat) * p), len(lat) - 1)], 3)
        return {
            **self.counters,
            "policy": dict(self.policy.stats),
            "p50_ms": pct(0.50), "p95_ms": pct(0.95), "p99_ms": pct(0.99),
            "model": self.model.version,
            "features": self.extractor.count,
            "anomaly_evaluated": self.model.cascade_calls,
            "anomaly_skipped": self.model.cascade_skips,
            "cascade_skip_rate": round(
                self.model.cascade_skips
                / max(self.model.cascade_skips + self.model.cascade_calls, 1), 4),
            **self.extractor.stats,
        }
