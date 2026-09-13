"""
Policy layer: turning a number into a decision you can defend.

A raw score is not a policy. Between "the model says 0.72" and "the user's
browser gets NXDOMAIN" sits a set of operational rules that stop a detector
from becoming an outage:

  * **Allowlist first.** Never block what the business has declared critical.
  * **Intel escalation.** A curated indicator outranks a model guess.
  * **Debounce.** Require N malicious verdicts in a window before enforcing,
    so a single unlucky query cannot take down a domain.
  * **Fail-open.** If the engine errors, resolve normally. A security control
    that breaks DNS is worse than the threat it was bought to stop.
  * **Monitor mode.** `CHRONODNS_ENFORCE=false` scores and logs everything but
    blocks nothing — how every sane rollout starts.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from ..config import DetectionConfig
from ..types import ThreatClass, Verdict


@dataclass
class Debouncer:
    """Counts recent malicious verdicts per (source_ip, zone)."""

    hits: int = 2
    window_s: float = 60.0
    _events: dict[tuple[str, str], deque] = field(
        default_factory=lambda: defaultdict(deque))

    def register(self, source_ip: str, zone: str, ts: float) -> int:
        key = (source_ip, zone)
        dq = self._events[key]
        dq.append(ts)
        while dq and ts - dq[0] > self.window_s:
            dq.popleft()
        if len(self._events) > 20_000:                 # bounded memory
            for k in list(self._events)[:5_000]:
                if not self._events[k]:
                    self._events.pop(k, None)
        return len(dq)

    def should_enforce(self, source_ip: str, zone: str, ts: float) -> tuple[bool, int]:
        count = self.register(source_ip, zone, ts)
        return count >= self.hits, count

    def reset(self) -> None:
        self._events.clear()


@dataclass
class RateLimiter:
    """Sliding-window QPS guard per source IP — catches volumetric exfil."""

    qps_alarm: float = 40.0
    window_s: float = 10.0
    _hits: dict[str, deque] = field(default_factory=lambda: defaultdict(deque))

    def observe(self, source_ip: str, ts: float) -> float:
        dq = self._hits[source_ip]
        dq.append(ts)
        while dq and ts - dq[0] > self.window_s:
            dq.popleft()
        return len(dq) / self.window_s

    def is_flooding(self, source_ip: str, ts: float) -> tuple[bool, float]:
        qps = self.observe(source_ip, ts)
        return qps > self.qps_alarm, qps


class PolicyEngine:
    """Maps (score, intel, context) -> Verdict."""

    def __init__(self, cfg: DetectionConfig) -> None:
        self.cfg = cfg
        self.debouncer = Debouncer(cfg.debounce_hits, cfg.debounce_window_s)
        self.limiter = RateLimiter(cfg.qps_alarm)
        self.stats = {
            "allow": 0, "monitor": 0, "suspicious": 0, "blocked": 0,
            "allowlisted": 0, "intel_blocked": 0, "debounce_held": 0,
        }

    # ------------------------------------------------------------------ #
    def decide(self, score: float, threat_class: str, source_ip: str, zone: str,
               ts: float, intel: dict | None = None, allowlisted: bool = False,
               ) -> tuple[Verdict, list[str]]:
        notes: list[str] = []

        # 1. Allowlist always wins.
        if allowlisted:
            self.stats["allowlisted"] += 1
            self.stats["allow"] += 1
            return Verdict.ALLOW, ["allowlisted: business-critical domain"]

        # 2. Curated intelligence outranks the model.
        if intel and int(intel.get("severity", 0)) >= 8:
            self.stats["intel_blocked"] += 1
            self.stats["blocked"] += 1
            return Verdict.BLOCK, [
                f"threat-intel {intel['ioc_type']} match "
                f"'{intel['indicator']}' ({intel['category']}, sev {intel['severity']})"
            ]
        if intel:
            notes.append(f"intel match '{intel['indicator']}' sev {intel['severity']}")

        # 3. Volumetric guard.
        flooding, qps = self.limiter.is_flooding(source_ip, ts)
        if flooding:
            notes.append(f"host flooding at {qps:.0f} q/s")

        # 4. Score bands.
        if score < self.cfg.threshold_suspicious:
            self.stats["allow"] += 1
            return Verdict.ALLOW, notes

        if score < self.cfg.threshold_malicious:
            self.stats["monitor"] += 1
            notes.append(f"score {score:.3f} in monitor band")
            return Verdict.MONITOR, notes

        # 5. Malicious band -> debounce before enforcing.
        #
        # The debounce key matters more than it looks. Keying on (host, zone)
        # is right for tunnelling and C2, where one zone is hit repeatedly.
        # It is exactly wrong for DGA: every query is a brand-new zone, so a
        # per-zone counter never reaches two and the implant is never blocked
        # however loud it gets. DGA therefore debounces on (host, class).
        key = "dga" if threat_class == "dga" else zone
        enforce_ok, count = self.debouncer.should_enforce(source_ip, key, ts)
        if not self.cfg.enforce:
            self.stats["suspicious"] += 1
            notes.append("monitor-only mode: would have blocked")
            return Verdict.SUSPICIOUS, notes
        if not enforce_ok:
            self.stats["debounce_held"] += 1
            self.stats["suspicious"] += 1
            notes.append(
                f"score {score:.3f} malicious but debounced "
                f"({count}/{self.cfg.debounce_hits} in {self.cfg.debounce_window_s:.0f}s)"
            )
            return Verdict.SUSPICIOUS, notes

        self.stats["blocked"] += 1
        notes.append(f"score {score:.3f} >= block threshold {self.cfg.threshold_malicious}")
        return Verdict.BLOCK, notes

    # ------------------------------------------------------------------ #
    def classify(self, threat_class: str) -> ThreatClass:
        try:
            return ThreatClass(threat_class)
        except ValueError:
            return ThreatClass.UNKNOWN

    def reset(self) -> None:
        self.debouncer.reset()
        for k in self.stats:
            self.stats[k] = 0
