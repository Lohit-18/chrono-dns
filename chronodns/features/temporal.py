"""
Temporal / kinetic features — the direct analogue of CAN-bus inter-arrival
time analysis, applied to DNS.

Two rolling state machines are maintained:

  1. per **source IP**      → volumetric exfiltration, NXDOMAIN storms, QPS
  2. per (source IP, zone)  → beaconing periodicity, subdomain novelty

The key insight: a human browsing produces *bursty, irregular* DNS traffic
(high coefficient of variation). Malware calling home produces a metronome
(σ/μ ≈ 0). Tunnelling produces a *sustained torrent of unique subdomains under
one zone* — a signature no single query can reveal.
"""

from __future__ import annotations

import math
import statistics
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field


# --------------------------------------------------------------------------- #
# Rolling windows
# --------------------------------------------------------------------------- #
@dataclass
class ZoneWindow:
    """Rolling state for one (source_ip, registrable domain) pair."""

    first_seen: float = 0.0
    last_seen: float = 0.0
    timestamps: deque[float] = field(default_factory=lambda: deque(maxlen=256))
    iats: deque[float] = field(default_factory=lambda: deque(maxlen=256))
    subdomains: deque[str] = field(default_factory=lambda: deque(maxlen=512))
    unique_subs: set[str] = field(default_factory=set)
    qtypes: Counter = field(default_factory=Counter)
    uploaded_bytes: int = 0
    total: int = 0
    nxdomain: int = 0


@dataclass
class HostWindow:
    """Rolling state for one source IP across all zones."""

    first_seen: float = 0.0
    last_seen: float = 0.0
    timestamps: deque[float] = field(default_factory=lambda: deque(maxlen=1024))
    zones: Counter = field(default_factory=Counter)
    nxdomain: deque[float] = field(default_factory=lambda: deque(maxlen=256))
    blocked: int = 0
    total: int = 0


# --------------------------------------------------------------------------- #
# Statistics helpers
# --------------------------------------------------------------------------- #
def _cv(values: list[float]) -> float:
    """Coefficient of variation σ/μ. ~0 ⇒ perfect metronome ⇒ beacon."""
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    if mean <= 0:
        return 0.0
    return statistics.pstdev(values) / mean


def burstiness(values: list[float]) -> float:
    """Goh & Barabási burstiness B = (σ-μ)/(σ+μ) ∈ [-1, 1].

    -1 = perfectly periodic (beacon)   0 = Poisson   +1 = extremely bursty (human)
    """
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    sd = statistics.pstdev(values)
    denom = sd + mean
    return (sd - mean) / denom if denom else 0.0


def fano_factor(timestamps: list[float], bin_s: float = 10.0) -> float:
    """Variance-to-mean ratio of counts per bin. 1.0 ⇒ Poisson."""
    if len(timestamps) < 4:
        return 0.0
    span = timestamps[-1] - timestamps[0]
    if span <= 0:
        return 0.0
    nbins = max(int(span / bin_s), 2)
    bins = [0] * nbins
    for t in timestamps:
        idx = min(int((t - timestamps[0]) / span * nbins), nbins - 1)
        bins[idx] += 1
    mean = statistics.fmean(bins)
    return (statistics.pvariance(bins) / mean) if mean > 0 else 0.0


def periodicity_score(iats: list[float]) -> tuple[float, float]:
    """Detect a dominant period via a lightweight autocorrelation sweep.

    Returns (strength 0..1, estimated period in seconds). Deliberately
    implemented without SciPy/FFT so the module stays dependency-light and
    fast enough to run inline on every packet.
    """
    n = len(iats)
    if n < 6:
        return 0.0, 0.0
    mean = statistics.fmean(iats)
    if mean <= 0:
        return 0.0, 0.0
    centred = [x - mean for x in iats]
    denom = sum(x * x for x in centred)
    if denom <= 0:
        # Zero variance = literally perfect periodicity.
        return 1.0, mean
    best_r, best_lag = 0.0, 0
    for lag in range(1, min(n // 2, 16) + 1):
        num = sum(centred[i] * centred[i + lag] for i in range(n - lag))
        r = num / denom
        if r > best_r:
            best_r, best_lag = r, lag
    # Fold in the coefficient of variation: low CV alone is strong evidence.
    cv = _cv(iats)
    regularity = max(0.0, 1.0 - min(cv / 0.5, 1.0))
    strength = max(best_r, regularity)
    return min(max(strength, 0.0), 1.0), mean * max(best_lag, 1)


def time_entropy(timestamps: list[float], bin_s: float = 5.0) -> float:
    """Shannon entropy of the arrival-time histogram. Low ⇒ clustered."""
    if len(timestamps) < 4:
        return 0.0
    span = timestamps[-1] - timestamps[0]
    if span <= 0:
        return 0.0
    nbins = max(int(span / bin_s), 2)
    counts = Counter(
        min(int((t - timestamps[0]) / span * nbins), nbins - 1) for t in timestamps
    )
    total = sum(counts.values())
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# --------------------------------------------------------------------------- #
# The stateful tracker
# --------------------------------------------------------------------------- #
class TemporalTracker:
    """Maintains rolling windows and emits ~28 temporal features per query."""

    def __init__(self, window_size: int = 64, max_hosts: int = 4096,
                 max_zones: int = 32_768) -> None:
        self.window_size = window_size
        self.max_hosts = max_hosts
        self.max_zones = max_zones
        self.hosts: dict[str, HostWindow] = defaultdict(HostWindow)
        self.zones: dict[tuple[str, str], ZoneWindow] = defaultdict(ZoneWindow)

    # -- housekeeping -------------------------------------------------------
    def _evict(self) -> None:
        if len(self.zones) > self.max_zones:
            oldest = sorted(self.zones.items(), key=lambda kv: kv[1].last_seen)
            for key, _ in oldest[: len(self.zones) // 4]:
                self.zones.pop(key, None)
        if len(self.hosts) > self.max_hosts:
            oldest_h = sorted(self.hosts.items(), key=lambda kv: kv[1].last_seen)
            for key, _ in oldest_h[: len(self.hosts) // 4]:
                self.hosts.pop(key, None)

    def reset(self) -> None:
        self.hosts.clear()
        self.zones.clear()

    # -- main entry point ---------------------------------------------------
    def observe(self, source_ip: str, registrable: str, subdomain: str,
                qtype: str, ts: float | None = None, qname_len: int = 0,
                nxdomain: bool = False) -> dict[str, float]:
        ts = ts if ts is not None else time.time()
        zkey = (source_ip, registrable)
        zone = self.zones[zkey]
        host = self.hosts[source_ip]

        # ---- update zone window ------------------------------------------
        if zone.first_seen == 0.0:
            zone.first_seen = ts
        prev_z = zone.last_seen
        if prev_z:
            zone.iats.append(max(ts - prev_z, 0.0))
        zone.last_seen = ts
        zone.timestamps.append(ts)
        is_new_sub = subdomain not in zone.unique_subs
        if subdomain:
            zone.subdomains.append(subdomain)
            zone.unique_subs.add(subdomain)
        zone.qtypes[qtype] += 1
        zone.uploaded_bytes += len(subdomain)
        zone.total += 1
        if nxdomain:
            zone.nxdomain += 1

        # ---- update host window ------------------------------------------
        if host.first_seen == 0.0:
            host.first_seen = ts
        host.last_seen = ts
        host.timestamps.append(ts)
        host.zones[registrable] += 1
        host.total += 1
        if nxdomain:
            host.nxdomain.append(ts)

        self._evict()
        return self._compute(zone, host, ts, is_new_sub, qname_len)

    # -- feature computation ------------------------------------------------
    def _compute(self, zone: ZoneWindow, host: HostWindow, ts: float,
                 is_new_sub: bool, qname_len: int) -> dict[str, float]:
        f: dict[str, float] = {}
        iats = list(zone.iats)[-self.window_size:]
        zts = list(zone.timestamps)[-self.window_size:]
        hts = list(host.timestamps)

        # --- Inter-arrival time statistics (9) ----------------------------
        if iats:
            f["iat_mean"] = float(statistics.fmean(iats))
            f["iat_std"] = float(statistics.pstdev(iats)) if len(iats) > 1 else 0.0
            f["iat_min"] = float(min(iats))
            f["iat_max"] = float(max(iats))
            f["iat_median"] = float(statistics.median(iats))
            f["iat_cv"] = _cv(iats)
            f["iat_range"] = float(max(iats) - min(iats))
            sorted_i = sorted(iats)
            q1 = sorted_i[len(sorted_i) // 4]
            q3 = sorted_i[(3 * len(sorted_i)) // 4]
            f["iat_iqr"] = float(q3 - q1)
            f["iat_last"] = float(iats[-1])
        else:
            for k in ("iat_mean", "iat_std", "iat_min", "iat_max", "iat_median",
                      "iat_cv", "iat_range", "iat_iqr", "iat_last"):
                f[k] = 0.0

        # --- Beaconing / periodicity (5) ----------------------------------
        strength, period = periodicity_score(iats)
        f["beacon_strength"] = strength if len(iats) >= 5 else 0.0
        f["beacon_period_s"] = period if len(iats) >= 5 else 0.0
        f["burstiness"] = burstiness(iats)
        f["fano_factor"] = fano_factor(zts)
        f["time_entropy"] = time_entropy(zts)

        # --- Zone velocity & novelty (8) — the tunnelling signature -------
        # Rates need a real observation window. On the very first query of a
        # zone the span is ~0, and dividing by it produces absurd values
        # (52 MB/s from a single 52-byte label) that poison both the model and
        # the analyst's trust. Below the floor, rates are reported as zero.
        raw_span = zone.last_seen - zone.first_seen
        has_window = zone.total >= 2 and raw_span >= 0.5
        span = max(raw_span, 0.5) if has_window else 0.0
        f["zone_query_count"] = float(zone.total)
        f["zone_unique_subs"] = float(len(zone.unique_subs))
        f["zone_sub_novelty"] = (
            len(zone.unique_subs) / zone.total if zone.total else 0.0
        )
        f["zone_is_new_sub"] = 1.0 if is_new_sub else 0.0
        f["zone_qps"] = zone.total / span if span > 0 else 0.0
        f["zone_uploaded_bytes"] = float(zone.uploaded_bytes)
        f["zone_upload_rate"] = zone.uploaded_bytes / span if span > 0 else 0.0
        f["zone_qtype_diversity"] = float(len(zone.qtypes))

        # --- Host-level volumetrics (6) -----------------------------------
        raw_hspan = host.last_seen - host.first_seen
        hspan = max(raw_hspan, 0.5) if (host.total >= 2 and raw_hspan >= 0.5) else 0.0
        f["host_query_count"] = float(host.total)
        f["host_unique_zones"] = float(len(host.zones))
        f["host_qps"] = host.total / hspan if hspan > 0 else 0.0
        f["host_qps_10s"] = float(sum(1 for t in hts if ts - t <= 10.0)) / 10.0
        f["host_qps_60s"] = float(sum(1 for t in hts if ts - t <= 60.0)) / 60.0
        f["host_nxdomain_60s"] = float(sum(1 for t in host.nxdomain if ts - t <= 60.0))

        # --- Session shape (3) ---------------------------------------------
        f["zone_age_s"] = float(ts - zone.first_seen)
        f["zone_duty_cycle"] = (
            (zone.total * f["iat_mean"]) / span if span > 0 and f["iat_mean"] else 0.0
        )
        f["zone_bytes_per_query"] = (
            zone.uploaded_bytes / zone.total if zone.total else 0.0
        )

        return f


# Canonical zero-vector so callers can build feature rows without state.
TEMPORAL_KEYS = [
    "iat_mean", "iat_std", "iat_min", "iat_max", "iat_median", "iat_cv",
    "iat_range", "iat_iqr", "iat_last",
    "beacon_strength", "beacon_period_s", "burstiness", "fano_factor", "time_entropy",
    "zone_query_count", "zone_unique_subs", "zone_sub_novelty", "zone_is_new_sub",
    "zone_qps", "zone_uploaded_bytes", "zone_upload_rate", "zone_qtype_diversity",
    "host_query_count", "host_unique_zones", "host_qps", "host_qps_10s",
    "host_qps_60s", "host_nxdomain_60s",
    "zone_age_s", "zone_duty_cycle", "zone_bytes_per_query",
]
