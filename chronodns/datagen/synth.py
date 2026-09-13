"""
Dataset orchestrator.

Builds a *chronologically interleaved, multi-host* DNS capture: benign users,
tunnelling sessions, DGA implants and C2 beacons all sharing the wire, exactly
as they would on a real network. Interleaving matters — the temporal features
are only meaningful if the events arrive in true time order with realistic
neighbours.

Output: a list of `DNSQuery` with ground-truth `label` and `family`, plus a
CSV/JSONL writer so the dataset is reproducible and inspectable.
"""

from __future__ import annotations

import csv
import random
from dataclasses import dataclass
from pathlib import Path

from ..types import DNSQuery
from .benign import BenignGenerator
from .dga import DGAGenerator
from .tunnel import BeaconGenerator, TunnelGenerator


@dataclass
class ScenarioMix:
    """Proportions of the synthetic estate. Defaults model a 'realistic bad day'."""

    benign_hosts: int = 24
    benign_per_host: int = 260
    telemetry_hosts: int = 6
    telemetry_per_host: int = 30

    tunnel_hosts: int = 3
    tunnel_per_host: int = 420
    slow_exfil_hosts: int = 2
    slow_exfil_per_host: int = 90

    dga_hosts: int = 4
    dga_per_host: int = 160

    beacon_hosts: int = 3
    beacon_per_host: int = 45

    duration_s: float = 3600.0


# A fixed epoch anchor so a seeded dataset is *bit-for-bit* reproducible.
#
# Anchoring to time.time() looks harmless but is not: a float64 holding ~1.8e9
# seconds has only ~7 fractional digits left, so accumulating thousands of
# sub-second gaps rounds differently depending on the exact wall-clock start.
# That silently reorders near-simultaneous events from different hosts, which
# changes the temporal feature windows, which changes the trained model. Runs
# then differ by a few tenths of a percent for no visible reason.
#
# 2023-11-14T22:13:20Z, chosen only because it is a round number.
FIXED_EPOCH = 1_700_000_000.0


def _ip(rng: random.Random, subnet: str = "10.10") -> str:
    return f"{subnet}.{rng.randrange(1, 60)}.{rng.randrange(2, 254)}"


class DatasetBuilder:
    def __init__(self, seed: int = 1337) -> None:
        self.seed = seed
        self.rng = random.Random(seed)
        self.benign = BenignGenerator(seed)
        self.tunnel = TunnelGenerator(seed + 1)
        self.dga = DGAGenerator(seed + 2)
        self.beacon = BeaconGenerator(seed + 3)

    # ------------------------------------------------------------------ #
    def build(self, mix: ScenarioMix | None = None, start_ts: float | None = None
              ) -> list[DNSQuery]:
        mix = mix or ScenarioMix()
        t0 = start_ts if start_ts is not None else FIXED_EPOCH
        events: list[tuple[float, str, str, str, str, str]] = []
        # tuple = (ts, fqdn, qtype, source_ip, label, family)

        # --- benign users -------------------------------------------------
        for _ in range(mix.benign_hosts):
            ip = _ip(self.rng)
            offset = self.rng.uniform(0, mix.duration_s * 0.25)
            for ts, fqdn, qtype, _tool in self.benign.session(
                    mix.benign_per_host, t0 + offset):
                events.append((ts, fqdn, qtype, ip, "benign", "user"))

        # --- legitimate pollers (benign beacons: the hard negative) -------
        for _ in range(mix.telemetry_hosts):
            ip = _ip(self.rng)
            for ts, fqdn, qtype, _tool in self.benign.telemetry_session(
                    mix.telemetry_per_host, t0 + self.rng.uniform(0, 300),
                    interval=self.rng.choice([60.0, 120.0, 300.0])):
                events.append((ts, fqdn, qtype, ip, "benign", "telemetry"))

        # --- DNS tunnelling ----------------------------------------------
        tunnel_profiles = ["iodine", "dnscat2", "dns2tcp"]
        for i in range(mix.tunnel_hosts):
            ip = _ip(self.rng, "10.20")
            profile = tunnel_profiles[i % len(tunnel_profiles)]
            begin = t0 + self.rng.uniform(0, mix.duration_s * 0.6)
            for ts, fqdn, qtype, tool in self.tunnel.session(
                    profile, mix.tunnel_per_host, begin):
                events.append((ts, fqdn, qtype, ip, "tunneling", tool))
            # Tunnel hosts also browse normally — cover traffic.
            for ts, fqdn, qtype, _t in self.benign.session(60, begin):
                events.append((ts, fqdn, qtype, ip, "benign", "user"))

        # --- low-and-slow exfiltration ------------------------------------
        for _ in range(mix.slow_exfil_hosts):
            ip = _ip(self.rng, "10.20")
            begin = t0 + self.rng.uniform(0, mix.duration_s * 0.4)
            for ts, fqdn, qtype, tool in self.tunnel.session(
                    "slowexfil", mix.slow_exfil_per_host, begin):
                events.append((ts, fqdn, qtype, ip, "tunneling", tool))
            for ts, fqdn, qtype, _t in self.benign.session(120, begin):
                events.append((ts, fqdn, qtype, ip, "benign", "user"))

        # --- DGA implants --------------------------------------------------
        for _ in range(mix.dga_hosts):
            ip = _ip(self.rng, "10.30")
            begin = t0 + self.rng.uniform(0, mix.duration_s * 0.7)
            t = begin
            for _ in range(mix.dga_per_host):
                fqdn, family = self.dga.generate()
                qtype = self.rng.choices(["A", "AAAA", "TXT"], weights=[80, 15, 5], k=1)[0]
                events.append((t, fqdn, qtype, ip, "dga", family))
                t += abs(self.rng.gauss(0.9, 0.5)) + 0.05
            for ts, fqdn, qtype, _t in self.benign.session(80, begin):
                events.append((ts, fqdn, qtype, ip, "benign", "user"))

        # --- C2 beacons -----------------------------------------------------
        for i in range(mix.beacon_hosts):
            ip = _ip(self.rng, "10.40")
            begin = t0 + self.rng.uniform(0, mix.duration_s * 0.3)
            interval = [60.0, 30.0, 300.0][i % 3]
            jitter = [0.02, 0.08, 0.05][i % 3]
            for ts, fqdn, qtype, tool in self.beacon.session(
                    "c2.example", mix.beacon_per_host, begin,
                    interval=interval, jitter_pct=jitter):
                events.append((ts, fqdn, qtype, ip, "c2_beacon", tool))
            for ts, fqdn, qtype, _t in self.benign.session(100, begin):
                events.append((ts, fqdn, qtype, ip, "benign", "user"))

        # --- interleave by true arrival time --------------------------------
        events.sort(key=lambda e: e[0])

        return [
            DNSQuery(
                qname=fqdn, qtype=qtype, source_ip=ip, timestamp=ts,
                transport="tcp" if len(fqdn) > 200 else "udp",
                payload_size=len(fqdn) + 17,
                label=label, family=family,
            )
            for ts, fqdn, qtype, ip, label, family in events
        ]

    # ------------------------------------------------------------------ #
    def build_evasive(self, count_per_class: int = 300,
                      start_ts: float | None = None) -> list[DNSQuery]:
        """**Hard mode.** An adversary who has read this repository.

        Synthetic benchmarks flatter detectors: default attack traffic is
        loud, long and obviously encoded, so every model scores ~1.0 and the
        number means nothing. This builder generates attacks that deliberately
        target each of our detection axes:

          * tunnelling  -> short labels well under the RFC cap, A records only,
                           a benign-looking zone, and a slow send rate, so the
                           length/qtype/volume features go quiet
          * DGA         -> dictionary-word families only, so entropy and the
                           vowel ratio look completely human
          * beaconing   -> 35% jitter, so the coefficient of variation leaves
                           the "metronome" band entirely

        Reporting detection rate on *this* set is the honest number. Use
        `chronodns evade` to see it.
        """
        t0 = start_ts if start_ts is not None else FIXED_EPOCH
        events: list[tuple[float, str, str, str, str, str]] = []
        rng = self.rng

        # --- evasive tunnelling ------------------------------------------
        for _host in range(2):
            ip = _ip(rng, "10.60")
            t = t0 + rng.uniform(0, 600)
            for _ in range(count_per_class // 2):
                # Short, mixed-case-free, dash-separated chunks under a zone
                # that reads like a legitimate CDN.
                blob = "-".join(
                    "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                            for _ in range(rng.randrange(5, 9)))
                    for _ in range(2)
                )
                fqdn = f"{blob}.assets.cdn-sync.example"
                events.append((t, fqdn, "A", ip, "tunneling", "evasive-tunnel"))
                t += abs(rng.gauss(2.4, 1.8)) + 0.4

        # --- dictionary DGA -----------------------------------------------
        for _host in range(2):
            ip = _ip(rng, "10.61")
            t = t0 + rng.uniform(0, 600)
            for _ in range(count_per_class // 2):
                fqdn, _fam = self.dga.generate("wordlist")
                events.append((t, fqdn, "A", ip, "dga", "evasive-dga"))
                t += abs(rng.gauss(6.0, 4.0)) + 1.0

        # --- high-jitter beacon --------------------------------------------
        for _host in range(2):
            ip = _ip(rng, "10.62")
            begin = t0 + rng.uniform(0, 600)
            for ts, fqdn, qtype, _tool in self.beacon.session(
                    "updates.cdn-sync.example", count_per_class // 4, begin,
                    interval=180.0, jitter_pct=0.35, qtype="A"):
                events.append((ts, fqdn, qtype, ip, "c2_beacon", "evasive-beacon"))

        # --- plenty of benign cover traffic --------------------------------
        for _ in range(6):
            ip = _ip(rng)
            for ts, fqdn, qtype, _t in self.benign.session(
                    count_per_class, t0 + rng.uniform(0, 600)):
                events.append((ts, fqdn, qtype, ip, "benign", "user"))

        events.sort(key=lambda e: e[0])
        return [
            DNSQuery(qname=f, qtype=qt, source_ip=ip, timestamp=ts,
                     payload_size=len(f) + 17, label=lab, family=fam)
            for ts, f, qt, ip, lab, fam in events
        ]

    # ------------------------------------------------------------------ #
    @staticmethod
    def write_csv(queries: list[DNSQuery], path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["ts", "source_ip", "qname", "qtype", "transport",
                        "label", "family"])
            for q in queries:
                w.writerow([f"{q.timestamp:.6f}", q.source_ip, q.qname, q.qtype,
                            q.transport, q.label, q.family])
        return path

    @staticmethod
    def read_csv(path: str | Path) -> list[DNSQuery]:
        out: list[DNSQuery] = []
        with Path(path).open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                out.append(DNSQuery(
                    qname=row["qname"], qtype=row["qtype"],
                    source_ip=row["source_ip"], timestamp=float(row["ts"]),
                    transport=row.get("transport", "udp"),
                    payload_size=len(row["qname"]) + 17,
                    label=row.get("label"), family=row.get("family"),
                ))
        return out

    @staticmethod
    def stats(queries: list[DNSQuery]) -> dict:
        from collections import Counter
        labels = Counter(q.label for q in queries)
        families = Counter(q.family for q in queries)
        hosts = {q.source_ip for q in queries}
        span = (max(q.timestamp for q in queries)
                - min(q.timestamp for q in queries)) if queries else 0.0
        return {
            "total": len(queries),
            "labels": dict(labels),
            "families": dict(families.most_common(12)),
            "hosts": len(hosts),
            "zones": len({q.registrable for q in queries}),
            "span_seconds": round(span, 1),
            "queries_per_second": round(len(queries) / span, 2) if span else 0.0,
        }
