"""Core data structures passed between pipeline stages."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """Final decision emitted by the engine for a single query."""

    ALLOW = "ALLOW"
    MONITOR = "MONITOR"       # scored suspicious, forwarded but flagged
    SUSPICIOUS = "SUSPICIOUS" # forwarded, alert raised, high confidence needed
    BLOCK = "BLOCK"           # sinkholed / NXDOMAIN returned
    ERROR = "ERROR"

    @property
    def is_blocked(self) -> bool:
        return self is Verdict.BLOCK

    @property
    def colour(self) -> str:
        return {
            Verdict.ALLOW: "green",
            Verdict.MONITOR: "cyan",
            Verdict.SUSPICIOUS: "yellow",
            Verdict.BLOCK: "bold red",
            Verdict.ERROR: "magenta",
        }[self]


class ThreatClass(str, Enum):
    """What kind of badness the classifier believes it is looking at."""

    BENIGN = "benign"
    TUNNELING = "tunneling"
    DGA = "dga"
    C2_BEACON = "c2_beacon"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class DNSQuery:
    """A single observed DNS question, normalised."""

    qname: str
    qtype: str = "A"
    source_ip: str = "127.0.0.1"
    source_port: int = 0
    transport: str = "udp"
    timestamp: float = field(default_factory=time.time)
    txid: int = 0
    query_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    payload_size: int = 0
    label: str | None = None          # ground truth, only present in datasets
    family: str | None = None         # e.g. "conficker", "iodine"

    def __post_init__(self) -> None:
        self.qname = (self.qname or "").strip().rstrip(".").lower()

    @property
    def labels(self) -> list[str]:
        return [x for x in self.qname.split(".") if x]

    @property
    def subdomain(self) -> str:
        """Everything left of the registrable domain (best effort, no PSL dep)."""
        parts = self.labels
        return ".".join(parts[:-2]) if len(parts) > 2 else ""

    @property
    def registrable(self) -> str:
        parts = self.labels
        return ".".join(parts[-2:]) if len(parts) >= 2 else self.qname

    @property
    def tld(self) -> str:
        parts = self.labels
        return parts[-1] if parts else ""


@dataclass(slots=True)
class Detection:
    """The engine's full answer about one query — this is what gets persisted."""

    query: DNSQuery
    verdict: Verdict = Verdict.ALLOW
    threat_class: ThreatClass = ThreatClass.BENIGN
    score: float = 0.0                 # fused 0..1
    supervised_score: float = 0.0
    anomaly_score: float = 0.0
    heuristic_score: float = 0.0
    intel_hit: str | None = None       # threat-intel source that matched
    reasons: list[str] = field(default_factory=list)
    top_features: list[tuple[str, float]] = field(default_factory=list)
    features: dict[str, float] = field(default_factory=dict)
    latency_ms: float = 0.0
    cached: bool = False

    def to_row(self) -> dict[str, Any]:
        """Flatten for SQL insertion."""
        q = self.query
        return {
            "query_id": q.query_id,
            "ts": q.timestamp,
            "source_ip": q.source_ip,
            "qname": q.qname,
            "registrable": q.registrable,
            "subdomain": q.subdomain,
            "tld": q.tld,
            "qtype": q.qtype,
            "transport": q.transport,
            "qname_length": len(q.qname),
            "label_count": len(q.labels),
            "entropy": round(float(self.features.get("shannon_entropy_full", 0.0)), 5),
            "sub_entropy": round(float(self.features.get("shannon_entropy_sub", 0.0)), 5),
            "score": round(self.score, 5),
            "supervised_score": round(self.supervised_score, 5),
            "anomaly_score": round(self.anomaly_score, 5),
            "heuristic_score": round(self.heuristic_score, 5),
            "verdict": self.verdict.value,
            "threat_class": self.threat_class.value,
            "intel_hit": self.intel_hit,
            "reasons": "; ".join(self.reasons[:6]),
            "latency_ms": round(self.latency_ms, 3),
            "is_blocked": 1 if self.verdict.is_blocked else 0,
            "truth_label": q.label,
            "family": q.family,
        }


@dataclass(slots=True)
class HostState:
    """Rolling per-source-IP state used for temporal / volumetric features."""

    source_ip: str
    last_seen: float = 0.0
    total_queries: int = 0
    nxdomain_count: int = 0
    unique_registrables: int = 0
    blocked_count: int = 0
