"""
DNS tunnelling traffic simulator.

Models the wire behaviour of four widely documented tunnelling tools. Again:
this generates *query strings that look like* what each tool emits, so the
classifier can learn the shape. It establishes no tunnel and sends no packets.

    iodine          base32 upstream, long labels, NULL/TXT downstream, high rate
    dnscat2         hex-ish upstream, many small labels, TXT/CNAME, session id
    dns2tcp         base64url upstream, TXT, chunked with sequence prefix
    dnsexfiltrator  base32 + RC4-ish opaque blob, single fat label, low & slow

The "low and slow" profile matters: a detector that only triggers on volume
misses the patient attacker. The temporal features are what catch that one.
"""

from __future__ import annotations

import base64
import random
import string
from dataclasses import dataclass

B32 = string.ascii_lowercase + "234567"
B64URL = string.ascii_lowercase + string.ascii_uppercase + string.digits + "-_"
HEXC = string.hexdigits.lower()[:16]


@dataclass
class TunnelProfile:
    name: str
    zone: str
    alphabet: str
    label_min: int
    label_max: int
    labels_min: int
    labels_max: int
    qtypes: list[str]
    iat_mean: float          # seconds between queries
    iat_jitter: float        # fraction of the mean
    session_prefix: bool     # tools that carry a session/sequence tag
    description: str


PROFILES: dict[str, TunnelProfile] = {
    "iodine": TunnelProfile(
        "iodine", "tunnel.example", B32, 48, 63, 1, 2,
        ["NULL", "TXT", "CNAME"], 0.04, 0.45, True,
        "High-throughput IP-over-DNS: labels pinned at the 63-byte RFC ceiling"),
    "dnscat2": TunnelProfile(
        "dnscat2", "c2.example", HEXC, 24, 40, 2, 3,
        ["TXT", "CNAME", "MX"], 0.35, 0.60, True,
        "Command-and-control shell: hex payload split across several labels"),
    "dns2tcp": TunnelProfile(
        "dns2tcp", "exfil.example", B64URL, 32, 56, 1, 3,
        ["TXT", "A"], 0.12, 0.50, True,
        "TCP-over-DNS relay: base64url chunks with a sequence counter"),
    "slowexfil": TunnelProfile(
        "slowexfil", "exfil.example", B32, 40, 62, 1, 1,
        ["TXT", "A", "AAAA"], 9.0, 0.15, False,
        "Low-and-slow document theft: one fat label every ~9s, volume-invisible"),
}


class TunnelGenerator:
    """Emits realistic tunnelling query streams with their timing."""

    def __init__(self, seed: int = 1337) -> None:
        self.rng = random.Random(seed)
        self._seq = 0

    def _blob(self, alphabet: str, length: int) -> str:
        return "".join(self.rng.choice(alphabet) for _ in range(length))

    def encode_payload(self, data: bytes, alphabet: str = "b32") -> str:
        """Real encoding path — used by `chronodns simulate --exfil <file>`."""
        if alphabet == "b32":
            return base64.b32encode(data).decode().lower().rstrip("=")
        if alphabet == "b64":
            return base64.urlsafe_b64encode(data).decode().rstrip("=")
        return data.hex()

    def query(self, profile: str = "iodine") -> tuple[str, str, str]:
        """Return (fqdn, qtype, tool_name)."""
        p = PROFILES[profile]
        labels: list[str] = []
        if p.session_prefix:
            self._seq = (self._seq + 1) % 0xFFFF
            labels.append(f"{self._seq:04x}")
        for _ in range(self.rng.randrange(p.labels_min, p.labels_max + 1)):
            labels.append(self._blob(p.alphabet, self.rng.randrange(p.label_min,
                                                                   p.label_max + 1)))
        fqdn = ".".join(labels) + "." + p.zone
        # Never exceed the 253-byte wire limit — real tools do not either.
        while len(fqdn) > 250 and len(labels) > 1:
            labels.pop()
            fqdn = ".".join(labels) + "." + p.zone
        return fqdn, self.rng.choice(p.qtypes), p.name

    def session(self, profile: str, count: int, start_ts: float
                ) -> list[tuple[float, str, str, str]]:
        """A full tunnelling session: [(ts, fqdn, qtype, tool), ...]."""
        p = PROFILES[profile]
        out = []
        t = start_ts
        for _ in range(count):
            fqdn, qtype, tool = self.query(profile)
            out.append((t, fqdn, qtype, tool))
            jitter = self.rng.uniform(1 - p.iat_jitter, 1 + p.iat_jitter)
            t += max(p.iat_mean * jitter, 0.001)
        return out

    def exfiltrate_file(self, data: bytes, zone: str = "exfil.example",
                        chunk: int = 48, start_ts: float = 0.0,
                        iat: float = 0.08) -> list[tuple[float, str, str, str]]:
        """Encode real bytes into a real query stream — the demo showstopper.

        Used by `chronodns simulate --exfil secret.txt` so you can watch an
        actual file leave the network one subdomain at a time, and watch
        Chrono-DNS cut it off mid-transfer.
        """
        blob = self.encode_payload(data, "b32")
        chunks = [blob[i:i + chunk] for i in range(0, len(blob), chunk)]
        out = []
        t = start_ts
        for idx, part in enumerate(chunks):
            fqdn = f"{idx:04x}.{part}.{zone}"
            out.append((t, fqdn, "TXT", "file-exfil"))
            t += iat
        return out


class BeaconGenerator:
    """C2 beaconing — the *timing* is the payload.

    A real implant sleeps for a fixed interval with a small jitter percentage.
    Over a dozen check-ins the coefficient of variation stays near zero, which
    no human browsing pattern ever does.
    """

    def __init__(self, seed: int = 1337) -> None:
        self.rng = random.Random(seed)

    def session(self, zone: str, count: int, start_ts: float,
                interval: float = 60.0, jitter_pct: float = 0.05,
                qtype: str = "TXT") -> list[tuple[float, str, str, str]]:
        out = []
        t = start_ts
        for _ in range(count):
            token = "".join(self.rng.choice(string.hexdigits.lower()[:16])
                            for _ in range(self.rng.randrange(8, 18)))
            out.append((t, f"{token}.{zone}", qtype, "beacon"))
            t += interval * self.rng.uniform(1 - jitter_pct, 1 + jitter_pct)
        return out
