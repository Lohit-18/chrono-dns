"""
Benign traffic simulator.

Getting the *negative* class right is harder than the positive class and it is
where most student projects fall over: if your benign traffic is just
"www.google.com" repeated, your model reports 99.9% accuracy and then blocks
the corporate CDN on day one of deployment.

So this generator deliberately includes the awkward cases that look malicious
but are not:

  * CDN edge hostnames    e2-92-hash7fx.akamaiedge.net   (high entropy, legit)
  * Cloud storage buckets  a8f3d91b-2c4e.s3.amazonaws.com
  * AV / RBL lookups       <base32 hash>.sophosxl.net    (literally encoded data)
  * DKIM selectors         s1024._domainkey.example.net
  * Reverse DNS            42.77.10.10.in-addr.arpa
  * Telemetry beacons      legitimate software polls on a timer too

Popularity follows a Zipf distribution and arrival times are bursty (a page
load fires 20 lookups in 2 seconds, then the user reads for 40 seconds) —
matching how real recursive-resolver logs actually look.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass

# Ordinary corporate / consumer zones.
POPULAR_ZONES = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "cloudflare.com",
    "github.com", "stackoverflow.com", "wikipedia.org", "youtube.com",
    "linkedin.com", "office.com", "office365.com", "live.com", "bing.com",
    "adobe.com", "zoom.us", "slack.com", "atlassian.net", "salesforce.com",
    "dropbox.com", "docker.com", "python.org", "npmjs.com", "pypi.org",
    "debian.org", "ubuntu.com", "redhat.com", "mozilla.org", "wordpress.org",
    "shopify.com", "paypal.com", "visa.com", "hdfcbank.com", "irctc.co.in",
    "example.com", "example.net", "example.org", "intranet.corp",
    # --- Reserved-TLD corporate zones -------------------------------------
    # These exist to defeat a subtle but fatal form of label leakage: if every
    # *attack* domain lives in a reserved TLD (.example/.test/.invalid) and
    # every *benign* domain lives in a real one, the classifier learns the TLD
    # and nothing else, then collapses the moment it meets real traffic.
    # Putting benign traffic in the same TLD space forces the model to learn
    # the linguistics and the timing instead.
    "intranet.example", "portal.example", "sharepoint.example", "erp.example",
    "printers.example", "hr.example", "wiki.example", "jenkins.test",
    "gitlab.test", "registry.test", "backup.invalid", "nas.invalid",
]

COMMON_HOSTS = [
    "www", "api", "cdn", "static", "assets", "img", "mail", "smtp", "imap",
    "login", "auth", "account", "app", "web", "m", "mobile", "edge", "gw",
    "vpn", "ns1", "ns2", "mx1", "mx2", "docs", "help", "support", "status",
    "update", "updates", "download", "telemetry", "metrics", "analytics",
    "ocsp", "crl", "time", "ntp", "push", "chat", "meet", "drive", "sync",
]

# Services whose hostnames are *supposed* to look like random noise.
HIGH_ENTROPY_LEGIT = [
    ("akamaiedge.net", "cdn-edge"),
    ("akamai.net", "cdn-edge"),
    ("cloudfront.net", "cdn-edge"),
    ("s3.amazonaws.com", "cloud-bucket"),
    ("blob.core.windows.net", "cloud-bucket"),
    ("azureedge.net", "cdn-edge"),
    ("fastly.net", "cdn-edge"),
    ("sophosxl.net", "av-lookup"),
    ("spamhaus.org", "rbl-lookup"),
    ("gvt1.com", "update-channel"),
    # Same anti-leakage reasoning: high-entropy *benign* names in reserved TLDs.
    ("cdn.example", "cdn-edge"),
    ("objects.test", "cloud-bucket"),
    ("rbl.invalid", "rbl-lookup"),
]


@dataclass
class BenignProfile:
    burst_min: int = 3
    burst_max: int = 18
    intra_burst_iat: float = 0.09
    inter_burst_min: float = 5.0
    inter_burst_max: float = 90.0


class BenignGenerator:
    def __init__(self, seed: int = 1337) -> None:
        self.rng = random.Random(seed)
        # Zipf weights: a handful of zones dominate real traffic.
        self.weights = [1.0 / (i + 1) ** 0.85 for i in range(len(POPULAR_ZONES))]

    # -- individual name builders --------------------------------------- #
    def _ordinary(self) -> tuple[str, str]:
        zone = self.rng.choices(POPULAR_ZONES, weights=self.weights, k=1)[0]
        host = self.rng.choice(COMMON_HOSTS)
        if self.rng.random() < 0.18:
            host = f"{host}{self.rng.randrange(1, 9)}"
        if self.rng.random() < 0.10:
            host = f"{self.rng.choice(['eu','us','ap','in'])}-{host}"
        qtype = self.rng.choices(
            ["A", "AAAA", "HTTPS", "CNAME", "MX", "TXT", "SRV", "PTR", "NS"],
            weights=[58, 20, 9, 4, 3, 3, 1, 1, 1], k=1)[0]
        return f"{host}.{zone}", qtype

    def _cdn_like(self) -> tuple[str, str]:
        """The hard negatives: legitimately high-entropy hostnames."""
        zone, kind = self.rng.choice(HIGH_ENTROPY_LEGIT)
        if kind == "cdn-edge":
            label = (f"e{self.rng.randrange(10, 9999)}-"
                     f"{self._hexish(self.rng.randrange(6, 14))}")
        elif kind == "cloud-bucket":
            label = "-".join(self._hexish(self.rng.randrange(4, 9))
                             for _ in range(self.rng.randrange(2, 4)))
        elif kind in ("av-lookup", "rbl-lookup"):
            # These really are encoded hashes — the classic false positive.
            label = self._b32ish(self.rng.randrange(26, 34))
        else:
            label = f"r{self.rng.randrange(1, 40)}---sn-{self._hexish(8)}"
        qtype = self.rng.choices(["A", "AAAA", "TXT", "CNAME"],
                                 weights=[55, 25, 10, 10], k=1)[0]
        return f"{label}.{zone}", qtype

    def _infrastructure(self) -> tuple[str, str]:
        pick = self.rng.random()
        if pick < 0.35:
            octets = [self.rng.randrange(1, 255) for _ in range(4)]
            return ".".join(map(str, reversed(octets))) + ".in-addr.arpa", "PTR"
        if pick < 0.55:
            sel = self.rng.choice(["s1024", "selector1", "google", "k1", "dkim"])
            return f"{sel}._domainkey.{self.rng.choice(POPULAR_ZONES)}", "TXT"
        if pick < 0.75:
            svc = self.rng.choice(["_sip._tcp", "_ldap._tcp", "_autodiscover._tcp",
                                   "_xmpp-client._tcp", "_kerberos._udp"])
            return f"{svc}.{self.rng.choice(POPULAR_ZONES)}", "SRV"
        if pick < 0.9:
            return f"_acme-challenge.{self.rng.choice(POPULAR_ZONES)}", "TXT"
        return f"{self.rng.choice(POPULAR_ZONES)}", "MX"

    def _hexish(self, n: int) -> str:
        return "".join(self.rng.choice("0123456789abcdef") for _ in range(n))

    def _b32ish(self, n: int) -> str:
        return "".join(self.rng.choice(string.ascii_lowercase + "234567")
                       for _ in range(n))

    # -- stream builders ------------------------------------------------- #
    def query(self) -> tuple[str, str]:
        r = self.rng.random()
        if r < 0.70:
            return self._ordinary()
        if r < 0.90:
            return self._cdn_like()
        return self._infrastructure()

    def session(self, count: int, start_ts: float,
                profile: BenignProfile | None = None
                ) -> list[tuple[float, str, str, str]]:
        """Bursty human-like browsing: page loads separated by reading pauses."""
        p = profile or BenignProfile()
        out: list[tuple[float, str, str, str]] = []
        t = start_ts
        while len(out) < count:
            burst = self.rng.randrange(p.burst_min, p.burst_max + 1)
            for _ in range(min(burst, count - len(out))):
                fqdn, qtype = self.query()
                out.append((t, fqdn, qtype, "benign"))
                t += abs(self.rng.gauss(p.intra_burst_iat, p.intra_burst_iat * 0.6)) + 0.005
            t += self.rng.uniform(p.inter_burst_min, p.inter_burst_max)
        return out

    def telemetry_session(self, count: int, start_ts: float, interval: float = 300.0
                          ) -> list[tuple[float, str, str, str]]:
        """Legitimate software that polls on a timer — a *benign* beacon.

        Included on purpose: without it the model learns "periodic == evil"
        and blocks every update checker in the building.
        """
        zone = self.rng.choice(["windowsupdate.com", "gvt1.com", "ntp.org",
                                "cloudflare.com", "apple.com"])
        host = self.rng.choice(["telemetry", "update", "time", "status", "metrics"])
        out = []
        t = start_ts
        for _ in range(count):
            out.append((t, f"{host}.{zone}", "A", "benign"))
            t += interval * self.rng.uniform(0.92, 1.08)
        return out
