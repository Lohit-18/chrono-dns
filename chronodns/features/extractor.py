"""
The Feature Extraction Engine.

Turns a raw DNS question into a fixed-order numeric vector that the ML
pipeline and the SQL forensics tables both consume.

    DNSQuery ──► lexical (45) ──┐
                structural (26) ├──► 100-dimension float vector
                temporal  (31) ──┘

The vector order is *frozen* by FEATURE_NAMES so a model trained today still
lines up with a gateway running tomorrow. Adding a feature is a model-version
bump — exactly the discipline you would want in production.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence

import numpy as np

from ..types import DNSQuery
from .lexical import lexical_features
from .structural import structural_features
from .temporal import TemporalTracker

__all__ = ["FeatureExtractor", "FEATURE_NAMES", "FEATURE_COUNT"]


def _probe_names() -> list[str]:
    """Build the canonical, ordered feature-name list by running one probe."""
    lex = lexical_features("probe.example.com", "probe")
    stru = structural_features("probe.example.com", "A", "probe", 40, "udp")
    tracker = TemporalTracker()
    temp = tracker.observe("10.0.0.1", "example.com", "probe", "A", time.time(), 17)
    return list(lex) + list(stru) + list(temp)


FEATURE_NAMES: list[str] = _probe_names()
FEATURE_COUNT: int = len(FEATURE_NAMES)

# Human-readable grouping used by the CLI explain view and the docs.
FEATURE_GROUPS = {
    "lexical": [n for n in FEATURE_NAMES if n in lexical_features("a.b.c", "a")],
    "structural": [
        n for n in FEATURE_NAMES if n in structural_features("a.b.c", "A", "a", 0, "udp")
    ],
}
FEATURE_GROUPS["temporal"] = [
    n for n in FEATURE_NAMES
    if n not in FEATURE_GROUPS["lexical"] and n not in FEATURE_GROUPS["structural"]
]


class FeatureExtractor:
    """Stateful extractor. One instance per gateway process."""

    def __init__(self, window_size: int = 64) -> None:
        self.tracker = TemporalTracker(window_size=window_size)
        self.names = FEATURE_NAMES
        self.count = FEATURE_COUNT
        self._extracted = 0

    # ---------------------------------------------------------------- #
    def extract(self, query: DNSQuery, nxdomain: bool = False) -> dict[str, float]:
        """Full feature dict for one query (updates temporal state)."""
        lex = lexical_features(query.qname, query.subdomain)
        stru = structural_features(
            query.qname, query.qtype, query.subdomain,
            query.payload_size, query.transport,
        )
        temp = self.tracker.observe(
            source_ip=query.source_ip,
            registrable=query.registrable,
            subdomain=query.subdomain,
            qtype=query.qtype,
            ts=query.timestamp,
            qname_len=len(query.qname),
            nxdomain=nxdomain,
        )
        self._extracted += 1
        return {**lex, **stru, **temp}

    def vector(self, features: dict[str, float]) -> np.ndarray:
        """Dict → frozen-order float32 vector, NaN/inf scrubbed."""
        vec = np.fromiter(
            (float(features.get(name, 0.0)) for name in self.names),
            dtype=np.float32,
            count=self.count,
        )
        return np.nan_to_num(vec, nan=0.0, posinf=1e6, neginf=-1e6)

    def extract_vector(self, query: DNSQuery, nxdomain: bool = False
                       ) -> tuple[dict[str, float], np.ndarray]:
        feats = self.extract(query, nxdomain=nxdomain)
        return feats, self.vector(feats)

    def batch(self, queries: Sequence[DNSQuery], reset: bool = True
              ) -> tuple[np.ndarray, list[dict[str, float]]]:
        """Vectorise a whole dataset in chronological order.

        Temporal state is rebuilt from scratch (reset=True) so training is
        reproducible and never leaks state from a previous run.
        """
        if reset:
            self.tracker.reset()
        rows: list[dict[str, float]] = []
        matrix = np.zeros((len(queries), self.count), dtype=np.float32)
        for i, q in enumerate(queries):
            feats = self.extract(q)
            rows.append(feats)
            matrix[i] = self.vector(feats)
        return matrix, rows

    # ---------------------------------------------------------------- #
    @property
    def stats(self) -> dict[str, int]:
        return {
            "extracted": self._extracted,
            "feature_count": self.count,
            "tracked_hosts": len(self.tracker.hosts),
            "tracked_zones": len(self.tracker.zones),
        }

    @staticmethod
    def describe() -> dict[str, int]:
        return {group: len(names) for group, names in FEATURE_GROUPS.items()}


def iter_feature_docs() -> Iterable[tuple[str, str, str]]:
    """(group, name, one-line description) — powers `chronodns features`."""
    docs = {
        "shannon_entropy_full": "Bits/char over the whole name — the core tunnelling signal",
        "shannon_entropy_sub": "Entropy of the attacker-controlled subdomain only",
        "conditional_entropy": "H(Xn|Xn-1); real words are predictable, payloads are not",
        "compression_ratio": "zlib size ratio — incompressible means encoded data",
        "index_of_coincidence": "Cryptanalytic IC; English ~0.066, random ~0.038",
        "chi_square_english": "Goodness of fit to English letter frequencies",
        "bigram_logprob": "Mean log-probability under a hostname bigram model",
        "trigram_logprob": "Same, trigram order — strongest DGA discriminator",
        "dictionary_hit_ratio": "Share of labels that are real hostname vocabulary",
        "vowel_consonant_ratio": "DGA output is consonant-heavy and unpronounceable",
        "base32_conformance": "Fraction of chars inside the base32 alphabet",
        "hex_conformance": "Fraction of chars inside the hex alphabet",
        "max_consec_consonants": "Longest unpronounceable run",
        "transition_rate": "How often the character class flips (encoder tell)",
        "label_len_saturation": "Longest label / 63 — tunnels sit at the RFC ceiling",
        "at_label_limit": "Binary: a label is within 2 bytes of the 63-byte cap",
        "qtype_risk": "Payload capacity + rarity of the record type",
        "is_txt": "TXT records carry the most data — heavily abused",
        "is_null": "NULL records: almost never legitimate",
        "tld_risk": "Offline abuse-rate score for the TLD",
        "subdomain_share": "How much of the name the attacker controls",
        "iat_cv": "sigma/mu of inter-arrival times; ~0 means metronome",
        "beacon_strength": "Autocorrelation-based periodicity score 0..1",
        "beacon_period_s": "Estimated beacon interval in seconds",
        "burstiness": "Goh-Barabasi B; -1 periodic, 0 Poisson, +1 human",
        "fano_factor": "Variance/mean of binned counts; 1.0 = Poisson",
        "zone_unique_subs": "Distinct subdomains seen under one zone",
        "zone_sub_novelty": "Unique/total — 1.0 means every query is brand new",
        "zone_upload_rate": "Bytes of subdomain pushed per second = exfil bandwidth",
        "host_nxdomain_60s": "NXDOMAIN storm counter — the classic DGA tell",
        "host_unique_zones": "Zone fan-out per host",

        # --- lexical, continued ------------------------------------------
        "shannon_entropy_longest": "Entropy of the single longest label",
        "normalized_entropy_full": "Entropy scaled by the maximum possible for that length",
        "normalized_entropy_sub": "Same, over the attacker-controlled subdomain",
        "renyi_entropy_2": "Collision entropy; very sensitive to flat encoder alphabets",
        "renyi_entropy_05": "Rényi alpha=0.5; weights rare characters more heavily",
        "min_entropy": "-log2 of the most frequent character's probability",
        "entropy_per_label": "Mean entropy across the individual labels",
        "compression_ratio_full": "zlib ratio over the whole name",
        "unique_char_ratio": "Distinct characters over length",
        "longest_repeat_ratio": "Longest substring occurring twice, over length",
        "bigram_logprob_longest": "Bigram plausibility of the longest label alone",
        "unique_bigram_ratio": "Share of letter pairs occurring exactly once",
        "unique_trigram_ratio": "Share of letter triples occurring exactly once",
        "bigram_coverage": "Fraction of letter pairs that exist in real hostnames",
        "trigram_coverage": "Fraction of letter triples that exist in real hostnames",
        "digit_ratio": "Share of digits",
        "alpha_ratio": "Share of letters",
        "vowel_ratio": "Share of vowels",
        "consonant_ratio": "Share of consonants",
        "hyphen_ratio": "Share of hyphens in the full name",
        "special_ratio": "Share of non-alphanumeric characters",
        "uppercase_ratio": "Share of uppercase characters (0-day mixed-case tricks)",
        "base64_conformance": "Fraction of chars inside the base64url alphabet",
        "max_consec_digits": "Longest digit run",
        "max_consec_vowels": "Longest vowel run",
        "digit_position_bias": "Mean normalised position of digits; real names put them last",
        "starts_with_digit": "Binary: first character is a digit",
        "has_punycode": "Binary: contains an xn-- IDN prefix",
        "repeated_char_max": "Longest run of one repeated character",
        "entropy_gap_sub_vs_reg": "Entropy of the subdomain minus that of the registered zone",
        "label_entropy_std": "Spread of per-label entropy; tunnels graft high onto low",
        "label_entropy_max": "Highest per-label entropy",

        # --- structural, continued ----------------------------------------
        "qname_length": "Total query name length in bytes",
        "qname_length_ratio": "Name length over the 253-byte wire limit",
        "label_count": "Number of dot-separated labels",
        "sub_label_count": "Labels belonging to the subdomain",
        "subdomain_length": "Bytes the attacker controls",
        "max_label_length": "Longest label in bytes",
        "min_label_length": "Shortest label in bytes",
        "mean_label_length": "Mean label length",
        "std_label_length": "Spread of label lengths",
        "near_name_limit": "Binary: within 20 bytes of the 253-byte wire limit",
        "long_label_count": "Number of labels longer than 30 bytes",
        "is_cname": "CNAME query — used for tunnel downstream data",
        "is_any": "ANY query — reconnaissance or tunnelling",
        "is_high_capacity_type": "TXT / NULL / CNAME / ANY / NAPTR",
        "tld_length": "Length of the top-level domain",
        "is_numeric_tld": "Binary: TLD is all digits (malformed)",
        "numeric_label_count": "Labels that are entirely digits",
        "payload_size": "Wire size of the request packet",
        "is_tcp": "Binary: arrived over TCP (large payload or zone transfer)",
        "bytes_per_label": "Name length divided by label count",

        # --- temporal, continued ------------------------------------------
        "iat_mean": "Mean inter-arrival time for this host/zone pair",
        "iat_std": "Standard deviation of inter-arrival times",
        "iat_min": "Shortest observed gap",
        "iat_max": "Longest observed gap",
        "iat_median": "Median gap — robust to one stalled request",
        "iat_range": "max - min gap",
        "iat_iqr": "Interquartile range of gaps",
        "iat_last": "Gap since the previous query to this zone",
        "time_entropy": "Entropy of the arrival-time histogram; low means clustered",
        "zone_query_count": "Queries seen for this host/zone pair",
        "zone_is_new_sub": "Binary: this subdomain has not been seen before",
        "zone_qps": "Queries per second to this zone",
        "zone_uploaded_bytes": "Cumulative subdomain bytes sent to this zone",
        "zone_qtype_diversity": "Distinct record types used against this zone",
        "host_query_count": "Total queries from this source IP",
        "host_qps": "Lifetime query rate for this host",
        "host_qps_10s": "Query rate over the last 10 seconds",
        "host_qps_60s": "Query rate over the last 60 seconds",
        "zone_age_s": "Seconds since this host first touched this zone",
        "zone_duty_cycle": "Fraction of the window occupied by queries",
        "zone_bytes_per_query": "Mean subdomain bytes per query to this zone",
    }
    for group, names in FEATURE_GROUPS.items():
        for name in names:
            yield group, name, docs.get(name, "")
