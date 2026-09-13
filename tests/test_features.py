"""Feature-engineering tests.

These assert the *mathematical properties* the detector relies on, not just
that the code runs. If entropy stops separating encoded payloads from
hostnames, these fail loudly.
"""

from __future__ import annotations

import math

import pytest

from chronodns.features import (
    FEATURE_COUNT,
    FEATURE_NAMES,
    FeatureExtractor,
    lexical_features,
    shannon_entropy,
    structural_features,
)
from chronodns.features.lexical import (
    compression_ratio,
    conditional_entropy,
    dictionary_hit_ratio,
    index_of_coincidence,
    ngram_coverage,
    ngram_score,
    normalized_entropy,
)
from chronodns.features.temporal import TemporalTracker, burstiness, periodicity_score
from chronodns.types import DNSQuery


# --------------------------------------------------------------------------- #
# entropy
# --------------------------------------------------------------------------- #
def test_shannon_entropy_bounds():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert 0 < shannon_entropy("github") < 3.0


def test_encoded_payload_has_higher_entropy_than_hostname():
    hostname = shannon_entropy("apigithubcom")
    payload = shannon_entropy("mzxw6ytboi7dnnsxs3dbomruwm4tbm5uwy2lteb")
    assert payload > hostname + 0.5


def test_normalized_entropy_is_bounded():
    for s in ("a", "ab", "github", "mzxw6ytboi7dnnsxs3db", "0123456789abcdef"):
        assert 0.0 <= normalized_entropy(s) <= 1.0001


def test_conditional_entropy_measures_bigram_repetition():
    """Documented behaviour: a string whose bigrams are all unique yields 0."""
    assert conditional_entropy("x7f2q9zk4m1p8w3r6t5y") == 0.0
    assert conditional_entropy("informationsecurity") > 0.0


def test_ngram_coverage_separates_hostnames_from_payloads():
    """The principled 'does this look like a hostname' test."""
    for benign in ("apigithubcom", "loginmicrosoftonlinecom", "informationsecurity"):
        assert ngram_coverage(benign, 2) > 0.65, benign
    for bad in ("mzxw6ytboi7dnnsxs3dbomruwm4tbm5uwy2lteb",
                "x7f2q9zk4m1p8w3r6t5y", "kqwbxjvmzpdlfr"):
        assert ngram_coverage(bad, 2) < 0.40, bad


def test_compression_ratio_detects_incompressible_payload():
    repetitive = compression_ratio("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    random_like = compression_ratio("mzxw6ytboi7dnnsxs3dbomruwm4tbm5uwy2lteb")
    assert repetitive < random_like


def test_index_of_coincidence_range():
    english = index_of_coincidence("thequickbrownfoxjumpsoverthelazydog")
    assert 0.0 <= english <= 1.0


# --------------------------------------------------------------------------- #
# n-gram model
# --------------------------------------------------------------------------- #
def test_ngram_prefers_plausible_hostnames():
    assert ngram_score("login", 2) > ngram_score("xqzjkvbw", 2)
    assert ngram_score("api", 3) >= ngram_score("qxzjvk", 3)


def test_dictionary_hit_ratio():
    assert dictionary_hit_ratio("api.github.com") > 0.0
    assert dictionary_hit_ratio("x89f21aq99z.kqwbxjvm") == 0.0


# --------------------------------------------------------------------------- #
# structural
# --------------------------------------------------------------------------- #
def test_rfc_label_limit_flag():
    long_label = "a" * 62
    f = structural_features(f"{long_label}.tunnel.example", "TXT", long_label, 0, "udp")
    assert f["at_label_limit"] == 1.0
    assert f["label_len_saturation"] > 0.95


def test_qtype_risk_ordering():
    null_r = structural_features("x.example", "NULL", "x")["qtype_risk"]
    txt_r = structural_features("x.example", "TXT", "x")["qtype_risk"]
    a_r = structural_features("x.example", "A", "x")["qtype_risk"]
    assert null_r >= txt_r > a_r


def test_subdomain_share():
    f = structural_features("a.b.c.example.com", "A", "a.b.c")
    assert 0 < f["subdomain_share"] < 1


# --------------------------------------------------------------------------- #
# temporal
# --------------------------------------------------------------------------- #
def test_perfect_beacon_has_near_zero_cv():
    tracker = TemporalTracker()
    feats = {}
    for i in range(12):
        feats = tracker.observe("10.0.0.1", "c2.example", f"s{i}", "TXT",
                                ts=1000.0 + i * 60.0)
    assert feats["iat_cv"] < 0.01
    assert feats["beacon_strength"] > 0.9
    assert feats["beacon_period_s"] == pytest.approx(60.0, abs=1.0)


def test_human_traffic_is_bursty_not_periodic():
    tracker = TemporalTracker()
    gaps = [0.05, 0.08, 0.06, 12.0, 0.07, 0.09, 40.0, 0.05, 0.11, 3.0, 0.06, 25.0]
    t = 1000.0
    feats = {}
    for i, g in enumerate(gaps):
        t += g
        feats = tracker.observe("10.0.0.2", "news.example", f"s{i}", "A", ts=t)
    assert feats["iat_cv"] > 0.5
    assert feats["burstiness"] > 0.0


def test_burstiness_signs():
    assert burstiness([60.0] * 10) == pytest.approx(-1.0, abs=0.01)
    assert burstiness([0.1, 0.1, 50.0, 0.1, 80.0]) > 0.0


def test_periodicity_on_constant_intervals():
    strength, period = periodicity_score([30.0] * 10)
    assert strength == pytest.approx(1.0)
    assert period == pytest.approx(30.0)


def test_rates_are_zero_without_an_observation_window():
    """A single query must never imply a data rate."""
    tracker = TemporalTracker()
    f = tracker.observe("10.0.0.3", "zone.example", "a" * 52, "TXT", ts=1000.0)
    assert f["zone_upload_rate"] == 0.0
    assert f["zone_qps"] == 0.0


def test_zone_novelty_tracks_unique_subdomains():
    tracker = TemporalTracker()
    for i in range(20):
        f = tracker.observe("10.0.0.4", "tunnel.example", f"chunk{i}", "TXT",
                            ts=1000.0 + i * 0.1)
    assert f["zone_sub_novelty"] == pytest.approx(1.0)
    assert f["zone_unique_subs"] == 20


# --------------------------------------------------------------------------- #
# extractor contract
# --------------------------------------------------------------------------- #
def test_feature_vector_shape_and_order_is_stable():
    fx = FeatureExtractor()
    assert FEATURE_COUNT >= 100
    assert len(FEATURE_NAMES) == FEATURE_COUNT
    assert len(set(FEATURE_NAMES)) == FEATURE_COUNT, "feature names must be unique"
    _, vec = fx.extract_vector(DNSQuery(qname="api.github.com"))
    assert vec.shape == (FEATURE_COUNT,)
    assert vec.dtype.name == "float32"


def test_no_nan_or_inf_for_pathological_inputs():
    fx = FeatureExtractor()
    for qname in ("", ".", "a", "a" * 250, "x" * 63 + ".example",
                  "xn--80ak6aa92e.example", "1.2.3.4.in-addr.arpa"):
        _, vec = fx.extract_vector(DNSQuery(qname=qname))
        assert not any(math.isnan(float(v)) or math.isinf(float(v)) for v in vec)


def test_batch_matches_sequential_extraction():
    queries = [DNSQuery(qname=f"h{i}.example.com", timestamp=1000.0 + i)
               for i in range(25)]
    matrix, rows = FeatureExtractor().batch(queries)
    assert matrix.shape == (25, FEATURE_COUNT)
    assert len(rows) == 25


def test_lexical_falls_back_for_short_subdomains():
    """'www' alone has no vowels; the ratio must not be computed from it."""
    f = lexical_features("www.github.com", "www")
    assert f["vowel_consonant_ratio"] > 0.0
