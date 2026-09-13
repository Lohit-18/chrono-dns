"""Model and data-generation tests."""

from __future__ import annotations

import numpy as np
import pytest

from chronodns.datagen import DatasetBuilder, DGAGenerator, ScenarioMix, TunnelGenerator
from chronodns.datagen.tunnel import PROFILES
from chronodns.features import FEATURE_COUNT, FeatureExtractor
from chronodns.ml import ThreatEnsemble, train_model
from chronodns.ml.train import build_mask, chronological_split


# --------------------------------------------------------------------------- #
# data generation
# --------------------------------------------------------------------------- #
def test_dga_families_produce_distinct_shapes():
    gen = DGAGenerator(7)
    for family in ("arithmetic", "hashbased", "wordlist", "permutation",
                   "markov", "base36"):
        fqdn, name = gen.generate(family)
        assert name == family
        assert "." in fqdn and len(fqdn) < 100
        assert all(c.isalnum() or c in ".-" for c in fqdn)


def test_tunnel_profiles_respect_dns_wire_limits():
    gen = TunnelGenerator(7)
    for profile in PROFILES:
        for _ in range(30):
            fqdn, qtype, _tool = gen.query(profile)
            assert len(fqdn) <= 253, f"{profile}: {len(fqdn)} bytes"
            assert all(len(label) <= 63 for label in fqdn.split("."))


def test_beacon_timing_is_regular():
    from chronodns.datagen import BeaconGenerator
    session = BeaconGenerator(1).session("c2.example", 20, 0.0,
                                         interval=60.0, jitter_pct=0.02)
    gaps = [b[0] - a[0] for a, b in zip(session, session[1:], strict=False)]
    cv = float(np.std(gaps) / np.mean(gaps))
    assert cv < 0.05


def test_dataset_is_chronological_and_labelled():
    queries = DatasetBuilder(3).build(ScenarioMix(
        benign_hosts=3, benign_per_host=40, telemetry_hosts=1,
        telemetry_per_host=5, tunnel_hosts=1, tunnel_per_host=40,
        slow_exfil_hosts=1, slow_exfil_per_host=10, dga_hosts=1,
        dga_per_host=20, beacon_hosts=1, beacon_per_host=10))
    assert queries
    timestamps = [q.timestamp for q in queries]
    assert timestamps == sorted(timestamps)
    labels = {q.label for q in queries}
    assert "benign" in labels and len(labels) >= 3


def test_csv_roundtrip(tmp_path):
    queries = DatasetBuilder(5).build(ScenarioMix(
        benign_hosts=2, benign_per_host=20, telemetry_hosts=0, tunnel_hosts=1,
        tunnel_per_host=20, slow_exfil_hosts=0, dga_hosts=1, dga_per_host=10,
        beacon_hosts=0))
    path = DatasetBuilder.write_csv(queries, tmp_path / "cap.csv")
    restored = DatasetBuilder.read_csv(path)
    assert len(restored) == len(queries)
    assert restored[0].qname == queries[0].qname
    assert restored[0].label == queries[0].label


def test_evasive_set_targets_the_detection_axes():
    evasive = DatasetBuilder(11).build_evasive(60)
    attacks = [q for q in evasive if q.label != "benign"]
    assert attacks
    # Evasive tunnelling must stay well under the RFC label ceiling.
    tun = [q for q in attacks if q.family == "evasive-tunnel"]
    assert tun
    assert all(max(len(x) for x in q.labels) < 40 for q in tun)


# --------------------------------------------------------------------------- #
# training
# --------------------------------------------------------------------------- #
def test_chronological_split_does_not_shuffle():
    queries = DatasetBuilder(9).build(ScenarioMix(
        benign_hosts=2, benign_per_host=50, telemetry_hosts=0, tunnel_hosts=1,
        tunnel_per_host=50, slow_exfil_hosts=0, dga_hosts=1, dga_per_host=20,
        beacon_hosts=0))
    train, test = chronological_split(queries, 0.25)
    assert max(q.timestamp for q in train) <= min(q.timestamp for q in test)


def test_ablation_mask_zeroes_the_named_group():
    mask = build_mask(("tld_",))
    from chronodns.features import FEATURE_NAMES
    for name, keep in zip(FEATURE_NAMES, mask, strict=False):
        assert keep == (0.0 if name.startswith("tld_") else 1.0)


@pytest.mark.slow
def test_end_to_end_training_reaches_useful_performance(tmp_path):
    queries = DatasetBuilder(1337).build(ScenarioMix(
        benign_hosts=8, benign_per_host=120, telemetry_hosts=2,
        telemetry_per_host=15, tunnel_hosts=2, tunnel_per_host=150,
        slow_exfil_hosts=1, slow_exfil_per_host=40, dga_hosts=2,
        dga_per_host=80, beacon_hosts=2, beacon_per_host=30))
    model, report = train_model(queries)
    m = report["metrics"]

    assert m["accuracy"] > 0.90
    assert m["f1"] > 0.90
    assert m["false_positive_rate"] < 0.02
    assert m["detection_rate"] > 0.80
    assert m["feature_count"] == FEATURE_COUNT

    saved = model.save(tmp_path)
    assert saved.exists()

    reloaded = ThreatEnsemble()
    assert reloaded.load(tmp_path)
    assert reloaded.feature_names == model.feature_names
    assert reloaded.classes_ == model.classes_


@pytest.mark.slow
def test_fast_inference_path_matches_sklearn(tmp_path):
    queries = DatasetBuilder(21).build(ScenarioMix(
        benign_hosts=5, benign_per_host=80, telemetry_hosts=1,
        telemetry_per_host=10, tunnel_hosts=1, tunnel_per_host=90,
        slow_exfil_hosts=0, dga_hosts=1, dga_per_host=50, beacon_hosts=1,
        beacon_per_host=20))
    model, _ = train_model(queries)
    fx = FeatureExtractor()
    for q in queries[:40]:
        _, vec = fx.extract_vector(q)
        x = np.ascontiguousarray(vec, dtype=np.float32).reshape(1, -1)
        model._fast_path_ok = True
        fast = model._fast_proba(x)
        model._fast_path_ok = False
        ref = model.rf.predict_proba(x)[0]
        assert np.allclose(fast, ref, atol=1e-6)


@pytest.mark.slow
def test_cascade_shortcut_never_changes_the_verdict_band():
    """The anomaly voter is skipped only when it provably cannot matter."""
    queries = DatasetBuilder(33).build(ScenarioMix(
        benign_hosts=4, benign_per_host=60, telemetry_hosts=1,
        telemetry_per_host=10, tunnel_hosts=1, tunnel_per_host=60,
        slow_exfil_hosts=0, dga_hosts=1, dga_per_host=30, beacon_hosts=1,
        beacon_per_host=15))
    model, _ = train_model(queries)
    model.set_bands(0.45, 0.70)
    fx = FeatureExtractor()

    for q in queries[:300]:
        feats, vec = fx.extract_vector(q)
        scores = model.score_vector(vec, feats)
        if scores.anomaly_evaluated:
            continue
        base = model.w_sup * scores.supervised + model.w_heur * scores.heuristic
        assert model._band(base) == model._band(min(base + model.w_anom, 1.0))


@pytest.mark.slow
def test_untrained_ensemble_still_scores():
    model = ThreatEnsemble()
    assert not model.is_trained
    fx = FeatureExtractor()
    from chronodns.types import DNSQuery
    feats, vec = fx.extract_vector(
        DNSQuery(qname="a" * 60 + ".tunnel.test", qtype="NULL"))
    scores = model.score_vector(vec, feats)
    assert scores.fused > 0.5
    assert scores.reasons
