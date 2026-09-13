"""Engine, policy and heuristic tests."""

from __future__ import annotations

from chronodns.config import get_config
from chronodns.engine import ChronoEngine
from chronodns.engine.policy import Debouncer, PolicyEngine, RateLimiter  # noqa: F401
from chronodns.ml import classify_by_rules, heuristic_score
from chronodns.types import DNSQuery, ThreatClass, Verdict


# --------------------------------------------------------------------------- #
# heuristics
# --------------------------------------------------------------------------- #
def _feats(qname: str, qtype: str = "A") -> dict:
    from chronodns.features import FeatureExtractor
    return FeatureExtractor().extract(DNSQuery(qname=qname, qtype=qtype))


def test_heuristics_flag_encoded_tunnel_payload():
    score, reasons = heuristic_score(
        _feats("mzxw6ytboi7dnnsxs3dbomruwm4tbm5uwy2ltebvgc4tfnzuw4zs.zone.test", "NULL"))
    assert score > 0.7
    assert reasons


def test_heuristics_stay_quiet_on_ordinary_hostnames():
    for name in ("www.github.com", "api.stripe.com", "mail.google.com",
                 "login.microsoftonline.com"):
        score, _ = heuristic_score(_feats(name))
        assert score < 0.45, f"{name} scored {score}"


def test_heuristics_tolerate_high_entropy_cdn_names():
    """The classic false positive: legitimate hostnames that look random."""
    score, _ = heuristic_score(_feats("e4821-a9f3c2d1b7e.akamaiedge.net"))
    assert score < 0.55


def test_rule_classifier_distinguishes_families():
    tunnel = _feats("a" * 62 + ".tunnel.test", "TXT")
    assert classify_by_rules(tunnel) == "tunneling"
    assert classify_by_rules(_feats("www.github.com")) == "benign"


# --------------------------------------------------------------------------- #
# debouncing and rate limiting
# --------------------------------------------------------------------------- #
def test_debouncer_requires_repeat_hits():
    d = Debouncer(hits=3, window_s=60.0)
    assert d.should_enforce("10.0.0.1", "z.test", 100.0) == (False, 1)
    assert d.should_enforce("10.0.0.1", "z.test", 101.0) == (False, 2)
    assert d.should_enforce("10.0.0.1", "z.test", 102.0)[0] is True


def test_debouncer_window_expires():
    d = Debouncer(hits=2, window_s=10.0)
    d.should_enforce("10.0.0.1", "z.test", 100.0)
    ok, count = d.should_enforce("10.0.0.1", "z.test", 200.0)
    assert ok is False and count == 1


def test_rate_limiter_detects_flood():
    limiter = RateLimiter(qps_alarm=5.0, window_s=10.0)
    flooding = False
    for i in range(120):
        flooding, _ = limiter.is_flooding("10.0.0.9", 1000.0 + i * 0.01)
    assert flooding


# --------------------------------------------------------------------------- #
# policy
# --------------------------------------------------------------------------- #
def test_allowlist_short_circuits_everything():
    policy = PolicyEngine(get_config().detection)
    verdict, reasons = policy.decide(
        score=0.99, threat_class="tunneling", source_ip="10.0.0.1",
        zone="cdn.example", ts=1000.0,
        intel={"indicator": "cdn.example", "ioc_type": "zone",
               "category": "tunnel", "severity": 10},
        allowlisted=True)
    assert verdict is Verdict.ALLOW
    assert "allowlisted" in reasons[0]


def test_high_severity_intel_blocks_immediately():
    policy = PolicyEngine(get_config().detection)
    verdict, _ = policy.decide(
        score=0.05, threat_class="benign", source_ip="10.0.0.1",
        zone="bad.test", ts=1000.0,
        intel={"indicator": "bad.test", "ioc_type": "zone",
               "category": "c2", "severity": 10})
    assert verdict is Verdict.BLOCK


def test_score_bands():
    policy = PolicyEngine(get_config().detection)
    assert policy.decide(0.10, "benign", "10.0.0.1", "a.test", 1.0)[0] is Verdict.ALLOW
    assert policy.decide(0.50, "dga", "10.0.0.1", "b.test", 2.0)[0] is Verdict.MONITOR


def test_dga_debounces_on_class_not_zone():
    """Every DGA query is a new zone, so a per-zone counter never fires."""
    cfg = get_config()
    policy = PolicyEngine(cfg.detection)
    v1, _ = policy.decide(0.9, "dga", "10.0.0.1", "aaa.test", 1.0)
    v2, _ = policy.decide(0.9, "dga", "10.0.0.1", "bbb.test", 2.0)
    assert v1 is Verdict.SUSPICIOUS          # first hit debounced
    assert v2 is Verdict.BLOCK               # second hit on a *different* zone


def test_monitor_only_mode_never_blocks():
    cfg = get_config()
    original = cfg.detection.enforce
    cfg.detection.enforce = False
    try:
        policy = PolicyEngine(cfg.detection)
        for i in range(5):
            verdict, _ = policy.decide(0.99, "tunneling", "10.0.0.1", "z.test", float(i))
            assert verdict is not Verdict.BLOCK
    finally:
        cfg.detection.enforce = original


# --------------------------------------------------------------------------- #
# engine
# --------------------------------------------------------------------------- #
async def test_engine_runs_without_a_trained_model():
    """Day zero: heuristics alone must still produce sane verdicts."""
    engine = ChronoEngine()
    assert not engine.model_ready
    d = await engine.analyse(
        DNSQuery(qname="a" * 60 + ".tunnel.test", qtype="NULL"), persist=False)
    assert d.score > 0.5
    benign = await engine.analyse(DNSQuery(qname="www.github.com"), persist=False)
    assert benign.score < 0.45


async def test_engine_is_fail_open_on_internal_error(monkeypatch):
    engine = ChronoEngine()

    def boom(*_a, **_kw):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(engine.extractor, "extract_vector", boom)
    d = await engine.analyse(DNSQuery(qname="example.com"), persist=False)
    assert d.verdict is Verdict.ALLOW
    assert "fail-open" in d.reasons[0]
    assert engine.counters["errors"] == 1


async def test_engine_records_latency_and_counters():
    engine = ChronoEngine()
    for i in range(5):
        await engine.analyse(DNSQuery(qname=f"h{i}.example.com"), persist=False)
    snap = engine.snapshot()
    assert snap["analysed"] == 5
    assert snap["p50_ms"] >= 0.0
    assert snap["features"] >= 100


async def test_detection_row_is_sql_ready():
    engine = ChronoEngine()
    d = await engine.analyse(DNSQuery(qname="x.tunnel.test", qtype="TXT"), persist=False)
    row = d.to_row()
    for key in ("query_id", "ts", "source_ip", "qname", "verdict", "score",
                "threat_class", "is_blocked"):
        assert key in row
    assert row["is_blocked"] in (0, 1)


def test_query_parsing():
    q = DNSQuery(qname="A.B.Example.COM.")
    assert q.qname == "a.b.example.com"
    assert q.registrable == "example.com"
    assert q.subdomain == "a.b"
    assert q.tld == "com"
    assert q.labels == ["a", "b", "example", "com"]


def test_threat_class_enum_roundtrip():
    assert ThreatClass("tunneling") is ThreatClass.TUNNELING
    assert Verdict.BLOCK.is_blocked is True
    assert Verdict.ALLOW.is_blocked is False
