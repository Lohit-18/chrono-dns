"""Gateway tests: cache, packet handling, sinkhole responses."""

from __future__ import annotations

import struct

import pytest

from chronodns.config import get_config
from chronodns.engine import ChronoEngine
from chronodns.gateway import AnswerCache, ChronoGateway
from chronodns.gateway.server import DNSLIB_AVAILABLE

dnslib = pytest.importorskip("dnslib") if DNSLIB_AVAILABLE else None

# A realistic base32 tunnelling payload at the RFC label ceiling.
TUNNEL_PROBE = ("mzxw6ytboi7dnnsxs3dbomruwm4tbm5uwy2ltebvgc4tfnzuw4z3ubmzqwy3a"
                ".tunnel.test")
pytestmark = pytest.mark.skipif(not DNSLIB_AVAILABLE, reason="dnslib not installed")


# --------------------------------------------------------------------------- #
# cache
# --------------------------------------------------------------------------- #
def test_cache_hit_and_miss():
    cache = AnswerCache(max_entries=10, ttl_floor=60)
    assert cache.get("example.com", "A") is None
    cache.put("example.com", "A", b"payload", 300)
    assert cache.get("example.com", "A") == b"payload"
    assert cache.stats["hits"] == 1
    assert cache.stats["misses"] == 1


def test_cache_is_case_and_dot_insensitive():
    cache = AnswerCache()
    cache.put("Example.COM.", "a", b"x", 60)
    assert cache.get("example.com", "A") == b"x"


def test_cache_evicts_lru():
    cache = AnswerCache(max_entries=3, ttl_floor=60)
    for i in range(6):
        cache.put(f"h{i}.example.com", "A", b"x", 60)
    assert cache.stats["entries"] == 3
    assert cache.stats["evictions"] == 3


def test_cache_respects_expiry(monkeypatch):
    import chronodns.gateway.cache as cache_mod
    now = [1000.0]
    monkeypatch.setattr(cache_mod.time, "time", lambda: now[0])
    cache = AnswerCache(ttl_floor=1)
    cache.put("example.com", "A", b"x", 5)
    assert cache.get("example.com", "A") == b"x"
    now[0] += 10
    assert cache.get("example.com", "A") is None


# --------------------------------------------------------------------------- #
# packet handling
# --------------------------------------------------------------------------- #
def _question(qname: str, qtype: str = "A") -> bytes:
    from dnslib import DNSRecord
    return DNSRecord.question(qname, qtype).pack()


@pytest.fixture
def gateway():
    engine = ChronoEngine()
    return ChronoGateway(engine, get_config())


async def test_malformed_packet_is_dropped_not_crashed(gateway):
    assert await gateway.handle_packet(b"\x00\x01garbage", "10.0.0.1", 5000, "udp") is None
    assert gateway.stats.malformed == 1


async def test_known_bad_zone_is_sinkholed(gateway):
    from dnslib import RCODE, DNSRecord

    gateway.cfg.detection.enforce = True
    # Force a block without needing a trained model or the database.
    # Note: the Debouncer captures its threshold at construction, so the
    # instance has to be updated too -- not just the config object.
    gateway.engine.policy.cfg.threshold_malicious = 0.10
    gateway.engine.policy.debouncer.hits = 1

    packet = _question(TUNNEL_PROBE, "A")
    reply = await gateway.handle_packet(packet, "10.0.0.1", 5000, "udp")
    assert reply is not None
    parsed = DNSRecord.parse(reply)
    assert parsed.header.qr == 1
    # Either a sinkhole A record or NXDOMAIN is an acceptable block.
    assert parsed.rr or parsed.header.rcode == RCODE.NXDOMAIN
    assert gateway.stats.blocked == 1


async def test_transaction_id_is_preserved_on_sinkhole(gateway):
    from dnslib import DNSRecord

    gateway.engine.policy.cfg.threshold_malicious = 0.10
    gateway.engine.policy.debouncer.hits = 1
    request = DNSRecord.question(TUNNEL_PROBE, "A")
    request.header.id = 0x4D2
    reply = await gateway.handle_packet(request.pack(), "10.0.0.1", 5000, "udp")
    assert DNSRecord.parse(reply).header.id == 0x4D2


def test_cached_answer_is_retagged_with_the_new_txid():
    original = struct.pack("!H", 0x1111) + b"rest-of-the-packet"
    retagged = ChronoGateway._retag(original, 0x2222)
    assert retagged[:2] == struct.pack("!H", 0x2222)
    assert retagged[2:] == original[2:]


async def test_gateway_snapshot_shape(gateway):
    snap = gateway.snapshot()
    for key in ("gateway", "cache", "upstream", "engine"):
        assert key in snap
    assert "qps" in snap["gateway"]
    assert "hit_rate" in snap["cache"]
