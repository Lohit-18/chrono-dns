"""Storage-layer tests: schema, write-behind buffer, intel cache, SQL analytics."""

from __future__ import annotations

import time

import pytest

from chronodns.storage import Repository, init_schema, make_database
from chronodns.storage.db import SQLiteDatabase, _to_pg, split_statements
from chronodns.types import Detection, DNSQuery, ThreatClass, Verdict


@pytest.fixture
async def repo(tmp_path):
    db = SQLiteDatabase(str(tmp_path / "test.db"))
    await db.connect()
    await init_schema(db)
    r = Repository(db, batch_size=1000, flush_interval=30.0)
    await r.start()
    yield r
    await r.close()
    await db.close()


def _detection(qname="a.b.example.com", score=0.9, verdict=Verdict.BLOCK,
               ts=None, ip="10.0.0.1", label=None):
    q = DNSQuery(qname=qname, qtype="TXT", source_ip=ip,
                 timestamp=ts if ts is not None else time.time(), label=label)
    d = Detection(query=q, verdict=verdict, score=score,
                  threat_class=ThreatClass.TUNNELING)
    d.features = {"shannon_entropy_full": 4.2, "shannon_entropy_sub": 4.4}
    return d


# --------------------------------------------------------------------------- #
# dialect helpers
# --------------------------------------------------------------------------- #
def test_placeholder_rewrite_for_postgres():
    assert _to_pg("SELECT * FROM t WHERE a=? AND b=?") == \
        "SELECT * FROM t WHERE a=$1 AND b=$2"


def test_placeholder_rewrite_ignores_question_marks_in_strings():
    sql = "SELECT ? WHERE note = 'what? really' AND x = ?"
    assert _to_pg(sql) == "SELECT $1 WHERE note = 'what? really' AND x = $2"


def test_statement_splitter_respects_function_bodies():
    script = """
    CREATE TABLE a (id INT);
    CREATE FUNCTION f() RETURNS INT LANGUAGE plpgsql AS $$
    BEGIN
      RETURN 1;
    END;
    $$;
    CREATE TABLE b (id INT);
    """
    stmts = split_statements(script)
    assert len(stmts) == 3
    assert "RETURN 1;" in stmts[1]


# --------------------------------------------------------------------------- #
# schema
# --------------------------------------------------------------------------- #
async def test_schema_creates_every_table(repo):
    for table in ("dns_events", "threat_intel", "allowlist", "domain_baseline",
                  "alerts", "model_registry", "gateway_stats"):
        assert await repo.db.fetchval(f"SELECT COUNT(*) FROM {table}") is not None


async def test_seed_data_loaded(repo):
    assert int(await repo.db.fetchval("SELECT COUNT(*) FROM threat_intel")) > 10
    assert int(await repo.db.fetchval("SELECT COUNT(*) FROM allowlist")) > 10


async def test_views_exist(repo):
    for view in ("v_recent_threats", "v_top_talkers", "v_tunnel_candidates",
                 "v_beacon_candidates", "v_host_velocity", "v_hourly_rollup"):
        await repo.db.fetch(f"SELECT * FROM {view} LIMIT 1")


# --------------------------------------------------------------------------- #
# write path
# --------------------------------------------------------------------------- #
async def test_events_are_buffered_then_flushed(repo):
    for i in range(20):
        await repo.record(_detection(qname=f"h{i}.example.com"))
    assert int(await repo.db.fetchval("SELECT COUNT(*) FROM dns_events")) == 0
    written = await repo.flush()
    assert written == 20
    assert int(await repo.db.fetchval("SELECT COUNT(*) FROM dns_events")) == 20


async def test_alerts_deduplicate_by_fingerprint(repo):
    for _ in range(50):
        await repo.raise_alert("10.0.0.7", "tunnel.example", "tunneling", 0.91, 40)
    await repo.flush_alerts()
    rows = await repo.db.fetch("SELECT hit_count, bytes_exfil, severity FROM alerts")
    assert len(rows) == 1
    assert rows[0]["hit_count"] == 50
    assert rows[0]["bytes_exfil"] == 2000


async def test_baseline_upsert_updates_running_mean(repo):
    for entropy in (2.0, 4.0):
        await repo.upsert_baseline("example.com", entropy, 20)
    row = await repo.db.fetchrow(
        "SELECT query_count, mean_entropy FROM domain_baseline WHERE registrable='example.com'")
    assert row["query_count"] >= 2


# --------------------------------------------------------------------------- #
# intel + allowlist
# --------------------------------------------------------------------------- #
async def test_allowlist_matches_suffixes(repo):
    assert repo.is_allowlisted("static.cloudfront.net")
    assert repo.is_allowlisted("cloudfront.net")
    assert not repo.is_allowlisted("evil.tunnel.example")


async def test_intel_lookup_by_zone_and_tld(repo):
    zone = repo.intel_lookup_sync("x.tunnel.example", "tunnel.example", "example")
    assert zone and zone["category"] == "tunnel"
    tld = repo.intel_lookup_sync("something.tk", "something.tk", "tk")
    assert tld and tld["ioc_type"] == "tld"
    assert repo.intel_lookup_sync("www.github.com", "github.com", "com") is None


async def test_adding_intel_refreshes_the_cache(repo):
    await repo.add_intel("newbad.test", "zone", "c2", 9)
    await repo.refresh_caches()
    hit = repo.intel_lookup_sync("a.newbad.test", "newbad.test", "test")
    assert hit and hit["severity"] == 9


# --------------------------------------------------------------------------- #
# analytics
# --------------------------------------------------------------------------- #
async def test_summary_and_breakdowns(repo):
    base = time.time()
    for i in range(40):
        await repo.record(_detection(
            qname=f"chunk{i}.tunnel.example", ts=base + i, label="tunneling"))
    await repo.flush()

    summary = await repo.summary(minutes=10_000)
    assert int(summary["events"]) == 40
    assert int(summary["blocked"]) == 40

    classes = await repo.class_breakdown(minutes=10_000)
    assert any(c["threat_class"] == "tunneling" for c in classes)

    talkers = await repo.top_talkers(minutes=10_000)
    assert talkers[0]["queries"] == 40


async def test_beacon_window_function_finds_regular_intervals(repo):
    base = 1_700_000_000.0
    for i in range(15):                       # perfectly periodic
        await repo.record(_detection(qname=f"t{i}.c2.example", ts=base + i * 60.0,
                                     ip="10.0.0.50"))
    for i in range(15):                       # highly irregular
        await repo.record(_detection(qname=f"u{i}.news.example",
                                     ts=base + i * i * 3.7, ip="10.0.0.51"))
    await repo.flush()

    rows = await repo.beacon_candidates(limit=10)
    assert rows
    best = rows[0]
    assert best["source_ip"] == "10.0.0.50"
    assert best["interval_s"] == pytest.approx(60.0, abs=1.0)


async def test_tunnel_candidates_rank_by_uploaded_bytes(repo):
    base = time.time()
    for i in range(30):
        await repo.record(_detection(
            qname=f"{'x' * 50}{i}.tunnel.example", ts=base + i * 0.1))
    await repo.flush()
    rows = await repo.tunnel_candidates(minutes=10_000)
    assert rows and rows[0]["registrable"] == "tunnel.example"
    assert rows[0]["bytes_uploaded"] > 1000


async def test_search_and_timeline(repo):
    await repo.record(_detection(qname="needle.haystack.example"))
    await repo.flush()
    assert await repo.search("needle")
    assert isinstance(await repo.timeline(minutes=10_000), list)


async def test_make_database_honours_backend_setting():
    db = make_database()
    assert db.dialect in ("sqlite", "postgres")
