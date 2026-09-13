#!/usr/bin/env bash
# =============================================================================
#  Chrono-DNS :: health check
#  ---------------------------------------------------------------------
#  Verifies every moving part and prints a pass/fail matrix. Exit code is the
#  number of failed checks, so it drops straight into CI or a cron monitor.
#
#      ./scripts/healthcheck.sh
#      ./scripts/healthcheck.sh --gateway 127.0.0.1:5353
# =============================================================================
# NOTE: no `set -e` here on purpose — this script is *expected* to run
# commands that fail, and `((VAR++))` returns a non-zero status when the
# variable was 0, which would silently abort the run after the first check.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'
PASS=0; FAIL=0; SKIP=0
GATEWAY=""

for a in "$@"; do
  case "$a" in
    --gateway) shift; GATEWAY="${1:-}" ;;
    --gateway=*) GATEWAY="${a#*=}" ;;
  esac
done

check() {                      # check <label> <command...>
  local label="$1"; shift
  printf '  %-46s' "$label"
  if "$@" >/dev/null 2>&1; then printf '%s PASS %s\n' "$G" "$N"; PASS=$((PASS + 1)); return 0
  else printf '%s FAIL %s\n' "$R" "$N"; FAIL=$((FAIL + 1)); return 1; fi
}
soft() {                       # non-fatal check
  local label="$1"; shift
  printf '  %-46s' "$label"
  if "$@" >/dev/null 2>&1; then printf '%s PASS %s\n' "$G" "$N"; PASS=$((PASS + 1))
  else printf '%s SKIP %s\n' "$Y" "$N"; SKIP=$((SKIP + 1)); fi
}

[[ -d .venv ]] && source .venv/bin/activate || true
PY=python3

printf '\n%s%sChrono-DNS health check%s  %s%s%s\n\n' "$C" "$B" "$N" "$D" "$(date -u +%FT%TZ)" "$N"

printf '%senvironment%s\n' "$B" "$N"
check "python >= 3.10"            $PY -c 'import sys; assert sys.version_info>=(3,10)'
check "numpy"                     $PY -c 'import numpy'
check "scikit-learn"              $PY -c 'import sklearn'
check "rich"                      $PY -c 'import rich'
check "aiosqlite"                 $PY -c 'import aiosqlite'
soft  "dnslib (gateway)"          $PY -c 'import dnslib'
soft  "fastapi + uvicorn (web UI)" $PY -c 'import fastapi, uvicorn'
soft  "asyncpg (postgres backend)" $PY -c 'import asyncpg'

printf '\n%spackage%s\n' "$B" "$N"
check "chronodns imports"         $PY -c 'import chronodns'
check "feature set >= 100 dimensions" $PY -c 'from chronodns.features import FEATURE_COUNT; assert FEATURE_COUNT>=100'
check "CLI responds"              $PY -m chronodns --version
check "config loads"              $PY -c 'from chronodns.config import get_config; get_config()'

printf '\n%sdata plane%s\n' "$B" "$N"
check "database reachable"        $PY - <<'PY'
import asyncio
from chronodns.storage import make_database
async def m():
    db = make_database(); await db.connect()
    await db.fetchval("SELECT COUNT(*) FROM threat_intel"); await db.close()
asyncio.run(m())
PY
check "threat intel seeded"       $PY - <<'PY'
import asyncio
from chronodns.storage import make_database
async def m():
    db = make_database(); await db.connect()
    n = await db.fetchval("SELECT COUNT(*) FROM threat_intel"); await db.close()
    assert n and int(n) > 0
asyncio.run(m())
PY
soft  "trained model present"     $PY - <<'PY'
from chronodns.config import get_config
from chronodns.ml import ThreatEnsemble
m = ThreatEnsemble(); assert m.load(get_config().ml.model_dir)
PY

printf '\n%sdetection%s\n' "$B" "$N"
check "known tunnel scores high"  $PY - <<'PY'
import asyncio
from chronodns.engine import ChronoEngine
from chronodns.types import DNSQuery
async def m():
    e = ChronoEngine(); e.load_model()
    d = await e.analyse(DNSQuery(
        qname="mzxw6ytboi7dnnsxs3dbomruwm4tbm5uwy2ltebvgc4tfnzuw4zs.badzone.test",
        qtype="NULL"), persist=False)
    assert d.score > 0.5, d.score
asyncio.run(m())
PY
check "ordinary hostname scores low" $PY - <<'PY'
import asyncio
from chronodns.engine import ChronoEngine
from chronodns.types import DNSQuery
async def m():
    e = ChronoEngine(); e.load_model()
    d = await e.analyse(DNSQuery(qname="www.github.com", qtype="A"), persist=False)
    assert d.score < 0.45, d.score
asyncio.run(m())
PY

if [[ -n "$GATEWAY" ]]; then
  host="${GATEWAY%%:*}"; port="${GATEWAY##*:}"
  printf '\n%slive gateway (%s)%s\n' "$B" "$GATEWAY" "$N"
  if command -v dig >/dev/null 2>&1; then
    check "resolves a normal domain" dig +short +time=3 +tries=1 "@$host" -p "$port" example.com
    check "answers a tunnel probe"   dig +time=3 +tries=1 "@$host" -p "$port" \
          TXT mzxw6ytboi7dnnsxs3db.tunnel.example
  else
    printf '  %-46s%s SKIP %s (dig not installed)\n' "dns probes" "$Y" "$N"; SKIP=$((SKIP + 1))
  fi
fi

printf '\n%s%s  %d passed  %s%d failed%s  %s%d skipped%s\n\n' \
  "$B" "$N" "$PASS" "$( ((FAIL)) && echo "$R" || echo "$G" )" "$FAIL" "$N" "$Y" "$SKIP" "$N"
exit "$FAIL"
