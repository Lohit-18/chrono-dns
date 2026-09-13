#!/usr/bin/env bash
# =============================================================================
#  Chrono-DNS :: one-shot environment bootstrap
#  ---------------------------------------------------------------------
#  Creates a virtualenv, installs dependencies, writes .env from the example,
#  initialises the database and trains a first model.
#
#  Usage:
#      ./scripts/setup.sh                 # SQLite, zero external services
#      ./scripts/setup.sh --postgres      # also configure a PostgreSQL backend
#      ./scripts/setup.sh --no-train      # skip model training
#
#  Tested on Ubuntu 22.04/24.04 (including WSL2), Debian 12 and macOS 14.
# =============================================================================
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ---- pretty output ----------------------------------------------------------
if [[ -t 1 ]]; then
  B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; D=$'\e[2m'; N=$'\e[0m'
else
  B=""; G=""; Y=""; R=""; C=""; D=""; N=""
fi
step()  { printf '\n%s==>%s %s%s%s\n' "$C" "$N" "$B" "$*" "$N"; }
ok()    { printf '    %s[ok]%s %s\n'   "$G" "$N" "$*"; }
warn()  { printf '    %s[!!]%s %s\n'   "$Y" "$N" "$*"; }
die()   { printf '\n%s[fatal]%s %s\n'  "$R" "$N" "$*" >&2; exit 1; }

trap 'die "setup failed on line $LINENO"' ERR

USE_POSTGRES=0
DO_TRAIN=1
for arg in "$@"; do
  case "$arg" in
    --postgres) USE_POSTGRES=1 ;;
    --no-train) DO_TRAIN=0 ;;
    -h|--help)  sed -n '2,16p' "$0"; exit 0 ;;
    *)          die "unknown option: $arg" ;;
  esac
done

# ---- 1. python --------------------------------------------------------------
step "Checking Python"
PY=""
for candidate in python3.12 python3.11 python3.10 python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    ver="$("$candidate" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    major="${ver%%.*}"; minor="${ver##*.}"
    if (( major == 3 && minor >= 10 )); then PY="$candidate"; break; fi
  fi
done
[[ -n "$PY" ]] || die "Python 3.10+ is required. On Ubuntu/WSL: sudo apt install python3 python3-venv"
ok "using $($PY --version) at $(command -v "$PY")"

# ---- 2. virtualenv ----------------------------------------------------------
step "Creating virtual environment (.venv)"
if [[ ! -d .venv ]]; then
  "$PY" -m venv .venv 2>/dev/null || die "python3-venv is missing. Install it: sudo apt install python3-venv"
  ok "created .venv"
else
  ok ".venv already exists"
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --quiet --upgrade pip setuptools wheel
ok "pip $(pip --version | awk '{print $2}')"

# ---- 3. dependencies --------------------------------------------------------
step "Installing dependencies"
pip install --quiet -r requirements.txt
ok "core dependencies installed"
if (( USE_POSTGRES )); then
  pip install --quiet 'asyncpg>=0.29'
  ok "asyncpg installed (PostgreSQL backend)"
fi
pip install --quiet -e . >/dev/null 2>&1 && ok "chronodns installed in editable mode" \
  || warn "editable install skipped — use 'python -m chronodns' instead"

# ---- 4. configuration -------------------------------------------------------
step "Configuring"
if [[ ! -f .env ]]; then
  cp .env.example .env
  ok "wrote .env from .env.example"
else
  ok ".env already present (left untouched)"
fi

if (( USE_POSTGRES )); then
  if command -v psql >/dev/null 2>&1; then
    ok "psql found: $(psql --version)"
    warn "make sure the role and database exist, then set CHRONODNS_DB_BACKEND=postgres in .env"
    printf '    %s%s%s\n' "$D" "sudo -u postgres psql -c \"CREATE USER chronodns WITH PASSWORD 'chronodns';\"" "$N"
    printf '    %s%s%s\n' "$D" "sudo -u postgres psql -c \"CREATE DATABASE chronodns OWNER chronodns;\"" "$N"
  else
    warn "PostgreSQL client not found. Install it:  sudo apt install postgresql postgresql-client"
  fi
fi

mkdir -p data models data/logs
ok "data/ models/ ready"

# ---- 5. database ------------------------------------------------------------
step "Initialising the database"
python -m chronodns init --reset >/dev/null
ok "schema, indexes, views and seed threat intel applied"

# ---- 6. model ---------------------------------------------------------------
if (( DO_TRAIN )); then
  step "Training the detection model (this takes ~20 seconds)"
  python -m chronodns --quiet-log train --harden >/dev/null
  ok "model trained and saved to models/"
else
  warn "training skipped (--no-train)"
fi

# ---- 7. done ----------------------------------------------------------------
cat <<EOF

${G}${B}Chrono-DNS is ready.${N}

  ${D}activate the environment${N}
    source .venv/bin/activate

  ${D}see everything work in one command${N}
    chronodns demo

  ${D}animated SOC console${N}
    chronodns live

  ${D}run the real DNS gateway, then point dig at it${N}
    chronodns serve
    dig @127.0.0.1 -p 5353 github.com
    dig @127.0.0.1 -p 5353 TXT mzxw6ytboi7dnnsxs3db.tunnel.example

  ${D}web dashboard${N}
    chronodns dashboard    ${D}# http://127.0.0.1:8088${N}

EOF
