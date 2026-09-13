#!/usr/bin/env bash
# =============================================================================
#  Chrono-DNS :: database provisioning
#  ---------------------------------------------------------------------
#  SQLite  : creates data/chronodns.db and applies sql/sqlite/*.sql
#  Postgres: creates role + database if missing, then applies sql/postgres/*.sql
#
#  Usage:
#      ./scripts/init_db.sh                    # use whatever .env says
#      ./scripts/init_db.sh --postgres         # force the PostgreSQL path
#      ./scripts/init_db.sh --reset            # drop everything first
#      ./scripts/init_db.sh --postgres --create-role
# =============================================================================
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; N=$'\e[0m'
step() { printf '\n%s==>%s %s%s%s\n' "$C" "$N" "$B" "$*" "$N"; }
ok()   { printf '    %s[ok]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '    %s[!!]%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%s[fatal]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

# shellcheck disable=SC1091
[[ -f .env ]] && set -a && source .env && set +a

FORCE_PG=0; RESET=0; CREATE_ROLE=0
for a in "$@"; do
  case "$a" in
    --postgres)    FORCE_PG=1 ;;
    --reset)       RESET=1 ;;
    --create-role) CREATE_ROLE=1 ;;
    -h|--help)     sed -n '2,15p' "$0"; exit 0 ;;
    *) die "unknown option: $a" ;;
  esac
done

BACKEND="${CHRONODNS_DB_BACKEND:-sqlite}"
(( FORCE_PG )) && BACKEND="postgres"

PGHOST="${CHRONODNS_PG_HOST:-127.0.0.1}"
PGPORT="${CHRONODNS_PG_PORT:-5432}"
PGUSER="${CHRONODNS_PG_USER:-chronodns}"
PGPASS="${CHRONODNS_PG_PASSWORD:-chronodns}"
PGDB="${CHRONODNS_PG_DATABASE:-chronodns}"

if [[ "$BACKEND" == "postgres" ]]; then
  step "PostgreSQL backend -> ${PGUSER}@${PGHOST}:${PGPORT}/${PGDB}"
  command -v psql >/dev/null || die "psql not found: sudo apt install postgresql-client"

  if (( CREATE_ROLE )); then
    step "Creating role and database (needs local superuser access)"
    sudo -u postgres psql -v ON_ERROR_STOP=0 <<SQL || warn "role/database step reported errors (often 'already exists')"
CREATE USER ${PGUSER} WITH PASSWORD '${PGPASS}';
CREATE DATABASE ${PGDB} OWNER ${PGUSER};
GRANT ALL PRIVILEGES ON DATABASE ${PGDB} TO ${PGUSER};
SQL
    ok "role/database provisioning attempted"
  fi

  export PGPASSWORD="$PGPASS"
  psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDB" -c 'SELECT 1' >/dev/null \
    || die "cannot connect. Try: ./scripts/init_db.sh --postgres --create-role"
  ok "connection verified"

  if (( RESET )); then
    step "Dropping schema chrono"
    psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDB" \
         -c 'DROP SCHEMA IF EXISTS chrono CASCADE;' >/dev/null
    ok "schema dropped"
  fi

  step "Applying migrations"
  for f in sql/postgres/*.sql; do
    printf '    %-34s' "$(basename "$f")"
    if psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDB" \
            -v ON_ERROR_STOP=1 -q -f "$f" >/dev/null 2>&1; then
      printf '%s[ok]%s\n' "$G" "$N"
    else
      printf '%s[warn]%s (re-run with --reset if this is a partial apply)\n' "$Y" "$N"
    fi
  done

  step "Verifying"
  psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDB" -c "
    SELECT table_name, (xpath('/row/c/text()',
      query_to_xml(format('SELECT COUNT(*) AS c FROM chrono.%I', table_name),
                   false, true, '')))[1]::text::int AS rows
    FROM information_schema.tables
    WHERE table_schema = 'chrono' AND table_type = 'BASE TABLE'
    ORDER BY table_name;"
else
  step "SQLite backend -> ${CHRONODNS_SQLITE_PATH:-data/chronodns.db}"
  ARGS=(); (( RESET )) && ARGS+=(--reset)
  python3 -m chronodns init "${ARGS[@]}"
fi

printf '\n%sdatabase ready.%s  Next: %schronodns train%s\n\n' "$G$B" "$N" "$C" "$N"
