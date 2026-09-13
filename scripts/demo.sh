#!/usr/bin/env bash
# =============================================================================
#  Chrono-DNS :: guided demo
#  ---------------------------------------------------------------------
#  Runs the whole pipeline with pauses and narration. This is the script to
#  run when someone says "show me what it does".
#
#      ./scripts/demo.sh              # interactive, pauses between acts
#      ./scripts/demo.sh --fast       # no pauses
#      ./scripts/demo.sh --record     # also writes docs/demo_output.txt
# =============================================================================
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

B=$'\e[1m'; C=$'\e[36m'; G=$'\e[32m'; Y=$'\e[33m'; D=$'\e[2m'; N=$'\e[0m'
FAST=0; RECORD=0
for a in "$@"; do
  case "$a" in
    --fast) FAST=1 ;;
    --record) RECORD=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
  esac
done

[[ -d .venv ]] && source .venv/bin/activate || true
CDNS="python3 -m chronodns --quiet-log"

pause() { (( FAST )) && return 0; printf '\n%s   [enter to continue]%s' "$D" "$N"; read -r; }
act()   { printf '\n\n%s%s══ %s ══%s\n\n' "$C" "$B" "$1" "$N"; }
note()  { printf '%s%s%s\n' "$D" "$1" "$N"; }

clear 2>/dev/null || true
cat <<'BANNER'
   ______ __                             ____  _   _ _____
  / ____// /_   _____ ____   ____   ____ / __ \/ | / // ___/
 / /    / __ \ / ___// __ \ / __ \ / __ \/ / / /  |/ / \__ \
/ /___ / / / // /   / /_/ // / / // /_/ / /_/ / /|  / ___/ /
\____//_/ /_//_/    \____//_/ /_/ \____/_____/_/ |_/ /____/
BANNER
printf '\n  %sDetecting DNS tunnelling, DGA and C2 beaconing with ML + SQL%s\n' "$D" "$N"
pause

act "ACT 1 — the database"
note "Schema, indexes, analytical views and a seeded local threat-intel feed."
$CDNS init --reset
pause

act "ACT 2 — the traffic"
note "A synthetic enterprise capture: real users browsing, plus three tunnelling"
note "tools, six DGA families and three C2 implants sharing the same wire."
$CDNS dataset --out data/capture.csv
pause

act "ACT 3 — the model"
note "Random Forest (known attacks) + Isolation Forest (zero-day) over 102 features."
$CDNS train --harden
pause

act "ACT 4 — one query, fully explained"
note "Every decision is auditable: which voter objected, and on what evidence."
$CDNS explain "mzxw6ytboi7dnnsxs3dbomruwm4tbm5uwy2ltebvgc4tfnzuw4zs.tunnel.example" --qtype NULL
pause
note "...and the same pipeline on a legitimate CDN hostname that *looks* random:"
$CDNS explain "e4821-a9f3c2d1b7e.akamaiedge.net"
pause

act "ACT 5 — replay the whole capture through the inline engine"
note "This is the exact code path the live DNS gateway runs, packet for packet."
$CDNS replay --data data/capture.csv --fresh --top 10
pause

act "ACT 6 — hard mode"
note "An adversary who has read the detection logic. The honest number."
$CDNS evade --count 250
pause

act "ACT 7 — the SOC report, straight out of SQL"
$CDNS report
pause

act "ACT 8 — threat hunting with window functions"
note "LAG() over (PARTITION BY host, zone ORDER BY ts) finds the metronomes."
$CDNS hunt beacons --limit 10
note ""
note "Note that legitimate update pollers show up here too — this query is a"
note "lead generator for an analyst, not a blocking decision. The ML makes that."
pause

act "ACT 9 — throughput"
$CDNS bench --count 6000
pause

printf '\n%s%sDemo complete.%s\n\n' "$G" "$B" "$N"
printf '  %schronodns live%s        animated SOC console\n' "$C" "$N"
printf '  %schronodns serve%s       real DNS gateway on 127.0.0.1:5353\n' "$C" "$N"
printf '  %schronodns dashboard%s   web UI on http://127.0.0.1:8088\n\n' "$C" "$N"

if (( RECORD )); then
  mkdir -p docs
  note "re-running non-interactively into docs/demo_output.txt ..."
  ( FAST=1; "$0" --fast ) | sed 's/\x1b\[[0-9;]*m//g' > docs/demo_output.txt
  printf '  wrote docs/demo_output.txt\n\n'
fi
