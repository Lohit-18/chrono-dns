#!/usr/bin/env bash
# =============================================================================
#  Chrono-DNS :: live attack simulation against a running gateway
#  ---------------------------------------------------------------------
#  Fires real DNS packets at your own Chrono-DNS instance with `dig`, so you
#  can watch detection happen in the gateway's console in real time.
#
#  This only ever queries reserved/lab zones (.example, .test, .invalid) that
#  cannot resolve on the public internet, and only against the resolver you
#  point it at. It is a test harness, not an attack tool.
#
#      ./scripts/attack_sim.sh                       # 127.0.0.1:5353
#      ./scripts/attack_sim.sh 127.0.0.1 5353 tunnel
#      ./scripts/attack_sim.sh 127.0.0.1 5353 all
# =============================================================================
set -Eeuo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-5353}"
MODE="${3:-all}"

G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'
command -v dig >/dev/null || { echo "dig not found: sudo apt install dnsutils"; exit 1; }

q() {                                    # q <type> <name>
  local out rc
  out="$(dig +short +time=2 +tries=1 "@$HOST" -p "$PORT" "$1" "$2" 2>&1)" || rc=$?
  if [[ "$out" == *"0.0.0.0"* ]]; then
    printf '  %sBLOCKED %s %s\n' "$R" "$N" "${2:0:72}"
  elif [[ -z "$out" ]]; then
    printf '  %sNXDOMAIN%s %s\n' "$Y" "$N" "${2:0:72}"
  else
    printf '  %sallowed %s %s\n' "$G" "$N" "${2:0:72}"
  fi
}

rand() { head -c "$1" /dev/urandom | base32 2>/dev/null | tr -d '=\n' \
         | tr '[:upper:]' '[:lower:]' | head -c "$1"; }

printf '\n%s%sattack simulation -> %s:%s%s\n' "$C" "$B" "$HOST" "$PORT" "$N"
printf '%sall target zones are RFC-reserved and unresolvable on the internet%s\n\n' "$D" "$N"

if [[ "$MODE" == "benign" || "$MODE" == "all" ]]; then
  printf '%s[1] baseline: ordinary traffic%s\n' "$B" "$N"
  for d in github.com www.google.com api.cloudflare.com cdn.jsdelivr.net; do q A "$d"; done
  echo
fi

if [[ "$MODE" == "tunnel" || "$MODE" == "all" ]]; then
  printf '%s[2] DNS tunnelling: long base32 labels on high-capacity records%s\n' "$B" "$N"
  for _ in $(seq 1 8); do q TXT "$(rand 55).$(rand 20).tunnel.example"; done
  echo
  printf '%s[3] file exfiltration: sequenced chunks under one zone%s\n' "$B" "$N"
  for i in $(seq 1 10); do
    q TXT "$(printf '%04x' "$i").$(rand 48).exfil.example"
  done
  echo
fi

if [[ "$MODE" == "dga" || "$MODE" == "all" ]]; then
  printf '%s[4] DGA storm: many unrelated random zones%s\n' "$B" "$N"
  for _ in $(seq 1 12); do q A "$(rand 14).example"; done
  echo
fi

if [[ "$MODE" == "beacon" || "$MODE" == "all" ]]; then
  printf '%s[5] C2 beacon: fixed 3s interval, watch the jitter collapse%s\n' "$B" "$N"
  for _ in $(seq 1 6); do
    q TXT "$(rand 12).c2.example"
    sleep 3
  done
  echo
fi

printf '%sdone. Now look at what the gateway recorded:%s\n' "$D" "$N"
printf '  chronodns report --minutes 10\n'
printf '  chronodns hunt tunnels\n'
printf '  chronodns hunt beacons\n\n'
