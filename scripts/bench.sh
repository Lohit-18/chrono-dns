#!/usr/bin/env bash
# =============================================================================
#  Chrono-DNS :: benchmark sweep
#  ---------------------------------------------------------------------
#  Runs the throughput benchmark at several dataset sizes and writes a
#  machine-readable summary to data/bench.csv, so you can show scaling
#  behaviour rather than a single number.
#
#      ./scripts/bench.sh
#      ./scripts/bench.sh 1000 5000 20000
# =============================================================================
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
[[ -d .venv ]] && source .venv/bin/activate || true

C=$'\e[36m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'
SIZES=("$@"); [[ ${#SIZES[@]} -eq 0 ]] && SIZES=(1000 3000 9000)

OUT=data/bench.csv
mkdir -p data
echo "n,extract_qps,score_qps,pipeline_qps,ms_per_query" > "$OUT"

printf '\n%s%sChrono-DNS benchmark sweep%s\n' "$C" "$B" "$N"
printf '%shost: %s | cpus: %s | python: %s%s\n\n' "$D" "$(uname -srm)" \
  "$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo '?')" \
  "$(python3 -V 2>&1 | awk '{print $2}')" "$N"

for n in "${SIZES[@]}"; do
  printf '%s── n = %s ─────────────────────────────────────%s\n' "$D" "$n" "$N"
  python3 - "$n" "$OUT" <<'PY'
import sys, time
from chronodns.datagen import DatasetBuilder
from chronodns.engine import ChronoEngine
from chronodns.logging_utils import setup_logging

setup_logging("ERROR")
n, out = int(sys.argv[1]), sys.argv[2]
eng = ChronoEngine(); eng.load_model()
qs = DatasetBuilder(1337).build()
while len(qs) < n:
    qs += DatasetBuilder(len(qs)).build()
qs = qs[:n]

t = time.perf_counter(); m, f = eng.extractor.batch(qs); t_ex = time.perf_counter() - t
t = time.perf_counter(); eng.model.score_batch(m, f);    t_sc = time.perf_counter() - t
t = time.perf_counter(); eng.analyse_batch_fast(qs);     t_pl = time.perf_counter() - t

print(f"  extraction {n/t_ex:10,.0f} q/s   scoring {n/t_sc:10,.0f} q/s"
      f"   pipeline {n/t_pl:10,.0f} q/s   {1000*t_pl/n:.4f} ms/query")
with open(out, "a") as fh:
    fh.write(f"{n},{n/t_ex:.1f},{n/t_sc:.1f},{n/t_pl:.1f},{1000*t_pl/n:.5f}\n")
PY
done

printf '\n%swrote %s%s\n\n' "$D" "$OUT" "$N"
column -s, -t "$OUT" 2>/dev/null || cat "$OUT"
