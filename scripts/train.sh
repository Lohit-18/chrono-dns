#!/usr/bin/env bash
# =============================================================================
#  Chrono-DNS :: full training + validation run
#  ---------------------------------------------------------------------
#  Trains the model, runs the adversarial evaluation and the feature ablation
#  study, and archives every artefact under models/runs/<timestamp>/ so you
#  have a reproducible record of each experiment.
#
#      ./scripts/train.sh
#      ./scripts/train.sh --quick        # skip the ablation sweep
# =============================================================================
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
[[ -d .venv ]] && source .venv/bin/activate || true

C=$'\e[36m'; G=$'\e[32m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'
QUICK=0; [[ "${1:-}" == "--quick" ]] && QUICK=1

STAMP="$(date -u +%Y%m%d-%H%M%S)"
RUN="models/runs/$STAMP"
mkdir -p "$RUN"

step() { printf '\n%s==>%s %s%s%s\n' "$C" "$N" "$B" "$*" "$N"; }

step "1/5  generating dataset"
python3 -m chronodns --quiet-log dataset --out "$RUN/capture.csv" --evasive 300 | tee "$RUN/dataset.txt"

step "2/5  training (with adversarial hardening)"
python3 -m chronodns --quiet-log train --data "$RUN/capture.csv" --harden | tee "$RUN/train.txt"

step "3/5  adversarial evaluation"
python3 -m chronodns --quiet-log evade --count 300 --seed 4242 | tee "$RUN/evade.txt"

if (( ! QUICK )); then
  step "4/5  feature ablation study"
  python3 -m chronodns --quiet-log ablate | tee "$RUN/ablate.txt"
else
  step "4/5  ablation skipped (--quick)"
fi

step "5/5  archiving artefacts"
cp -f models/chronodns_model.joblib "$RUN/" 2>/dev/null || true
cp -f models/model_card.json        "$RUN/" 2>/dev/null || true
cp -f models/train_report.json      "$RUN/" 2>/dev/null || true
{
  echo "run:        $STAMP"
  echo "host:       $(uname -srm)"
  echo "python:     $(python3 -V 2>&1)"
  echo "sklearn:    $(python3 -c 'import sklearn;print(sklearn.__version__)')"
  echo "git:        $(git rev-parse --short HEAD 2>/dev/null || echo 'not a repo')"
} > "$RUN/environment.txt"

printf '\n%s%srun archived -> %s%s\n' "$G" "$B" "$RUN" "$N"
ls -la "$RUN"
