#!/usr/bin/env bash
# run_ieee_cis_realdata_grid.sh — small IEEE-CIS real-data-grounded grid.
#
# Real-data-grounded SUPPLEMENT (not the main proof experiment). Uses real IEEE-CIS transaction
# marginals + a CONSTRUCTED typed provenance authorization policy. isFraud is a diagnostic only.
#
# Usage:
#   INPUT_DIR=bridge_benchmark/data/raw/ieee_cis bash scripts/run_ieee_cis_realdata_grid.sh
#   # or, to smoke-test the plumbing without the real dataset:
#   INPUT_DIR=bridge_benchmark/data/fixtures/ieee_cis_tiny N_RECORDS=200 bash scripts/run_ieee_cis_realdata_grid.sh
#
# The full IEEE-CIS dataset is large; the default grid is deliberately small.
set -euo pipefail

INPUT_DIR="${INPUT_DIR:-bridge_benchmark/data/raw/ieee_cis}"
N_RECORDS="${N_RECORDS:-10000}"
THETA_Q="${THETA_Q:-0.70}"
OUT_ROOT="bridge_benchmark/cert/out/realdata_ieee_cis"
DATA_ROOT="bridge_benchmark/data/realdata"
mkdir -p "$OUT_ROOT" "$DATA_ROOT"

SAMPLINGS=("natural" "boundary_balanced" "c_targeted")
DELTAS=(0.04 0.08 0.12)
EPSILONS=(0.05 0.10)
SEEDS=(0 1 2)

for sampling in "${SAMPLINGS[@]}"; do
  for delta in "${DELTAS[@]}"; do
    for eps in "${EPSILONS[@]}"; do
      for seed in "${SEEDS[@]}"; do
        tag="${sampling}_d${delta}_e${eps}_s${seed}"
        recs="${DATA_ROOT}/ieee_cis_${tag}.jsonl"
        echo "=== generate ${tag} ==="
        python -m bridge_benchmark.experiments.realdata_ieee_cis \
          --input-dir "$INPUT_DIR" --out "$recs" \
          --sampling "$sampling" --n-records "$N_RECORDS" \
          --theta-quantile "$THETA_Q" --delta "$delta" --epsilon "$eps" --seed "$seed"
        echo "=== certify ${tag} ==="
        python -m bridge_benchmark.experiments.run_realdata_ieee_cis_cert \
          --records "$recs" --epsilon "$eps" --d 1 --sigma 0.10 --tau 0.90 \
          --n-mc 2000 --seed "$seed" --out "${OUT_ROOT}/${tag}"
      done
    done
  done
done
echo "grid complete -> ${OUT_ROOT}/"
