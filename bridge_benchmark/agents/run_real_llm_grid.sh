#!/bin/bash
# run_real_llm_grid.sh — Experiment F driver: run the real-LLM action-proposal grid
# (2 domains x {clean, c_witness} x {none, learned, certified, oracle}) and evaluate it.
#
# The certified object is ONLY the post-tool-return gate. The LLM merely proposes an action; the
# runtime always calls the gate. A disk proposal cache makes the 4 gates reuse one set of generations.
#
#   bash bridge_benchmark/agents/run_real_llm_grid.sh                       # default: qwen2.5:7b via ollama
#   MODEL=qwen2.5:32b TAG=qwen32b bash bridge_benchmark/agents/run_real_llm_grid.sh
#   BACKEND=vllm MODEL=Qwen/Qwen2.5-Coder-32B-Instruct ENDPOINT=http://localhost:8000/v1 \
#       TAG=coder32b bash bridge_benchmark/agents/run_real_llm_grid.sh
#   BACKEND=mock MODEL=mock TAG=mock bash bridge_benchmark/agents/run_real_llm_grid.sh
#
# Env knobs (with defaults):
#   BACKEND   ollama | vllm | mock                 (default ollama)
#   MODEL     model name/tag for the backend        (default qwen2.5:7b-instruct)
#   ENDPOINT  server base URL                        (default http://127.0.0.1:11434 for ollama)
#   TAG       output filename prefix                 (default qwen7b)
#   N         records per category                   (default 200)
#   TAU SIGMA EPS NMC   certificate hyperparameters  (default 0.90 0.10 0.10 2000)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"

BACKEND="${BACKEND:-ollama}"
MODEL="${MODEL:-qwen2.5:7b-instruct}"
ENDPOINT="${ENDPOINT:-http://127.0.0.1:11434}"
TAG="${TAG:-qwen7b}"
N="${N:-200}"
TAU="${TAU:-0.90}"; SIGMA="${SIGMA:-0.10}"; EPS="${EPS:-0.10}"; NMC="${NMC:-2000}"
OUTD="bridge_benchmark/cert/out/real_llm_action_exp"
mkdir -p "$OUTD"

echo "grid: backend=$BACKEND model=$MODEL tag=$TAG n/cat=$N  (tau=$TAU sigma=$SIGMA eps=$EPS n_mc=$NMC)"
for attack in clean c_witness; do
  for gate in none learned certified oracle; do
    echo "=== gate=$gate attack=$attack ==="
    python -m bridge_benchmark.agents.real_llm_action_exp \
      --domain both --categories C,R,U --attack "$attack" --gate "$gate" \
      --llm-backend "$BACKEND" --model "$MODEL" --endpoint "$ENDPOINT" \
      --n-per-category "$N" --pool 9000 --seed 0 \
      --tau "$TAU" --sigma "$SIGMA" --epsilon "$EPS" --n-mc "$NMC" \
      --out "$OUTD/${TAG}_${gate}_${attack}.jsonl" 2>&1 | grep -vE "Warning|FutureWarning|warnings.warn" || true
  done
done

echo "=== EVALUATE ==="
python -m bridge_benchmark.agents.evaluate_real_llm_exp \
  --inputs "$OUTD/${TAG}_*.jsonl" \
  --out-csv "$OUTD/summary_${TAG}.csv" \
  --out-md  "$OUTD/summary_${TAG}.md" 2>&1 | grep -vE "Warning|warn" || true
echo "GRID DONE -> $OUTD/summary_${TAG}.{csv,md}"
