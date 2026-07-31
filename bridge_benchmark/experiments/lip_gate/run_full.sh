#!/usr/bin/env bash
# EXP_LIP_VS_RS full run (finance/sre/ops, eps {0.03,0.10}, n_mc {1500,2000,10000}).
set -e
cd "$(dirname "$0")"
python scripts/compare_smoothing_vs_lip.py --domains finance,sre,ops --n-train 1500 --n-eval 400 \
  --per-cat 80 --eps-list 0.03,0.10 --mc-list 1500,2000,10000 --variant robust-aug
python scripts/decompose_recovery_deficit.py
python scripts/measure_runtime.py --domain finance --eps 0.10 --n 60 --mc-list 1500,2000,10000
python scripts/make_delta_epsilon_geometry.py --domains finance,sre,ops --n 2000
python scripts/make_tables.py
