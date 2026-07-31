#!/usr/bin/env bash
# EXP_LIP_VS_RS quick run (finance only, eps 0.10, reduced n_mc) — sanity, ~1-2 min on GPU.
set -e
cd "$(dirname "$0")"
python scripts/compare_smoothing_vs_lip.py --domains finance --n-train 1000 --n-eval 300 \
  --per-cat 60 --eps-list 0.03,0.10 --mc-list 1500,2000 --variant robust-aug
python scripts/decompose_recovery_deficit.py
python scripts/measure_runtime.py --domain finance --eps 0.10 --n 40 --mc-list 1500,2000
python scripts/make_delta_epsilon_geometry.py --domains finance --n 1500
python scripts/make_tables.py
