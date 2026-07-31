# NAB (Numenta Anomaly Benchmark) — second real dataset (non-finance telemetry)

This directory holds the **real cloud-CPU telemetry** used by the T2-7 "second real dataset"
experiment (`bridge_benchmark/experiments/second_real_dataset.py`), the non-finance counterpart to the
IEEE-CIS finance experiment. It closes the "cherry-picked finance" objection: all prior real data was
finance (IEEE-CIS); this instantiates the **monitoring / SRE** domain on genuine operational metrics.

## Source & license

- **Source:** Numenta Anomaly Benchmark, <https://github.com/numenta/NAB> (`numenta/NAB`, `master`).
- **License:** **MIT** (see `LICENSE.txt`, downloaded from the repo root).
- **Downloaded via** `bridge_benchmark/realdata/nab_adapter.py::download_if_absent` from the public
  GitHub raw endpoint (`raw.githubusercontent.com/numenta/NAB/master/...`). Cached here; **gitignored**
  (`data/`, `labels/`, `LICENSE.txt`). Really downloaded — not fabricated. To (re)fetch:
  `python bridge_benchmark/experiments/second_real_dataset.py --download --quick`.

## Files (regenerable, gitignored)

- `data/realAWSCloudwatch/ec2_cpu_utilization_*.csv` (8 EC2 machines) and `rds_cpu_utilization_*.csv`
  (2 RDS machines): real AWS CloudWatch **CPU-utilization %**, 5-minute cadence, 4032 points each.
- `data/realKnownCause/cpu_utilization_asg_misconfiguration.csv`: real CPU trace of an auto-scaling-
  group misconfiguration (18050 points).
- `labels/combined_windows.json`: NAB's human-labeled **anomaly windows** per series.
- Total ≈ **58,370 real telemetry rows across 11 machines**.

## What is real vs constructed

- **REAL:** the CPU-utilization values (genuine EC2/RDS % load) and the NAB anomaly windows.
- **CONSTRUCTED:** the typed authorization policy — provenance/env monitoring endpoints, the
  provenance-conditioned threshold θ_t(x1), and `Safe(z, a)`. Built by `nab_policy.py` and labeled by
  the **same analytic oracle** (`generators/oracle.py`, scalar-threshold family) used everywhere else.

## Policy construction (mirrors the IEEE-CIS adapter)

- **Continuous field (policy-binding):** `cpu_util_norm = CPU% / 100 ∈ [0,1]`. Other x2 fields
  (`roll_mean_norm`, `roll_std_norm`, `delta_norm`, `max_recent_norm`, `min_recent_norm`) are real
  rolling-window aggregates used as gate features (not policy-binding).
- **Provenance context s:** each telemetry return is routed through one of four monitoring endpoints —
  loose (`staging_metrics_loose`, `dev_telemetry_loose`) or strict (`prod_metrics_strict`,
  `oncall_monitor_strict`). Loose endpoints tolerate higher CPU before suppression is unsafe →
  threshold `θ_base + δ`; strict → `θ_base`. Assignment is per-observation (a machine's readings can be
  scraped by a staging or a prod collector), deterministic in the seed.
- **Action:** `suppress_alert` (privileged; **unsafe iff cpu_util_norm ≥ θ_env**, i.e. suppressing an
  alert on a genuinely high-load reading) with the safe fallback `page_on_call`.
- **θ_base** is grounded in the **real gate-pool CPU quantile** (default q=0.70), δ=0.08, ε=0.10, d=1.
- **d=1 discrete swap** = a related-pair provenance mislabel (loose↔strict, i.e. wrong environment).
  A **Category-C witness** is a real reading safe under its loose endpoint but unsafe under the strict
  swap after an ≤ε CPU move — the analytic C-interval has length `min(δ, ε)`.

## Caveat

This is a **constructed authorization policy on real telemetry**, NOT a deployed monitoring policy, NOT
certified anomaly detection, and NOT end-to-end LLM-agent robustness. The NAB anomaly label is used
only as an external plausibility diagnostic (the monitoring analogue of IEEE-CIS `isFraud`), never as a
certification label.
