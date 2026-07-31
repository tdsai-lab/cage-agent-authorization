# experiments/ — controlled scaling & realism study

Beyond the MVP correctness/ablation, this block proves the three things a paper needs:

1. **Category C exists systematically** (not a hand-crafted artifact);
2. **R_allow stays non-vacuous at scale**;
3. **marginal / naive certificates fail reproducibly**, while the hybrid
  `enumerate_discrete_gaussian_rs` certificate stays **sound** (`C_allow = cert_false_allow = 0`).

It is a controlled *typed-tool* study — **no LLM, no live MCP execution**. It reuses the existing
pipeline unchanged (oracle labels → small tabular gate → empirical attack → enumerate-discrete +
Gaussian-RS certificate). No theorem change, no discrete smoothing.

## Files
- **`synthetic_tools.py`** — parametric `make_rule_table(K, k, |X1|)` (same schema as the real rule
  tables, so `oracle.py` / `FeatureEncoder` / `smoothed_gate.py` work unchanged) + a boundary-aware
  record sampler labelled by the analytic oracle. K tools are partitioned into action groups of size
  `m≈4`, so the per-action valid-swap set (the threat set) stays bounded as the vocabulary K grows —
  which keeps R non-vacuous at scale. Scalar tools in a group share a field with a threshold gap
  (guarantees C); affine tools add D.
- **`harness.py`** — `run_setting(rt, records, …)`: stratified split, train the certified gate,
  clean eval, empirical mixed attack (vectorized), the learned certificate per category, the
  deterministic naive-composition false-certify on C, and runtime. Returns one metrics row.
- **`scaling_study.py`** — sweeps `K∈{4,8,16,32}`, `k∈{2,5,10,20,50}`, `|X1|∈{2,4,8}` (`--full` adds
  the K×k grid) → `cert/out/scaling_results.{csv,md}`.
- **`realistic_schemas.py`** — real-looking finance/monitoring/ops-security schemas (synthetic
  policies) at 50k records/domain → `cert/out/realistic_schema_results.{csv,md}` +
  `realistic_examples.jsonl`.
- **`aggregate_results.py`** — combines both into `cert/out/experiments_summary.md` and checks the
  three claims.
- **`geometric_sensitivity.py`** (PLAN5 §2/§5, the headline figure) — C% vs boundary separation Δ/ε
  for a 2-tool scalar family (and the finance template with `--realistic-finance`). Shows C is a
  geometric O(ε) effect (analytic C-interval length = `min(Δ, ε)`): C=0 at Δ=0, peaks near Δ/ε≈1,
  then declines as A grows / R shrinks. → `cert/out/geometric_sensitivity.{csv,md}`.
- **`dimension_validity.py`** (PLAN5 §3) — regime of validity: certificate soundness/non-vacuity vs
  the continuous dimension `k ∈ {2,5,10,20,50,100}` (K fixed, d=1). → `cert/out/dimension_validity.{csv,md}`.
- **`offline_llm_action_study.py`** (PLAN5 §6) — **offline** LLM action proposal (no agent loop):
  clean propensity on C, unsafe susceptibility on the C witness, and gate-would-block rate.
  → `cert/out/offline_llm_action_study.{csv,md}`. Default `--llm mock` (offline); `--llm openai` for a
  real model. Note: σ/τ/margin ablation lives in `../cert/ablate_smoothed_gate.py`
  (→ `sigma_tau_ablation.{csv,md}`, `r_margin_diagnostics.csv`).

## Run
```bash
python scaling_study.py  # ~3 min (sweeps, n=8000/setting)
python realistic_schemas.py --n 50000  # minimum big experiment: 50k/domain
python aggregate_results.py  # summary + claim checks
# bigger: python scaling_study.py --full --n 20000
```

## Headline columns
`label | K | k | |X1| | #records | A% B% C% R% U% | clean_acc | attack_false_allow |
naive_C_falseallow | C_allow | R_allow | U_allow | cert_false_allow | runtime`.

## Result (σ=0.10, ε=0.10, τ=0.90, n_mc=2000, d=1)
Across the scaling sweep (K up to 32, k up to 50) and the three 50k realistic schemas:
- **C present everywhere** (C% ≈ 8–10%);
- **C_allow = 0, U_allow = 0, cert_false_allow = 0** in every setting (sound);
- **R_allow ≈ 0.2–0.6** in every setting (non-vacuous at scale);
- **naive_C_falseallow = 1.0** and uncertified **attack_false_allow ≈ 0.9–1.0** (marginal/naive and
  uncertified gates fail reproducibly);
- clean accuracy ≈ 0.97–1.0 (the small tabular gate tracks the oracle even at k=50).

Honesty: tool/field names in `realistic_schemas.py` are realistic but thresholds/weights are
`synthetic_stress_test`-grade (see `../../notes/rule_provenance.md`); no real-API data.
Generated CSV/MD/JSONL land in `../cert/out/` and are gitignored.
