# REPRODUCE.md — result → exact command

One row per experiment: the command to run it, what the command needs, and where its numbers land.
Run every command **from the artifact root** (the directory containing this file).

**Reference values.** Each row names the file it writes under `bridge_benchmark/cert/out/`. The
aggregated reports already shipped there (`*.md`, `*.csv`, `*.json`) are the numbers behind the
paper's tables: re-run a row and compare against the report it overwrites — the configuration used is
recorded at the top of each report. The paper's tables are the other reference; the headline
soundness cells are quoted inline in the tables below.

**Looking for a specific table of the paper?** [`PAPER_MAPPING.md`](PAPER_MAPPING.md) maps
Tables 1-6 and S1-S51 to the rows below.

## 0. How to read this file

**Requirement tags** (column `needs`):

| tag | meaning |
|---|---|
| `stdlib` | Python standard library only — no third-party package at all |
| `cpu` | `requirements.txt` (numpy / scipy / scikit-learn / pandas) |
| `gpu` | `torch` + `orthogonium` (`requirements-optional.txt`); runs on CPU but slowly |
| `opa` | the OPA 1.17.1 binary at `bridge_benchmark/experiments/opa_gate/bin/opa` (not redistributed — `setup.sh` prints the download command) |
| `zen` | `zen-engine` (pip, `requirements-optional.txt`) |
| `llm` | a local Ollama server + the model tag in the command (`--llm-backend mock` runs the same code offline) |
| `ieee` | the licensed IEEE-CIS download — `python scripts/download_ieee_cis.py` first (see `bridge_benchmark/data/README.md`) |
| `nab` | the NAB telemetry, **vendored** in `bridge_benchmark/data/realdata/nab/` (MIT) — nothing to do |
| `corpora` | third-party policy corpora that must be cloned into `external/corpora/` — see §6 |
| `k8s` | a Kubernetes cluster (`kind`) + Kyverno, or an MCP server |
| `marble` | a running Marble AML engine (container runtime required) |
| `precomputed` | the aggregated outputs are shipped in `bridge_benchmark/cert/out/`; re-running needs the tags listed alongside |

**Seeds.** Every stochastic entry point exposes `--seed` (or `--seeds`) and its default *is* the seed
used for the reported numbers — running the bare command reproduces the paper's configuration. Fixed
defaults: `--seed 0` almost everywhere; `--seed 1` for `scaling_study.py`,
`realistic_schemas.py`, `geometric_sensitivity.py`, `dimension_validity.py`; `--seeds 0 1 2` for the
multi-seed studies. Deterministic entry points (oracle, generators, detectors, scans, aggregators,
post-processors) take no seed by construction.

**Canonical hyperparameters** (defaults in every script): `ε = 0.10`, `δ = 0.08`, `σ = 0.10`,
`τ = 0.90`, `n_mc = 2000`, `α = 1e-3`, `d = 1`. `n_mc` is a **randomized-smoothing-only** knob; the
1-Lipschitz backend is deterministic and sampling-free.

**Tolerance.** `stdlib`/`cpu` deterministic rows must match exactly. Sampling rows (randomized
smoothing, attacks, LLM) match within the multi-seed variance recorded in the corresponding
shipped report; the soundness cells (`cert_false_allow`, `C_allow`, `U_allow`) are exact zeros
and must reproduce as exact zeros.

**Outputs.** Unless a command names an `--out`, results land in `bridge_benchmark/cert/out/`.
Aggregated copies of those files are already shipped, so the tables can be checked without re-running.

**What was verified from a fresh copy of this artifact** (Python 3.12, no `opa`, no licensed dataset,
no LLM server): `python -m pytest -q` → **258 passed, 60 skipped** (the skips are exactly the `gpu` /
`opa` / `ieee` / `llm` / `k8s` / `marble` capabilities absent on that machine), plus every row in §1,
§2.1–2.7, §3.1–3.7, §6 (`stdlib` rows), §8.2–8.3 and §9.1–9.2/9.5 run end-to-end. Rows needing a
capability that machine did not have are marked with their tag and were not re-run for this check.

---

## 1. Core proof — analytic oracle and non-composition (no dependencies)

| # | result | command | needs | output |
|---|---|---|---|---|
| 1.1 | Oracle health — 10/10 unit tests | `python bridge_benchmark/generators/test_oracle.py` | stdlib | stdout |
| 1.2 | Labelled records + C-witness audit ("violations: 0") | `python bridge_benchmark/generators/generate.py` | stdlib | `bridge_benchmark/data/*.jsonl` |
| 1.3 | Category verifier / witness cross-check | `python bridge_benchmark/generators/verify_interaction_type.py --selftest` | stdlib | stdout |
| 1.4 | C robustness over the threshold grid (455/455 nonempty) | `python bridge_benchmark/generators/threshold_sensitivity.py` | stdlib | stdout |
| 1.5 | **§4.0 Model-free non-composition** — C rows: naive composition FALSE; R rows: hybrid safe | `python bridge_benchmark/cert/certificate_oracles.py` | stdlib | stdout |
| 1.6 | Exact affine fragment (CAGE-Exact, rung 1) | `python bridge_benchmark/cert/fragment.py` | stdlib | stdout |
| 1.7 | Action-indexed safety demonstration (same `z`, opposite verdicts) | `python bridge_benchmark/experiments/action_indexed_safety.py` | stdlib | `cert/out/` |

## 2. Learned gate + certificate backends

| # | result | command | needs | output |
|---|---|---|---|---|
| 2.1 | Baselines table (8 baselines + certified gate) | `python bridge_benchmark/models/baselines.py` | cpu | stdout |
| 2.2 | Empirical mixed attack over `B_{1,ε}` | `python bridge_benchmark/attacks/mixed_attack.py` | cpu | stdout (~1 min) |
| 2.3 | Adaptive attack on the learned gate (TM2) | `python bridge_benchmark/attacks/adaptive_gate_attack.py` | cpu | `cert/out/` |
| 2.4 | **Certificate Tables 1–5** (sound + non-vacuous; `cert_false_allow = 0`) | `python bridge_benchmark/cert/evaluate_certificates.py` | cpu | `cert/out/certificates.jsonl` (~8 s) |
| 2.5 | Certificate audit (8 invariant checks, all PASS) | `python bridge_benchmark/cert/audit_smoothed_gate.py` | cpu | stdout |
| 2.6 | σ/τ/n_mc ablation — soundness invariant, only utility moves | `python bridge_benchmark/cert/ablate_smoothed_gate.py` | cpu | `cert/out/ablation_smoothed_gate.{csv,md}`, `sigma_tau_ablation.*` |
| 2.7 | R-margin diagnostics (`corr(oracle margin, bound) = 0.86`) | `python bridge_benchmark/cert/r_margin_diagnostics.py` | cpu | `cert/out/r_margin_diagnostics.csv` |
| 2.8 | Complete verification (exact small-net ceiling, ablation) | `python bridge_benchmark/experiments/complete_verification.py` | gpu | `cert/out/complete_verification.*` |
| 2.9 | Out-of-budget adversary / breaking radius (Experiment P2) | `python bridge_benchmark/experiments/adaptive/out_of_budget_attacks.py` | cpu | `cert/out/out_of_budget_attacks.*` |

### 2b. Deterministic 1-Lipschitz backend (primary certified backend, Experiment LIP / P4)

| # | result | command | needs | output |
|---|---|---|---|---|
| 2b.1 | Train the 1-Lipschitz gate | `python bridge_benchmark/experiments/lip_gate/scripts/train_lip_gate.py` | gpu | `cert/out/lip_gate/` |
| 2b.2 | Certify it (deterministic margin bound, no `n_mc`) | `python bridge_benchmark/experiments/lip_gate/scripts/certify_lip_gate.py` | gpu | `cert/out/lip_gate/` |
| 2b.3 | Lipschitz vs smoothing head-to-head (Tables L1–L4) | `python bridge_benchmark/experiments/lip_gate/scripts/compare_smoothing_vs_lip.py` | gpu | `experiments/lip_gate/results/tables/` |
| 2b.4 | 5-seed variance (L5) | `python bridge_benchmark/experiments/lip_gate/scripts/multiseed_variance.py` | gpu | same |
| 2b.5 | Dimension regime k ∈ {10,50,100,150} (L6) | `python bridge_benchmark/experiments/lip_gate/scripts/k100_regime.py` | gpu | same |
| 2b.6 | Soundness/utility suite L7–L10 (MC budget, FWER, 12 σ×τ×ε cells, 4 base gates) | `python bridge_benchmark/experiments/lip_gate/scripts/soundness_suite.py` | gpu | same |
| 2b.7 | Certified **local** Lipschitz bound (L11, `‖∇h‖ ≈ 0.98`) | `python bridge_benchmark/experiments/lip_gate/scripts/tighten_lcert.py` | gpu | same |
| 2b.8 | Recovery-deficit decomposition | `python bridge_benchmark/experiments/lip_gate/scripts/decompose_recovery_deficit.py` | stdlib | same |
| 2b.9 | Runtime measurement | `python bridge_benchmark/experiments/lip_gate/scripts/measure_runtime.py` | gpu | same |
| 2b.10 | Rebuild all L-tables from the recorded runs | `python bridge_benchmark/experiments/lip_gate/scripts/make_tables.py` | stdlib | `experiments/lip_gate/results/tables/*.md` |
| 2b.11 | Whole backend, one shot | `bash bridge_benchmark/experiments/lip_gate/run_full.sh` (quick variant: `run_quick.sh`) | gpu | all of the above |

## 3. Scaling, realism, regime of validity (Tier 1)

| # | result | command | needs | output |
|---|---|---|---|---|
| 3.1 | **Experiment A** — scaling K∈{4,8,16,32}, k∈{2,…,50}, \|X₁\|∈{2,4,8} | `python bridge_benchmark/experiments/scaling_study.py` | cpu | `cert/out/scaling_results.{csv,md}` (~3 min) |
| 3.2 | **Experiment B** — realistic schemas (finance / monitoring / ops), 50k/domain | `python bridge_benchmark/experiments/realistic_schemas.py --n 50000` | cpu | `cert/out/realistic_schema_results.{csv,md}` (~2 min) |
| 3.3 | **D.1** — C is geometric: C% peaks at Δ/ε ≈ 1, analytic interval `min(Δ,ε)` | `python bridge_benchmark/experiments/geometric_sensitivity.py --realistic-finance` | cpu | `cert/out/geometric_sensitivity.*` (~1 min) |
| 3.4 | **D.2** — dimension validity: sound + non-vacuous to k ≈ 50, fidelity breaks at k = 100 | `python bridge_benchmark/experiments/dimension_validity.py` | cpu | `cert/out/dimension_validity.*` (~2 min) |
| 3.5 | **D.4** — low-dimensional policy-state projection (k_eff ≤ 50 vs raw k = 100) | `python bridge_benchmark/experiments/policy_state_projection.py` | cpu | `cert/out/policy_state_projection.*` |
| 3.6 | Aggregate the scaling/realism study into one summary | `python bridge_benchmark/experiments/aggregate_results.py` | stdlib | `cert/out/experiments_summary.md` |
| 3.7 | **Experiment 7-C** — held-out policy/schema generalization | `python bridge_benchmark/experiments/generalization_eval.py` | cpu | `cert/out/generalization_eval.*` |
| 3.8 | **Experiment 7-D** — negative control: endpoint lies are out of budget | `python bridge_benchmark/experiments/negative_controls.py` | ieee, cpu (reads the row 4.3 record file) | `cert/out/negative_controls.*` |
| 3.9 | **Experiment 7-E** — runtime & cost | `python bridge_benchmark/experiments/runtime_report.py` | cpu (`llm` for the LLM rows) | `cert/out/runtime_report.*` |
| 3.10 | **T2-8** — discrete-budget d-sweep (enumeration cliff) | `python bridge_benchmark/experiments/d_sweep.py` | gpu | `cert/out/d_sweep.*` |
| 3.11 | **T2-9** — abstention-DoS (attacking the price of soundness) | `python bridge_benchmark/experiments/abstention_dos.py` | cpu | `cert/out/abstention_dos.*` |
| 3.12 | **T1-2** — discrete escape rate (leave-one-fault-out) | `python bridge_benchmark/experiments/discrete_escape.py` | cpu | `cert/out/discrete_escape.*` |
| 3.13 | **T1-3** — operational triage (R_allow as certified-autonomy fraction) | `python bridge_benchmark/experiments/operational_triage.py` | gpu | `cert/out/operational_triage.*` |

## 4. Real-data grounding (Tier 2)

Rows tagged `ieee` need the licensed download first:
`python scripts/download_ieee_cis.py --out bridge_benchmark/data/raw/ieee_cis`, then
`export IEEE_CIS_DIR=$PWD/bridge_benchmark/data/raw/ieee_cis`.

| # | result | command | needs | output |
|---|---|---|---|---|
| 4.1 | **Experiment G** — AmPermBench-grounded records (generate) | `python -m bridge_benchmark.experiments.benchmark_grounded --source ampermbench --use-fixture --out bridge_benchmark/data/benchmark_grounded/ampermbench_fixture_records.jsonl` | cpu | records jsonl |
| 4.2 | **Experiment G** — certify them | `python -m bridge_benchmark.experiments.run_benchmark_grounded_cert --records bridge_benchmark/data/benchmark_grounded/ampermbench_fixture_records.jsonl --oracle-mode hybrid_policy --out bridge_benchmark/cert/out/benchmark_grounded` | cpu | `cert/out/benchmark_grounded/` |
| 4.3 | **Experiment H** — IEEE-CIS record generation (seeded, deterministic) | `python -m bridge_benchmark.experiments.realdata_ieee_cis --input-dir $IEEE_CIS_DIR --out bridge_benchmark/data/realdata/ieee_cis_boundary_balanced_s0.jsonl --sampling boundary_balanced --n-records 10000 --theta-quantile 0.70 --delta 0.08 --epsilon 0.10 --seed 0` | ieee, cpu | records + generation report |
| 4.4 | **Experiment H** — certify the IEEE-CIS records | `python -m bridge_benchmark.experiments.run_realdata_ieee_cis_cert --records bridge_benchmark/data/realdata/ieee_cis_boundary_balanced_s0.jsonl --epsilon 0.10 --d 1 --n-mc 2000 --seed 0 --out bridge_benchmark/cert/out/realdata_ieee_cis_seed0` | ieee, cpu | `metrics.json`, `report.md` |
| 4.5 | **Experiment H** — full grid | `INPUT_DIR=$IEEE_CIS_DIR bash scripts/run_ieee_cis_realdata_grid.sh` | ieee, cpu | `cert/out/realdata_ieee_cis_*/` |
| 4.6 | Smoke test without the licensed data (tiny synthetic fixture) | `python -m bridge_benchmark.experiments.realdata_ieee_cis --input-dir bridge_benchmark/data/fixtures/ieee_cis_tiny --out bridge_benchmark/data/realdata/ieee_cis_fixture_records.jsonl --sampling c_targeted --n-records 200 --seed 0` | cpu | fixture records |
| 4.7 | **Experiment FAULT (#16)** — `B_{d,ε}` measured: every atomic fault Pr[d=1]=1, Pr[d≥2]=0 | `python bridge_benchmark/experiments/fault_injection.py` | ieee, cpu | `cert/out/fault_injection.*` |
| 4.8 | **EXP-FAULT** — mechanistic fault-injection / budget calibration | `python bridge_benchmark/experiments/exp_fault_injection.py` | ieee, cpu | `cert/out/exp_fault/` |
| 4.9 | **#17 EPS-DERIVE** — per-domain ε_emp@p95 under integrity+freshness | `python bridge_benchmark/experiments/derive_epsilon.py` | ieee, cpu | `cert/out/epsilon_derivation.{csv,md}` |
| 4.10 | **#20 EPS-RESWEEP** — re-sweep ε (cert_false_allow = 0 at every ε) | `python bridge_benchmark/experiments/epsilon_resweep.py` | cpu | `cert/out/epsilon_resweep.{csv,md}` |
| 4.11 | **#32 IMPLICIT** — gate on a really-implicit policy (real `isFraud`, no predicate) | `python bridge_benchmark/experiments/implicit_policy_gate.py` | ieee, gpu | `cert/out/implicit_policy_gate.*` |
| 4.12 | **T2-7** — second real dataset, non-finance (NAB CPU telemetry) | `python bridge_benchmark/experiments/second_real_dataset.py` | nab, gpu | `cert/out/exp_second_dataset/` |
| 4.13 | **EXP-HARNESS** — deployed-agent harness for the post-return gate | `python bridge_benchmark/experiments/exp_harness.py` | cpu | `cert/out/exp_harness/` |
| 4.14 | **EXP1** — neighbor head-to-head (point vs neighborhood, 5 seeds) | `python bridge_benchmark/experiments/neighbor_head_to_head.py` | ieee, gpu, opa | `cert/out/neighbor_head_to_head.*` |
| 4.15 | **EXP2-A** — validation-stack adversary: freshness SLA + constructor TCB | `python bridge_benchmark/experiments/validation_stack_adversary.py` | ieee, cpu | `cert/out/exp2a_freshness_sla.*` |
| 4.16 | **A3** — sub-minute freshness-SLA sweep | `python bridge_benchmark/experiments/freshness_sla_submin.py` | ieee, cpu | `cert/out/freshness_sla_submin.*` |
| 4.17 | **A1** — compound / correlated fault injection (pairs, triples; d=2 sound) | `python bridge_benchmark/experiments/compound_fault_injection.py` | ieee, gpu | `cert/out/compound_fault_injection.*` |
| 4.18 | **A4** — operational fidelity monitor (delayed-oracle audit) | `python bridge_benchmark/experiments/fidelity_monitor.py` | ieee, gpu | `cert/out/fidelity_monitor.*` |
| 4.19 | **B1** — δ-sensitivity of C prevalence (the `min(δ,ε)` law on real data) | `python bridge_benchmark/experiments/delta_sensitivity_c.py` | ieee, nab, cpu | `cert/out/exp_b1_delta_sensitivity.json` |
| 4.20 | **EXP-B2** — raw-unit ε audit (what ‖·‖₂ ≤ ε means in dollars / CPU %) | `python bridge_benchmark/experiments/raw_unit_epsilon_audit.py` | precomputed (ieee, nab to regenerate) | `cert/out/raw_unit_epsilon_audit.*` |
| 4.21 | **C4** — fscale held-out selection (outcome-conditioned-selection control) | `python bridge_benchmark/experiments/fscale_heldout_selection.py` | gpu, opa | `cert/out/fscale_heldout_selection.*` |
| 4.22 | **CX4 = A6** — calibrated per-field ε budget (ellipsoid / weighted-ℓ∞ vs global ℓ₂) | `python bridge_benchmark/experiments/perfield_budget_cx4.py` | ieee, cpu | `cert/out/perfield_budget_cx4.*` |
| 4.23 | **RECONCILE** — unified ε_emp(freshness-SLA) curve (figure) | `python bridge_benchmark/experiments/reconciliation_curve.py` | precomputed, cpu | `cert/out/reconciliation_curve.pdf` |

## 5. Policy engines (executable policy as the label source)

| # | result | command | needs | output |
|---|---|---|---|---|
| 5.1 | **Experiment OPA Track C** — authored provenance-conditioned Rego; C ≈ 10–12%, `C_allow = U_allow = cert_false_allow = 0` | `python bridge_benchmark/experiments/opa_gate/run_opa_gate.py` | opa, cpu | `cert/out/opa_gate/` |
| 5.2 | **Experiment OPA Track A** — unmodified Gatekeeper: `idiom_rate = 0` (informative null) | `python bridge_benchmark/experiments/opa_gate/run_track_a.py` | opa | `cert/out/opa_track_a/` |
| 5.3 | **EXP-OPA-FULL** — full authored-policy sweep with real OPA labels + utility curves | `python bridge_benchmark/experiments/exp_opa_full.py` | opa, gpu | `cert/out/exp_opa_full/` |
| 5.4 | **EXP-POLICY-THIRD-PARTY** — third-party Rego/Gatekeeper grounding | `python bridge_benchmark/experiments/exp_policy_third_party.py` | opa, corpora | `cert/out/exp_policy_third_party/` |
| 5.5 | **#9b** — engine-labelled Category-C witnesses on real IEEE-CIS (OPA 1.17.1; agreement 1.0, Jaccard 1.0) | `python bridge_benchmark/experiments/opa_gate/ieee_cis_opa_cwitness.py` | opa, ieee | `cert/out/ieee_cis_opa_cwitness.*` |
| 5.6 | **B2** — second real engine: GoRules ZEN/JDM, 800 C-witnesses, agreement 1.0 | `python bridge_benchmark/experiments/zen_engine_cwitness.py` | zen, ieee | `cert/out/zen_engine_cwitness.*` |
| 5.7 | **CX1** — learned-policy vs exact-OPA gate-policy fidelity | `python bridge_benchmark/experiments/opa_fidelity_cx1.py` | opa, gpu | `cert/out/opa_fidelity_cx1.*` |
| 5.8 | **CX2** — deployment-horizon confidence for randomized smoothing | `python bridge_benchmark/experiments/opa_rs_horizon_cx2.py` | opa, gpu | `cert/out/opa_rs_horizon_cx2.*` |
| 5.9 | **CX3** — differential validation of the exact affine fragment | `python bridge_benchmark/experiments/cx3_differential.py` | opa, cpu | `cert/out/cx3_differential.*` |
| 5.10 | **CX5** — third-party-authored policy case study (OpenFisca BRS zone ceilings) | `python bridge_benchmark/experiments/cx5_openfisca.py` | corpora, cpu | `cert/out/cx5_openfisca.*` |
| 5.11 | **REG** — PSD2/AML source-locked continuous C-witness mechanism | `python bridge_benchmark/experiments/policy_idiom_prevalence/scripts/run_regulatory_cwitness.py` | cpu | `experiments/policy_idiom_prevalence/results/` |
| 5.12 | **AZ** — Azure Key Vault `keyType→keySize` existence table | `python bridge_benchmark/experiments/policy_idiom_prevalence/scripts/make_azure_existence_table.py` | stdlib | same |
| 5.13 | Claim ladder (Table E5), provenance kept separate | `python bridge_benchmark/experiments/policy_idiom_prevalence/scripts/make_claim_ladder.py` | stdlib | same |
| 5.14 | **B2-Marble** — C-witnesses inside a real purpose-built AML engine | `MARBLE_DIR=/path/to/marble python bridge_benchmark/experiments/marble_cwitness.py` | marble, ieee | `cert/out/marble_cwitness.*` |
| 5.15 | **B2-Marble e2e** — certified gate + a real committed decision side effect | `MARBLE_DIR=/path/to/marble python bridge_benchmark/experiments/marble_e2e.py` | marble | `cert/out/marble_e2e.*` |
| 5.16 | **CX6** — real adapter-stack budget calibration through Marble | `MARBLE_DIR=/path/to/marble python bridge_benchmark/experiments/cx6_marble.py` | marble, ieee | `cert/out/cx6_marble.*` |

Marble is a third-party engine; it is not vendored. Set `MARBLE_DIR` to a checkout with its
dev compose file running; the reference values are in `cert/out/marble_cwitness.*`.

## 6. Prevalence scans (frozen detectors — see PREREGISTRATION.md)

These four scans returned **informative nulls** and are reported as such. Their detectors are frozen
and SHA-256-pinned; `PREREGISTRATION.md` lists the hashes and the freeze dates, and each scan
re-prints its detector hash at run time — that hash is the check that the predicate was not tuned
after seeing the corpus.

Corpora are third-party clones and are **not** redistributed. Clone them into `external/corpora/`
before running the `corpora` rows; each scan script prints the exact expected sub-directory and the
upstream URL when the corpus is missing.

| # | result | command | needs | output |
|---|---|---|---|---|
| 6.1 | Detector self-report (precision/recall 1.0 on fixtures; prints its own SHA-256) | `python bridge_benchmark/experiments/detector/idiom_detector.py` | stdlib | stdout |
| 6.2 | **P1** — pre-registered scan of ~1424 third-party executable policies → honest null (39 numeric-θ, 0 provenance-keyed) | `python bridge_benchmark/experiments/detector/scan_corpus.py` | corpora | `cert/out/scan_corpus.*` |
| 6.3 | **P1-B / A-DMN** — re-scan the right habitat: OpenFisca 6.8%, DMN-TCK 4.9%, Kogito 11.5% structural idiom | `python bridge_benchmark/experiments/detector/idiom_rescan.py` | corpora | `cert/out/idiom_rescan.*` |
| 6.4 | **B1** — per-engine idiomaticity inventory (7 engines, qualitative, no rate) | `python bridge_benchmark/experiments/detector/engine_idiomaticity.py` | stdlib | `experiments/policy_idiom_prevalence/results/tables/engine_idiomaticity_inventory.md` |
| 6.5 | **MCP-SUBSTRATE** — zero-execution static scan of the public MCP reference servers → `substrate_rate = 0` | `python bridge_benchmark/experiments/mcp_substrate/stage0_static.py` | corpora | `cert/out/mcp_substrate/` |
| 6.6 | **T2-6** — MCP registry-scale scan (31 substrate candidates / 8 servers) | `python bridge_benchmark/experiments/mcp_substrate/registry_scan.py` | precomputed (network to refresh) | `cert/out/exp_mcp_registry/` |
| 6.7 | **A2** — conservative two-pass adjudication of those 31 → 1/31 structural, 0/31 documented θ(s) | `python bridge_benchmark/experiments/mcp_substrate/registry_adjudicate.py` | stdlib (zero compute) | `cert/out/registry_adjudicate.*` |
| 6.8 | **OPENAPI-SUBSTRATE** — 4138 APIs.guru specs: candidate 9.8% / 22.4% financial | `python bridge_benchmark/experiments/mcp_substrate/openapi_scan.py` | corpora | `cert/out/openapi_scan.*` |
| 6.9 | **OPENAPI** step 2 — conservative adjudication → `CONFIRMED_PIPELINE = 0` | `python bridge_benchmark/experiments/mcp_substrate/openapi_adjudicate.py` | stdlib | `cert/out/openapi_adjudicate.*` |

`bridge_benchmark/experiments/mcp_substrate/introspect.py` is the deliberately **not run**
first-party-only escalation (live third-party introspection); it is gated behind
`--allow-execution` and is included for completeness.

## 7. Agent integration and threat models (TM1 / TM2)

The LLM is a validation layer — we certify the gate, never the LLM. Every row runs offline with
`--llm-backend mock`; the reported real-LLM numbers use a local Ollama server
(`bash bridge_benchmark/agents/serve_ollama.sh` starts one; set `OLLAMA_ROOT` to choose where models
live).

| # | result | command | needs | output |
|---|---|---|---|---|
| 7.1 | **Experiment E** — offline LLM action study (no agent loop) | `python bridge_benchmark/experiments/offline_llm_action_study.py` | cpu | `cert/out/offline_llm_action_study.*` |
| 7.2 | **Experiment C** — full agent loop, 500 episodes/condition (mock) | `python -m bridge_benchmark.agents.run_agent_experiment` | cpu | `cert/out/agent_experiment_summary.{csv,md}` |
| 7.3 | **Experiment F / F.2** — real-LLM node grid (Qwen ladder) | `python -m bridge_benchmark.agents.real_llm_action_exp --llm-backend ollama --model qwen2.5:32b` | llm | `cert/out/real_llm_action_exp/` |
| 7.4 | **7-B** — real-data finance (IEEE-CIS) TM1 + TM2 | `python -m bridge_benchmark.agents.realdata_finance_exp --llm-backend ollama --model qwen3.6:latest` | llm, ieee | `cert/out/realdata_finance_*/` |
| 7.5 | **Experiment I** — IEEE-CIS agent integration | `python -m bridge_benchmark.agents.run_ieee_cis_agent_exp --records bridge_benchmark/data/realdata/ieee_cis_boundary_balanced_s0.jsonl --llm-backend ollama --model qwen2.5:7b-instruct --out bridge_benchmark/cert/out/ieee_cis_agent_exp_qwen7b` | llm, ieee | that `--out` dir |
| 7.6 | **TM1-adaptive** — best-of-K prompt-injection stress test | `python -m bridge_benchmark.agents.evaluate_tm1_adaptive` | precomputed (llm to regenerate) | `cert/out/tm1_adaptive/` |
| 7.7 | **TM1** — non-instructability / typed-boundary ablation (`gate_flip = 0`) | `python -m bridge_benchmark.agents.evaluate_tm1_real_llm` | precomputed (llm to regenerate) | `cert/out/tm1_real_llm/` |
| 7.8 | **TM1b** — return dependence (a pre-return predictor cannot decide `Safe(z,a)`) | `python bridge_benchmark/experiments/return_dependence.py` | cpu | `cert/out/return_dependence.*` |
| 7.9 | **T1-4** — LLM-judge baselines (locus, not intelligence) | `python bridge_benchmark/experiments/llm_judge_baselines.py` | llm | `cert/out/llm_judge_baselines.*` |
| 7.10 | Mandatory-gate ablation | `python bridge_benchmark/experiments/mandatory_gate_ablation.py` | llm | `cert/out/mandatory_gate_ablation.*` |
| 7.11 | **SEL (#3)** — tool-selection poisoning as a controlled limit | `python bridge_benchmark/experiments/tool_selection_attack.py` | cpu | `cert/out/tool_selection_attack.*` |
| 7.12 | Re-aggregate any of the above from recorded runs | `python -m bridge_benchmark.agents.evaluate_agent_results` / `evaluate_real_llm_exp` / `evaluate_tm1_adaptive_display` | stdlib | `cert/out/` |

## 8. End-to-end exploit and deployed harnesses

| # | result | command | needs | output |
|---|---|---|---|---|
| 8.1 | **E2E (#29)** — real mutable runtime, inspectable side effects; `joint_cert = oracle = 0.000`, marginal/point/no-gate leak | `python -m bridge_benchmark.agents.end_to_end_exploit` | cpu | `cert/out/e2e_exploit_summary.{csv,md}` |
| 8.2 | **P5** — CaMeL-style comparator | `python bridge_benchmark/comparators/vs_camel.py` | stdlib | `cert/out/vs_camel.*` |
| 8.3 | **P5** — faithful pre-execution classifier comparator | `python bridge_benchmark/comparators/vs_preexec.py` | cpu | `cert/out/vs_preexec.*` |
| 8.4 | **P3** — real `kind` cluster + Kyverno admission harness | `python bridge_benchmark/experiments/e2e/real_harness/run_p3.py` | k8s | `cert/out/p3/` |
| 8.5 | **P3 + MCP** — the same through a real MCP agent loop | `python bridge_benchmark/experiments/e2e/real_harness/run_p3_mcp.py` | k8s, llm | `cert/out/p3_mcp/` |
| 8.6 | **#30** — complete mediation (scale-subresource gap closed) | `python bridge_benchmark/experiments/e2e/real_harness/run_p3_mediation.py` | k8s | `cert/out/p3_mediation/` |
| 8.7 | **A7** — second independent adapter (k8s cost admission) reproduces the taxonomy | `python bridge_benchmark/experiments/e2e/real_harness/a7_second_adapter.py` | k8s | `cert/out/a7_second_adapter.*` |
| 8.8 | **A8** — harness-agnosticism across a second MCP server | `python bridge_benchmark/experiments/e2e/real_harness/a8_flagship.py` | k8s, llm | `cert/out/a8_flagship.*` |

## 9. Revision-hygiene post-processing (no new campaigns)

All five are pure post-processing over shipped outputs — they run on CPU with no dataset and are the
cheapest independent check that the numbers in the tables are the numbers in the files.

Row 9.1 counts as many zero cells as it finds per-example evidence for. The large per-example JSONLs
are not shipped (they are regenerable), so **out of the box it audits 71 of the paper's 91 cells**;
running rows 8.1 and 7.2 first (CPU-only, a few minutes) regenerates `e2e_exploit_results.jsonl` and
`agent_experiment_results.jsonl` and takes it to **83**; the last 8 come from the OPA/harness
per-example files, i.e. rows 5.3 and 4.13 (`opa` / `gpu`). The summary-derived cells and the headline
number (loosest Wilson upper 0.3244 at N=8, REG psd2_tra) reproduce in every case.

| # | result | command | needs | output |
|---|---|---|---|---|
| 9.1 | **M1** — Wilson-95% upper bound + explicit n/N for the zero cells | `python bridge_benchmark/experiments/wilson_zero_cells.py` | precomputed, cpu | `cert/out/wilson_zero_cells.{csv,md}` |
| 9.2 | **M2** — natural-traffic autonomy accounting (unconditional certified-allow) | `python bridge_benchmark/experiments/natural_traffic_autonomy.py` | precomputed, cpu | `cert/out/natural_traffic_autonomy.{csv,md}` |
| 9.3 | **M3** — NAB fscale held-out selection | `python bridge_benchmark/experiments/nab_fscale_heldout.py` | nab, gpu | `cert/out/nab_fscale_heldout.{json,md}` |
| 9.4 | **M4** — anytime-valid fidelity-audit stopping rule | `python bridge_benchmark/experiments/fidelity_audit_stopping.py` | ieee, cpu (re-joins the raw CSVs for wall-clock order) | `cert/out/fidelity_audit_stopping.{json,md}` |
| 9.5 | **M5** — Prop. 3 boundary-mass check on clipped/quantized real marginals | `python bridge_benchmark/experiments/prop3_boundary_mass.py` | precomputed, cpu | `cert/out/prop3_boundary_mass.{csv,md}` |

## 10. Test suite

```bash
python -m pytest -q          # the whole suite; GPU / dataset / engine / cluster tests self-skip
```

Tests that require an unavailable capability skip rather than fail, so a `stdlib`-only machine still
gets a green run over the analytic core, the oracle, the certificate math, the frozen detectors and
the methodology checks.

## 11. Known gaps (stated, not hidden)

- **Not reproducible from this artifact alone:** rows tagged `corpora`, `marble`, `k8s` and `llm`
  depend on third-party corpora, engines, clusters or model servers we cannot redistribute. For each,
  the aggregated output of our run ships in `bridge_benchmark/cert/out/` and the exact upstream
  source is printed by the script when the dependency is missing.
- **IEEE-CIS** is licensed competition data: the download script plus the seeded preprocessing
  reproduces our records bit-for-bit, but the raw CSVs must be fetched by the reviewer.
- **LLM rows** depend on open-weight model checkpoints served locally; different quantizations move
  the *undefended* attack-success rate. The certified rows (`cert_false_allow = 0`) are
  model-independent by construction — that is the point of the experiment, and it is what should be
  checked.
