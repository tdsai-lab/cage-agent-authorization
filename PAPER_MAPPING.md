# PAPER_MAPPING.md — every table in the paper → the command that produces it

Extracted from `main.tex` (6 tables, 4 figures) and `supplementary.tex` (51 tables, numbered
`S1`–`S51` in order of appearance). Every command is run **from the repository root**; the
requirement tags (`stdlib` / `cpu` / `gpu` / `opa` / `zen` / `llm` / `ieee` / `nab` / `corpora` /
`k8s` / `marble`) and the environment setup are documented in [`REPRODUCE.md`](REPRODUCE.md).

Outputs land under `bridge_benchmark/cert/out/`. The aggregated result files already in that
directory are the ones the tables were built from — re-running a row overwrites its own file, so a
`diff` against the shipped copy is the check.

## Main paper

| Table | Subject | Experiment | Command | Output |
|---|---|---|---|---|
| **1** (`tab:backends`) | What each backend certifies (rung 1 policy-certified; rungs 2–3 + ceiling gate-certified) | — (summary of the four backends) | `bridge_benchmark/cert/fragment.py` (exact) · `experiments/lip_gate/` (Lipschitz) · `cert/smoothed_gate.py` (RS) · `experiments/complete_verification.py` (MILP ceiling) | no single run — see S5, S6, S48 |
| **2** (`tab:setup`) | Shared experimental frame, sampling modes | Frame definition | `python bridge_benchmark/generators/generate.py` (synthetic) · `--sampling {natural,boundary_balanced,c_targeted}` of `realdata_ieee_cis.py` | `schemas/rule_tables.json`, `data/*.jsonl` |
| **3** (`tab:headtohead`) | Point vs. neighborhood on the witness set `W` (real IEEE-CIS + OPA policy, 6032/10000) | EXP1 neighbor head-to-head | `python bridge_benchmark/experiments/neighbor_head_to_head.py` | `cert/out/exp1_neighbor_head_to_head.{csv,json}` |
| **4** (`tab:systems`) | End-to-end validation on deployed substrates | P3 / P3-MCP / P3-mediation / A8 / B2-Marble e2e | `python bridge_benchmark/experiments/e2e/real_harness/run_p3.py` · `run_p3_mcp.py` · `run_p3_mediation.py` · `a8_flagship.py` · `python bridge_benchmark/experiments/marble_e2e.py` | `cert/out/p3_real_harness.*`, `p3_mcp_harness.*`, `p3_mediation.*`, `a8_flagship.*`, `marble_e2e.*` |
| **5** (`tab:soundness`) | Soundness + robust-safe autonomy across all settings (`d=1`, `ε=0.10`) | Aggregate of the per-setting runs | `run_realdata_ieee_cis_cert.py` (IEEE) · `second_real_dataset.py` (NAB) · `exp_opa_full.py` (OPA) · `policy_idiom_prevalence/scripts/run_regulatory_cwitness.py` (REG) · `realistic_schemas.py` (synthetic) | the per-setting outputs listed in S1–S5 and S9 |
| **6** (`tab:faults`) | Budget measurement from injected adapter-fault mechanisms (4000/fault) | FAULT | `python bridge_benchmark/experiments/fault_injection.py` | `cert/out/fault_injection_summary.{csv,md}`, `cert/out/exp_fault/` |
| **Fig. 4** (`fig:reconcile`) | Freshness governs the residual: ε_emp@p95 vs the declared ε | RECONCILE | `python bridge_benchmark/experiments/reconciliation_curve.py` | `bridge_benchmark/figures/reconciliation_eps_freshness_sla.{pdf,png}` |

Figures 1–3 (`fig:post-return-boundary`, `fig:eval-locus`, `fig:joint-gap-witness`) are schematics
drawn in the manuscript; they have no generating experiment.

## Supplement

| Table | Subject | Experiment | Command | Output |
|---|---|---|---|---|
| **S1** (`tab:ieeecis`) | Joint certificate on real IEEE-CIS marginals | H | `python -m bridge_benchmark.experiments.realdata_ieee_cis …` then `python -m bridge_benchmark.experiments.run_realdata_ieee_cis_cert …` (see REPRODUCE §4.3–4.4) or `INPUT_DIR=$IEEE_CIS_DIR bash scripts/run_ieee_cis_realdata_grid.sh` | `cert/out/<--out>/metrics.json`, `report.md` (generated locally — derived from licensed data) |
| **S2** (`tab:nab`) | Second real dataset: NAB CloudWatch CPU telemetry | T2-7 | `python bridge_benchmark/experiments/second_real_dataset.py` | `cert/out/exp_second_dataset/` |
| **S3** (`tab:opa`) | Policy-as-code grounding, real OPA engine labels | OPA Track C | `python bridge_benchmark/experiments/opa_gate/run_opa_gate.py` | `cert/out/opa_gate/` |
| **S4** (`tab:opasweep`) | OPA operating-point sweep with per-record FWER correction | EXP-OPA-FULL | `python bridge_benchmark/experiments/exp_opa_full.py` | `cert/out/exp_opa_full/` |
| **S5** (`tab:lip`) | Backend comparison on the OPA track (75 multi-seed cells) | LIP | `python bridge_benchmark/experiments/lip_gate/scripts/compare_smoothing_vs_lip.py` · `multiseed_variance.py` · `make_tables.py` | `experiments/lip_gate/results/tables/` |
| **S6** (`tab:cv`) | Complete-verification ceiling (big-M MILP per branch) | T1-1 | `python bridge_benchmark/experiments/complete_verification.py` | `cert/out/exp_complete_verification/` |
| **S7** (`tab:cx1fidelity`) | Gate–policy fidelity under known ground truth | CX1 | `python bridge_benchmark/experiments/opa_fidelity_cx1.py` | `cert/out/exp_cx1_opa_fidelity.{json,md}` |
| **S8** (`tab:scaling`) | Scaling study (3 sweeps × 8000 records) | A | `python bridge_benchmark/experiments/scaling_study.py` | `cert/out/scaling_results.{csv,md}` |
| **S9** (`tab:settinganchors`) | Per-setting anchors: PSD2/AML, realistic schemas, DevOps | REG · B · G | `python bridge_benchmark/experiments/policy_idiom_prevalence/scripts/run_regulatory_cwitness.py` · `python bridge_benchmark/experiments/realistic_schemas.py --n 50000` · `python -m bridge_benchmark.experiments.run_benchmark_grounded_cert …` | `experiments/policy_idiom_prevalence/results/`, `cert/out/realistic_schema_results.{csv,md}`, `cert/out/<--out>/` |
| **S10** (`tab:tm2`) | Adaptive attack on the gate | TM2 | `python bridge_benchmark/attacks/adaptive_gate_attack.py` | `cert/out/adaptive_gate_attack.{csv,md}`, `adaptive_gate_attack_curves.{csv,md}` |
| **S11** (`tab:generalization`) | Held-out generalization (policy / schema shift) | 7-C | `python bridge_benchmark/experiments/generalization_eval.py` | `cert/out/generalization/` |
| **S12** (`tab:realdata`) | Real-data two-channel run on IEEE-CIS (display attacks + typed certificate) | 7-B | `python -m bridge_benchmark.agents.realdata_finance_exp --llm-backend ollama --model qwen3.6:latest` | `cert/out/realdata_finance*/` |
| **S13** (`tab:implicit`) | Implicit-policy regime as a gate-fidelity stress test | #32 | `python bridge_benchmark/experiments/implicit_policy_gate.py` | `cert/out/implicit_policy_gate.{json,md}` |
| **S14** (`tab:q7model`) | Model-dependent threat vs. model-independent defense | F / F.2 | `python -m bridge_benchmark.agents.real_llm_action_exp --llm-backend ollama --model <tag>` then `python -m bridge_benchmark.agents.evaluate_real_llm_exp` | `cert/out/real_llm_action_exp/` |
| **S15** (`tab:ieeecisagent`) | Real-LLM action proposal on IEEE-CIS, unsafe execution rate | I | `python -m bridge_benchmark.agents.run_ieee_cis_agent_exp --records … --llm-backend ollama --model qwen2.5:7b-instruct --out cert/out/ieee_cis_agent_exp_qwen7b` | `cert/out/ieee_cis_agent_exp_*/` |
| **S16** (`tab:tm1`) | Non-instructability: display text moves the proposal, not the typed gate | TM1 | `python -m bridge_benchmark.agents.real_llm_action_exp …` (sweep) then `python -m bridge_benchmark.agents.evaluate_tm1_real_llm` | `cert/out/tm1_real_llm*/` |
| **S17** (`tab:judge`) | LLM-judge baselines on the witness set `W` | T1-4 | `python bridge_benchmark/experiments/llm_judge_baselines.py` | `cert/out/exp_llm_judge*/` |
| **S18** (`tab:comparators`) | Deployed-defense comparators (CaMeL, pre-exec classifier) | P5 | `python bridge_benchmark/comparators/vs_camel.py` · `python bridge_benchmark/comparators/vs_preexec.py` | `cert/out/vs_camel.{json,md}`, `cert/out/vs_preexec.{json,md}` |
| **S19** (`tab:e2e`) | End-to-end unsafe commits (300 episodes per domain × attack) | #29 | `python -m bridge_benchmark.agents.end_to_end_exploit` | `cert/out/e2e_exploit_summary.{csv,md}` |
| **S20** (`tab:realharness`) | Real-harness integration: live `kind` + Kyverno + MCP | P3, P3-MCP, P3-mediation, P3-A8 | `python bridge_benchmark/experiments/e2e/real_harness/run_p3.py` · `run_p3_mcp.py` · `run_p3_mediation.py` · `a8_flagship.py` | `cert/out/p3_real_harness.*`, `p3_mcp_harness.*`, `p3_mediation.*`, `a8_flagship.*` |
| **S21** (`tab:marble`) | Joint-gap taxonomy verified inside a purpose-built AML engine | B2-Marble | `MARBLE_DIR=… python bridge_benchmark/experiments/marble_cwitness.py` | `cert/out/marble_cwitness.{json,md}` |
| **S22** (`tab:marblee2e`) | Committed side effects on the AML engine | B2-Marble e2e | `MARBLE_DIR=… python bridge_benchmark/experiments/marble_e2e.py` | `cert/out/marble_e2e.{json,md}` |
| **S23** (`tab:a7`) | Second independent real adapter (k8s Deployment + Kyverno) | A7 | `python bridge_benchmark/experiments/e2e/real_harness/a7_second_adapter.py` | `cert/out/a7_second_adapter.{json,md}` |
| **S24** (`tab:claimladder`) | Evidence ladder for external validity, separated by provenance | Claim ladder | `python bridge_benchmark/experiments/policy_idiom_prevalence/scripts/make_claim_ladder.py` | `policy_idiom_prevalence/results/tables/` |
| **S25** (`tab:adjudication`) | Registry-scale substrate adjudication (31 candidates, 8 servers) | EXP-A2 | `python bridge_benchmark/experiments/mcp_substrate/registry_adjudicate.py` (Stage 1: `registry_scan.py`) | `cert/out/exp_mcp_registry_adjudication/` |
| **S26** (`tab:idiomaticity`) | Structural prevalence + per-engine idiomaticity of `op(f_num, θ(s))` | P1-B · A-DMN · B1 | `python bridge_benchmark/experiments/detector/idiom_rescan.py` · `engine_idiomaticity.py` (Phase-1 scan: `scan_corpus.py`) | `cert/out/idiom_rescan.{json,md}`, `cert/out/engine_idiomaticity.{json,md}`, `cert/out/idiom_scan.{json,md}` |
| **S27** (`tab:cx5openfisca`) | Independent third-party policy case study (OpenFisca BRS ceilings) | CX5 | `python bridge_benchmark/experiments/cx5_openfisca.py` | `cert/out/exp_cx5/` |
| **S28** (`tab:compound`) | Compound / correlated fault injection (pairs and triples) | EXP-A1 | `python bridge_benchmark/experiments/compound_fault_injection.py` | `cert/out/exp_a1_compound_faults.{json,md}` |
| **S29** (`tab:dsweep`) | Discrete-budget sweep `d ∈ {1,2,3}`, exact enumeration | T2-8 | `python bridge_benchmark/experiments/d_sweep.py` | `cert/out/exp_d_sweep/` |
| **S30** (`tab:escape`) | Discrete-channel escape, leave-one-fault-out | T1-2 | `python bridge_benchmark/experiments/discrete_escape.py` | `cert/out/exp_discrete_escape/` |
| **S31** (`tab:perfault`) | Per-fault continuous residuals (4000 samples/fault) | FAULT (detail of Table 6) | `python bridge_benchmark/experiments/fault_injection.py` · `exp_fault_injection.py` | `cert/out/fault_injection_summary.{csv,md}`, `cert/out/exp_fault/` |
| **S32** (`tab:negcontrol`) | Negative control: fabricated endpoint lies in/out of budget | 7-D | `python bridge_benchmark/experiments/negative_controls.py` | `cert/out/negative_controls/` |
| **S33** (`tab:breaking`) | Breaking radius of the declared budget | P2 | `python bridge_benchmark/experiments/adaptive/out_of_budget_attacks.py` | `cert/out/out_of_budget_attacks.{json,md}` |
| **S34** (`tab:constructor`) | Constructor-corruption sweep (below the typed interface) | EXP2 part B | `python bridge_benchmark/experiments/validation_stack_adversary.py` | `cert/out/exp2b_constructor_corruption.{csv,json}` |
| **S35** (`tab:slasweep`) | Sub-minute freshness-SLA sweep (Δt ∈ {1…120} s) | EXP-A3 | `python bridge_benchmark/experiments/freshness_sla_submin.py` | `cert/out/exp_a3_freshness_submin.{csv,json}` |
| **S36** (`tab:slacoarse`) | Coarse freshness-SLA grid (the points Fig. 4 plots) | EXP2 part A | `python bridge_benchmark/experiments/validation_stack_adversary.py` | `cert/out/exp2a_freshness_sla.{csv,json}` |
| **S37** (`tab:rawunit`) | Raw-unit ε audit (what ε = 0.10 means in dollars / CPU %) | EXP-B2 | `python bridge_benchmark/experiments/raw_unit_epsilon_audit.py` | `cert/out/exp_b2_raw_unit_epsilon.{json,md}` |
| **S38** (`tab:cx4perfield`) | Calibrated per-field budget (ellipsoid / weighted-ℓ∞ vs global ℓ₂) | CX4 = A6 | `python bridge_benchmark/experiments/perfield_budget_cx4.py` | `cert/out/exp_cx4_perfield_budget.{json,md}` |
| **S39** (`tab:cx6`) | Real-adapter budget calibration through the Marble engine | CX6 | `MARBLE_DIR=… python bridge_benchmark/experiments/cx6_marble.py` | `cert/out/cx6_marble.{json,md}` |
| **S40** (`tab:projection`) | Policy-state projection (k_active = 5 padded to k_raw ∈ {20,50,100}) | D.4 | `python bridge_benchmark/experiments/policy_state_projection.py` | `cert/out/policy_state_projection.{json,md}` |
| **S41** (`tab:dos`) | Abstention-DoS: boundary-seeking input selection | T2-9 | `python bridge_benchmark/experiments/abstention_dos.py` | `cert/out/exp_abstention_dos/` |
| **S42** (`tab:runtime`) | Validity regime: per-decision cost and soundness | 7-E | `python bridge_benchmark/experiments/runtime_report.py` (Lipschitz timing: `lip_gate/scripts/measure_runtime.py`) | `cert/out/runtime/`, `cert/out/runtime_qwen36/` |
| **S43** (`tab:monitor`) | Operational fidelity monitor (two-window delayed audit) | EXP-A4 | `python bridge_benchmark/experiments/fidelity_monitor.py` | `cert/out/exp_a4_fidelity_monitor.{json,md}` |
| **S44** (`tab:deltasweep`) | δ-sensitivity of C prevalence (the `min(δ,ε)` law on real data) | EXP-B1 | `python bridge_benchmark/experiments/delta_sensitivity_c.py` | `cert/out/exp_b1_delta_sensitivity.{json,md}` |
| **S45** (`tab:fscaleheldout`) | Held-out `f_scale` selection (selection hygiene for S2 / S29) | EXP-C4 | `python bridge_benchmark/experiments/fscale_heldout_selection.py` · `nab_fscale_heldout.py` | `cert/out/exp_c4_fscale_heldout.{json,md}`, `cert/out/nab_fscale_heldout.{json,md}` |
| **S46** (`tab:dimsweep`) | Dimension sweep (sound through k = 50; fidelity edge at k = 100) | D.2 | `python bridge_benchmark/experiments/dimension_validity.py` | `cert/out/dimension_validity.{csv,md}` |
| **S47** (`tab:cx2horizon`) | Deployment-horizon confidence for randomized smoothing | CX2 | `python bridge_benchmark/experiments/opa_rs_horizon_cx2.py` | `cert/out/exp_cx2_rs_horizon.{json,md}` |
| **S48** (`tab:cx3differential`) | Differential validation of CAGE-Exact (200 policies × 1000 returns) | CX3 | `python bridge_benchmark/experiments/cx3_differential.py` (fragment under test: `cert/fragment.py`) | `cert/out/exp_cx3/` |
| **S49** (`tab:triage`) | Operational triage: R_allow as a certified-autonomy fraction | T1-3 | `python bridge_benchmark/experiments/operational_triage.py` | `cert/out/exp_triage/` |
| **S50** (`tab:autonomy`) | Natural-traffic autonomy accounting (unconditional certified allow) | M2 | `python bridge_benchmark/experiments/natural_traffic_autonomy.py` | `cert/out/natural_traffic_autonomy.{csv,md}` |
| **S51** (`tab:wilson`) | Zero-cell audit: n/N + Wilson-95% upper for every quoted zero | M1 | `python bridge_benchmark/experiments/wilson_zero_cells.py` | `cert/out/wilson_zero_cells.{csv,md}` |

## Formal claims → code

| Claim in the paper | Implementation | Empirical validation |
|---|---|---|
| Definition 1 (verified affine fragment) + Proposition 7 (support-function robust test) | `bridge_benchmark/cert/fragment.py` | S48 — `experiments/cx3_differential.py` (200 policies × 1000 returns, frozen seeds) |
| Proposition (robust-safe floor) behind Table 3 | `bridge_benchmark/experiments/neighbor_head_to_head.py` | Table 3 |
| Proposition 3 boundary assumption `Pr[m = ε] = 0` on clipped/quantized data | — | `python bridge_benchmark/experiments/prop3_boundary_mass.py` → `cert/out/prop3_boundary_mass.{csv,md}` (M5) |
| Anytime-valid fidelity-audit stopping rule | `bridge_benchmark/experiments/fidelity_audit_stopping.py` | `cert/out/fidelity_audit_stopping.{json,md}` (M4) |
| Non-composition of marginal certificates (Category C) | `bridge_benchmark/generators/oracle.py`, `cert/certificate_oracles.py` | `python bridge_benchmark/cert/certificate_oracles.py` (model-free, `stdlib`) |
| Frozen prevalence scans and their nulls | `experiments/detector/`, `experiments/mcp_substrate/` | [`PREREGISTRATION.md`](PREREGISTRATION.md) — detector SHA-256s, registered protocols, outcomes |

## Not reproducible from a bare clone

Rows tagged `ieee` (licensed Kaggle data — `scripts/download_ieee_cis.py` fetches it),
`corpora` (third-party policy corpora to clone into `external/corpora/`), `marble`, `k8s` and `llm`
(external engines, clusters and model servers) need the corresponding dependency. Each script prints
the exact expected path and upstream source when its dependency is missing, and the aggregated output
of our run is committed under `bridge_benchmark/cert/out/`.
