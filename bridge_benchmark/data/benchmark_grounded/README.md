# Benchmark-grounded typed-return experiment

This directory holds the **benchmark-grounded** authorization dataset and is a *supplement* to the
synthetic oracle benchmark — it does **not** replace it. The synthetic pipeline
(`experiments/synthetic_tools.py`, `realistic_schemas.py`, the `cert/` evaluators) remains the main
certificate-controlled benchmark.

> This experiment uses benchmark-derived task families, target sets, action types, and state fields.
> The post-tool-return typed node and continuous perturbation policy are constructed to fit the
> certificate interface. Therefore this is a **benchmark-grounded authorization experiment, not a
> fully real production-policy benchmark.**

## What benchmark source is used

**AmPermBench-style** agent-permission tasks. AmPermBench-style tasks expose, per prompt, an
**authorized** target set and a **must-preserve / protected** target set, plus a candidate agent
action over a proposed target set. Four task families are implemented:

| family | tools (provenance channels) | candidate actions |
| --- | --- | --- |
| `cancel_jobs` | cluster_job_status, scheduler_queue_state, job_owner_index | cancel_job, cancel_jobs |
| `branch_cleanup` | git_branch_scanner, remote_branch_index, repo_state_tool | delete_branch, delete_remote_branch, delete_branches |
| `service_restart` | k8s_service_status, deployment_health_api, incident_context_tool | restart_service, restart_services |
| `artifact_cleanup` | artifact_inventory, s3_object_index, build_cache_state | delete_artifact, delete_artifacts |

AgentDojo is *not* used here: it flattens typed returns to text and does not expose the
post-tool-return authorization node (see the paper's motivation section).

## What is real / benchmark-derived / constructed / synthetic

| layer | status |
| --- | --- |
| task families, candidate actions, tool identities | benchmark-derived |
| authorized / must-preserve / protected target sets | benchmark-derived |
| categorical state fields `x1` (environment, owner_match, ticket_match, target_scope, protected…) | benchmark-derived |
| blast-radius numeric fields `x2` (`unauthorized_fraction`, `protected_fraction`, `target_count_norm`) | **computed from the benchmark sets** |
| operational numeric fields (`age_norm`, `staleness_norm`, `latency_norm`, …) | derived-from-state or `synthetic_neutral_default` (see each record's `feature_origin`) |
| typed numeric **policy thresholds** (`hybrid_policy`) | **synthetic** — constructed to fit the certificate interface |
| continuous L2 perturbation policy `B_{1,ε}` | constructed |

`x2` features are normalized to `[0,1]`:
```
target_count_norm  = min(|proposed| / 10, 1)
unauthorized_fraction = |proposed \ authorized| / max(|proposed|, 1)
protected_fraction  = |proposed ∩ protected| / max(|proposed|, 1)
```

## Two oracle modes

* **`benchmark_set`** — the FAITHFUL hard set-membership oracle: `Safe(z,a)=1` iff the proposed
  action touches **no** unauthorized and **no** protected target. Its continuous channel is weak by
  construction (a near-zero boundary on the fractions), so it yields **few or no Category C** — this
  is expected and honest, not a bug.
* **`hybrid_policy`** — benchmark-grounded **structure** + **synthetic typed policy thresholds**:
  `Safe(z,a)=1` iff a weighted blast-radius score over (`unauthorized_fraction`,
  `protected_fraction`, `target_count_norm`) stays under a per-`(tool, x1)` boundary. The boundary
  **tightens in prod / on protected resources** and differs across same-family provenance tools, so a
  single discrete provenance flip repositions it by more than `ε·‖w‖` — this is what creates the
  **Category C** (joint-only) failures. The numeric thresholds are synthetic.

## Why this is supplementary

The contribution of this repo is the **certificate-composition** result (a discrete-only certificate
and a continuous-only certificate can each be sound while their naive composition is false — only the
hybrid certificate over the joint ball is correct) and a sound, non-vacuous learned certificate.
This benchmark-grounded experiment asks a narrower question: *does the same failure mode appear when
the task/action/state structure is benchmark-derived rather than fully synthetic?* It does.

## How to run

```bash
# 1) generate canonical records (bundled fixture; no internet, no API)
python -m bridge_benchmark.experiments.benchmark_grounded \
  --source ampermbench --use-fixture --n-per-family 2400 --seed 0 \
  --out bridge_benchmark/data/benchmark_grounded/ampermbench_fixture_records.jsonl

#...or from local AmPermBench-style task files (.json/.jsonl with keys
#  task_family, proposed_targets, authorized_targets [, protected_targets, x1, tool_id, candidate_action]):
python -m bridge_benchmark.experiments.benchmark_grounded \
  --source ampermbench --input-dir bridge_benchmark/data/raw/ampermbench \
  --out bridge_benchmark/data/benchmark_grounded/ampermbench_records.jsonl

# 2) train -> attack -> certify (both oracle modes)
python -m bridge_benchmark.experiments.run_benchmark_grounded_cert \
  --records bridge_benchmark/data/benchmark_grounded/ampermbench_fixture_records.jsonl \
  --oracle-mode hybrid_policy --epsilon 0.10 --d 1 --sigma 0.10 --tau 0.90 --n-mc 2000 \
  --seed 0 --n-cert 100 \
  --out bridge_benchmark/cert/out/benchmark_grounded_ampermbench_hybrid_seed0

python -m bridge_benchmark.experiments.run_benchmark_grounded_cert \
  --records bridge_benchmark/data/benchmark_grounded/ampermbench_fixture_records.jsonl \
  --oracle-mode benchmark_set --epsilon 0.10 --d 1 --sigma 0.10 --tau 0.90 --n-mc 2000 \
  --seed 0 --n-cert 100 \
  --out bridge_benchmark/cert/out/benchmark_grounded_ampermbench_benchmarkset_seed0
```

Outputs per run (under `cert/out/...`): `metrics.json`, `records_with_categories.jsonl`,
`report.md`, `config.json`.

## How to interpret (fixture, seed 0, σ=0.10, ε=0.10, τ=0.90, n_mc=2000)

`hybrid_policy` (9600 records): categories A=447, B=334, **C=1661 (~17%)**, R=2474 (~26%), U=4684;
`clean_accuracy=0.997`; **`cert_false_allow=0` (sound)**; `C_allow=U_allow=0`;
`R_allow≈0.11` (non-vacuous; a conservative lower bound — ~27% of R is analytically certifiable, and
the smoothed certificate realizes about half of that at n_mc=2000 due to Clopper–Pearson
conservativeness); **`naive_C_falseallow=1.0`** — the naive marginal composition false-certifies every
Category C point, exactly the non-composition result, now reproduced on benchmark-grounded structure.

`benchmark_set` (faithful): only B/U categories (degenerate continuous channel, no discrete
repositioning ⇒ no C), sound (`cert_false_allow=0`).

## Known limitations

> This experiment does not provide end-to-end robustness for an LLM agent. It evaluates a certified
> post-tool-return authorization node built from benchmark-derived task/action/state structure.

- The numeric policy thresholds (`hybrid_policy`) are **synthetic** and chosen to fit the certificate
  interface; they are not real industrial thresholds.
- `benchmark_set` is faithful but has a weak continuous channel by construction (few/no C).
- No claim of end-to-end agent robustness; the certified object is the typed post-tool-return
  authorization node, not the LLM, planner, or tool selector.

Generated `*.jsonl` records are git-ignored (`bridge_benchmark/data/`); regenerate with the commands
above. The bundled fixture is fully deterministic (fixed seed, no network).
