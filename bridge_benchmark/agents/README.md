# agents/ — LLM-agent experiments + how to launch them

Two related experiments live here. Both validate the certified typed gate **inside an agent pipeline**.
We certify **only** the post-tool-return authorization gate `allow(z, a)` (SPEC) — never the LLM, tool
selection, or the planner. The LLM merely *proposes* a candidate action; the runtime **always** calls
the gate before executing the privileged action, and the gate ignores the LLM rationale.

> Loop: `user task → LLM proposes action from the (possibly corrupted) tool return z′ → gate authorizes
> the privileged action → execute or fall back`.

| Experiment | What | Entry script | Evaluator | LLM |
|---|---|---|---|---|
| **F — real-LLM action proposal** (current) | LLM proposes; a separate certified gate gates execution. Supports **real local models** (Ollama / vLLM) + mock. | `real_llm_action_exp.py` | `evaluate_real_llm_exp.py` | mock **or real** (Qwen/Llama) |
| **C — full agent loop** (appendix) | Older integration illustration; same gates, mock proposer only. | `run_agent_experiment.py` | `evaluate_agent_results.py` | mock |

Both write to `bridge_benchmark/cert/out/` (gitignored).

---

## Entry points (where the scripts are)

All paths are relative to the repo root ``.

**Shell drivers (run these):**
- `bridge_benchmark/agents/serve_ollama.sh` — start/confirm a local Ollama server with its model store on the NAS.
- `bridge_benchmark/agents/run_real_llm_grid.sh` — **the main Experiment F driver**: runs the full
  2×2×4 grid and evaluates it. Parameterized by `BACKEND/MODEL/ENDPOINT/TAG/N` env vars.
- `<local-run-dir>` — convenience wrapper that just calls the repo driver with
  `MODEL=qwen2.5:7b-instruct` (edit the repo script, not this one).

**Python CLIs (called by the drivers; runnable directly):**
- `python -m bridge_benchmark.agents.real_llm_action_exp …` — one (gate, attack) run → a JSONL.
- `python -m bridge_benchmark.agents.evaluate_real_llm_exp …` — aggregate JSONLs → `summary_*.{csv,md}`.
- `python -m bridge_benchmark.agents.run_agent_experiment …` / `…evaluate_agent_results` — appendix loop.

**Library modules (imported, not entry points):** `llm_clients.py` (real backends + cache), `gates.py`
(the 4 gates), `prompts.py` (action-proposal prompts), plus the appendix's `agent_loop.py`,
`tool_env.py`, `llm_client.py`. Tests: `tests/test_real_llm_action_exp.py` (8), `test_agent_loop.py` (6).

---

## How to launch real-LLM agent experiments (Experiment F)

### 0. One-time infrastructure (already done on this machine)
Local Ollama on the NAS, serving the Blackwell GPU. To (re)start the server and pull a model:

```bash
cd 
bash bridge_benchmark/agents/serve_ollama.sh  # start/confirm server
bash bridge_benchmark/agents/serve_ollama.sh pull qwen2.5:7b-instruct  # pull (already present)
```

The server binds `127.0.0.1:11434`; weights + runtime live under `<local-run-dir>`
(`OLLAMA_MODELS=$OLLAMA_MODELS`, binary `…/ollama_install/bin/ollama`).

### 1. Run the full grid + evaluate (one command)
```bash
bash bridge_benchmark/agents/run_real_llm_grid.sh  # qwen2.5:7b-instruct via ollama (~25 min)
```
This runs `{clean, c_witness} × {none, learned, certified, oracle}` over both domains at 200/category and
writes `cert/out/real_llm_action_exp/qwen7b_*.jsonl` + `summary_qwen7b.{csv,md}`. A disk proposal cache
(`CachingLLMClient`) means the 4 gates share **one** set of LLM generations (≈1× cost, not 4×).

Other models / backends — just set env vars:
```bash
# bigger ollama model (pull first): ollama pull qwen2.5:32b
MODEL=qwen2.5:32b TAG=qwen32b bash bridge_benchmark/agents/run_real_llm_grid.sh

# vLLM OpenAI-compatible server (needs `pip install vllm` + a running server)
BACKEND=vllm MODEL=Qwen/Qwen2.5-Coder-32B-Instruct ENDPOINT=http://localhost:8000/v1 \
  TAG=coder32b bash bridge_benchmark/agents/run_real_llm_grid.sh

# offline deterministic baseline (no GPU/server)
BACKEND=mock MODEL=mock TAG=mock bash bridge_benchmark/agents/run_real_llm_grid.sh
```

### 2. Run a single condition (debug / inspect)
```bash
python -m bridge_benchmark.agents.real_llm_action_exp \
  --domain both --categories C,R,U --attack c_witness --gate certified \
  --llm-backend ollama --model qwen2.5:7b-instruct --endpoint http://127.0.0.1:11434 \
  --n-per-category 50 \
  --out bridge_benchmark/cert/out/real_llm_action_exp/dbg.jsonl
```

### 3. Evaluate any set of run files
```bash
python -m bridge_benchmark.agents.evaluate_real_llm_exp \
  --inputs "bridge_benchmark/cert/out/real_llm_action_exp/qwen7b_*.jsonl" \
  --out-csv bridge_benchmark/cert/out/real_llm_action_exp/summary_qwen7b.csv \
  --out-md  bridge_benchmark/cert/out/real_llm_action_exp/summary_qwen7b.md
```

### CLI reference (`real_llm_action_exp.py`)
| flag | default | meaning |
|---|---|---|
| `--domain` | `both` | `finance` \| `sre` \| `both` |
| `--categories` | `C,R,U` | which oracle categories to sample |
| `--attack` | `c_witness` | `clean` \| `c_witness` \| `mixed` |
| `--gate` | `certified` | `none` \| `learned` \| `certified` \| `oracle` |
| `--llm-backend` | `mock` | `mock` \| `ollama` \| `vllm` |
| `--model` / `--endpoint` | — | model name / server base URL |
| `--n-per-category` | `200` | episodes per category (≥200 advised) |
| `--tau --sigma --epsilon --n-mc` | `0.90 0.10 0.10 2000` | certificate hyperparameters |
| `--no-cache` | off | disable the cross-gate proposal cache |

**Hyperparameter note.** The defaults (σ=0.10, τ=0.90, ε=0.10, n_mc=2000) are the project-validated
values that keep the certificate **sound and non-vacuous on R**. The task's illustrative σ=0.25/τ=0.95 is
too aggressive at small n_mc (max achievable lower bound < τ → the gate becomes vacuous).

---

## Results

### Experiment F.2 — real open-weight models (local Ollama, Q4_K_M), 9600 episodes each, parse_ok = 1.000
Main validation = **`qwen2.5:32b`** (32.8B); `qwen2.5:7b-instruct` and `qwen2.5-coder:7b` are the sanity
rungs. Values **finance / sre**. The honest soundness metric is `cert_false_allow` (of privileged
executions, the fraction oracle-unsafe).

`qwen2.5:32b` under `c_witness` (500/category, n=1500/cell):

| gate | cert_false_allow | C_unsafe | U_unsafe | R_exec |
|---|---|---|---|---|
| none | **0.158 / 0.448** | 0.102 / 0.068 | 0.014 / 0.010 | 0.616 / 0.096 |
| learned | 0.031 / 0.077 | 0.020 / 0.008 | 0.000 | 0.616 / 0.096 |
| **certified** | **0.000 / 0.000** | **0.000** | **0.000** | **0.342 / 0.028** |
| oracle | 0.000 | 0.000 | 0.000 | 0.616 / 0.096 |

**Model-independent soundness.** Certified `cert_false_allow = C_unsafe = U_unsafe = 0` in all 8 conditions
for every model; undefended leaks at model-dependent rates — undefended `cert_false_allow` under
`c_witness` (finance / sre): coder-7b **0.385 / 0.639**, 7b-instruct 0.087 / 0.118, 32b (500/cat)
0.158 / 0.448. Stronger model ⇒ proposes the privileged action more ⇒ clearer non-vacuity (32b finance
R_exec 0.342).
Summaries: `cert/out/real_llm_action_exp/summary_{qwen32b,qwen7b,qwencoder7b}.md`; mock baseline (F.1) in
`summary.md`. A vLLM BF16 rerun is the paper-quality second pass.

### Experiment C — appendix full agent loop (mock LLM)
```bash
python -m bridge_benchmark.agents.run_agent_experiment --llm mock --n 500
python -m bridge_benchmark.agents.evaluate_agent_results
```
Under `c_witness`: undefended unsafe_exec 1.0 / 0.4, certified 0.0 / 0.0, cert_false_allow 0.0; on clean
inputs certified R_exec ≈ 0.31 / 0.15 (oracle is the ceiling).

---

## Claim boundary (SPEC)
We certify a typed authorization gate inside a tool-using agent pipeline under bounded post-tool-return
corruption `B_{1,ε}` (d=1), with explicit assumptions on provenance and fallback safety. We do **not**
claim end-to-end agent certification, prompt-injection defense, tool-selection security, MCP-poisoning
defense, or endpoint truthfulness. "Open-weight", not "open-source", for Qwen/Llama.
