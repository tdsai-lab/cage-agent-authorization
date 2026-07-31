# Runtime & cost reporting (NEW_EXPS_7 Part E)

- per-decision latency of `gate.evaluate(z,a)` over 300 category-balanced records/domain (single-thread, no batching). Certificate: σ=0.1, ε=0.1, τ=0.9, n_mc=2000.

| domain | gate | n_mc | discrete_branches | sigma | epsilon | tau | mean_latency_ms | p50_latency_ms | p95_latency_ms | decisions_per_second | R_allow | cert_false_allow |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| finance | none | 0 | 1 | 0.1 | 0.1 | 0.9 | 0.0002 | 0.0002 | 0.0003 | 4504076.56 | 1.0 | 0.6667 |
| finance | rule | 0 | 1 | 0.1 | 0.1 | 0.9 | 0.0036 | 0.0034 | 0.0058 | 277176.45 | 1.0 | 0.5 |
| finance | learned | 0 | 1 | 0.1 | 0.1 | 0.9 | 0.083 | 0.0834 | 0.0883 | 12044.81 | 1.0 | 0.5 |
| finance | certified | 2000 | 9 | 0.1 | 0.1 | 0.9 | 10.3541 | 10.3425 | 10.5697 | 96.58 | 0.5 | 0.0 |
| sre | none | 0 | 1 | 0.1 | 0.1 | 0.9 | 0.0002 | 0.0002 | 0.0003 | 4307862.16 | 1.0 | 0.6667 |
| sre | rule | 0 | 1 | 0.1 | 0.1 | 0.9 | 0.0039 | 0.0037 | 0.0062 | 253343.37 | 1.0 | 0.5 |
| sre | learned | 0 | 1 | 0.1 | 0.1 | 0.9 | 0.0829 | 0.0832 | 0.0881 | 12064.54 | 1.0 | 0.5 |
| sre | certified | 2000 | 9 | 0.1 | 0.1 | 0.9 | 10.3608 | 10.3292 | 10.5145 | 96.52 | 0.22 | 0.0 |

## LLM proposal latency (separate from the gate)

- backend=`ollama` model=`qwen3.6`: median LLM proposal latency **1435.14 ms** (p95 1482.3 ms) over 12 prompts. The gate / certificate latency above is incurred AFTER the proposal and is typically dominated by the LLM decode for the cheaper gates.

**Reading.** `none`/`rule`/`learned` are sub-millisecond pointwise decisions. The `certified` gate runs Gaussian-RS Monte-Carlo (`n_mc` samples) over each of the `discrete_branches` enumerated states, so it is materially slower — **the certified gate is intended for high-stakes actions where abstention and additional latency are acceptable; it is not free.** Latency scales ~linearly in `n_mc × discrete_branches`; lowering `n_mc` trades the certificate's confidence margin for speed.

