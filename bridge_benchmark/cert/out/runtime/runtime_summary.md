# Runtime & cost reporting (NEW_EXPS_7 Part E)

- per-decision latency of `gate.evaluate(z,a)` over 300 category-balanced records/domain (single-thread, no batching). Certificate: σ=0.1, ε=0.1, τ=0.9, n_mc=2000.

| domain | gate | n_mc | discrete_branches | sigma | epsilon | tau | mean_latency_ms | p50_latency_ms | p95_latency_ms | decisions_per_second | R_allow | cert_false_allow |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| finance | none | 0 | 1 | 0.1 | 0.1 | 0.9 | 0.0002 | 0.0002 | 0.0002 | 4664015.28 | 1.0 | 0.6667 |
| finance | rule | 0 | 1 | 0.1 | 0.1 | 0.9 | 0.0036 | 0.0035 | 0.0057 | 276898.75 | 1.0 | 0.5 |
| finance | learned | 0 | 1 | 0.1 | 0.1 | 0.9 | 0.0804 | 0.0809 | 0.0854 | 12434.27 | 1.0 | 0.5 |
| finance | certified | 2000 | 9 | 0.1 | 0.1 | 0.9 | 10.2695 | 10.2432 | 10.4811 | 97.38 | 0.5 | 0.0 |
| sre | none | 0 | 1 | 0.1 | 0.1 | 0.9 | 0.0002 | 0.0002 | 0.0003 | 4314382.02 | 1.0 | 0.6667 |
| sre | rule | 0 | 1 | 0.1 | 0.1 | 0.9 | 0.0039 | 0.0036 | 0.006 | 256451.84 | 1.0 | 0.5 |
| sre | learned | 0 | 1 | 0.1 | 0.1 | 0.9 | 0.0809 | 0.0815 | 0.0861 | 12368.03 | 1.0 | 0.5 |
| sre | certified | 2000 | 9 | 0.1 | 0.1 | 0.9 | 10.1997 | 10.1375 | 10.3116 | 98.04 | 0.22 | 0.0 |

## LLM proposal latency (separate from the gate)

- backend=`ollama` model=`qwen2.5:7b-instruct`: median LLM proposal latency **710.33 ms** (p95 751.67 ms) over 12 prompts. The gate / certificate latency above is incurred AFTER the proposal and is typically dominated by the LLM decode for the cheaper gates.

**Reading.** `none`/`rule`/`learned` are sub-millisecond pointwise decisions. The `certified` gate runs Gaussian-RS Monte-Carlo (`n_mc` samples) over each of the `discrete_branches` enumerated states, so it is materially slower — **the certified gate is intended for high-stakes actions where abstention and additional latency are acceptable; it is not free.** Latency scales ~linearly in `n_mc × discrete_branches`; lowering `n_mc` trades the certificate's confidence margin for speed.

