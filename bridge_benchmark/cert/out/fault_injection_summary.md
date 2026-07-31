# PLAN.md #16 — measured corruption budget B_{d,eps} (fault injection)

Budget under test: **B_{1,0.1}**. Each row injects a concrete adapter fault and measures the drift `(d, eps)`. `frac_in_B_1_budget` = fraction landing inside the asserted budget. `param_free` faults are pure measurement (no tuned parameter).

| substrate | fault | n | free | Pr[d=0] | Pr[d=1] | Pr[d>=2] | eps p50 | eps p90 | eps p95 | frac eps<=b | **frac in B_{1,b}** |
|---|---|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---:|
| ieee_cis | wrong_provenance_binding | 4000 | Y | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | **1.000** |
| ieee_cis | wrong_policy_pack | 4000 | Y | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | **1.000** |
| ieee_cis | toctou_env_label | 4000 | Y | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | **1.000** |
| ieee_cis | stale_cache | 4000 | Y | 1.000 | 0.000 | 0.000 | 0.061 | 0.252 | 0.376 | 0.631 | **0.631** |
| ieee_cis | numeric_jitter | 4000 | n | 1.000 | 0.000 | 0.000 | 0.046 | 0.067 | 0.074 | 0.997 | **0.997** |
| ieee_cis | normalization_skew | 4000 | n | 1.000 | 0.000 | 0.000 | 0.042 | 0.078 | 0.090 | 0.974 | **0.974** |
| ieee_cis | schema_skew | 4000 | Y | 1.000 | 0.000 | 0.000 | 0.522 | 0.992 | 1.103 | 0.195 | **0.195** |
| ieee_cis | cache_key_collision | 4000 | Y | 1.000 | 0.000 | 0.000 | 0.630 | 1.044 | 1.147 | 0.021 | **0.021** |
| ieee_cis | POOLED_MIX | 4000 | n | 0.717 | 0.283 | 0.000 | 0.037 | 0.244 | 0.578 | 0.833 | **0.833** |
| financial_compliance | wrong_provenance_binding | 4000 | Y | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | **1.000** |
| financial_compliance | wrong_policy_pack | 4000 | Y | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | **1.000** |
| financial_compliance | toctou_env_label | 4000 | Y | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | **1.000** |
| financial_compliance | stale_cache | 4000 | Y | 1.000 | 0.000 | 0.000 | 0.231 | 0.340 | 0.378 | 0.031 | **0.031** |
| financial_compliance | numeric_jitter | 4000 | n | 1.000 | 0.000 | 0.000 | 0.051 | 0.078 | 0.086 | 0.987 | **0.987** |
| financial_compliance | normalization_skew | 4000 | n | 1.000 | 0.000 | 0.000 | 0.049 | 0.092 | 0.104 | 0.936 | **0.936** |
| financial_compliance | schema_skew | 4000 | Y | 1.000 | 0.000 | 0.000 | 0.414 | 0.940 | 1.069 | 0.119 | **0.119** |
| financial_compliance | cache_key_collision | 4000 | Y | 1.000 | 0.000 | 0.000 | 0.756 | 1.073 | 1.157 | 0.001 | **0.001** |
| financial_compliance | POOLED_MIX | 4000 | n | 0.728 | 0.272 | 0.000 | 0.051 | 0.314 | 0.536 | 0.704 | **0.704** |
| sre_monitoring | wrong_provenance_binding | 4000 | Y | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | **1.000** |
| sre_monitoring | wrong_policy_pack | 4000 | Y | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | **1.000** |
| sre_monitoring | toctou_env_label | 4000 | Y | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | **1.000** |
| sre_monitoring | stale_cache | 4000 | Y | 1.000 | 0.000 | 0.000 | 0.224 | 0.345 | 0.383 | 0.033 | **0.033** |
| sre_monitoring | numeric_jitter | 4000 | n | 1.000 | 0.000 | 0.000 | 0.052 | 0.079 | 0.088 | 0.984 | **0.984** |
| sre_monitoring | normalization_skew | 4000 | n | 1.000 | 0.000 | 0.000 | 0.050 | 0.092 | 0.103 | 0.938 | **0.938** |
| sre_monitoring | schema_skew | 4000 | Y | 1.000 | 0.000 | 0.000 | 0.428 | 0.994 | 1.120 | 0.133 | **0.133** |
| sre_monitoring | cache_key_collision | 4000 | Y | 1.000 | 0.000 | 0.000 | 0.781 | 1.110 | 1.195 | 0.001 | **0.001** |
| sre_monitoring | POOLED_MIX | 4000 | n | 0.728 | 0.272 | 0.000 | 0.052 | 0.315 | 0.537 | 0.698 | **0.698** |

**Reads.** (1) Atomic provenance/policy/TOCTOU faults each change exactly one discrete atom (Pr[d=1]=1, eps=0), and NO single fault reaches d>=2 -> `d=1` is the natural single-fault granularity, not a tuned choice (d>=2 needs two compounded faults). (2) On REAL IEEE-CIS data, a same-surface stale read drifts modestly (p90~0.25, ~64% within eps=0.10) and re-read jitter / normalizer skew sit ~0.93-0.99 within budget. (3) `schema_skew` (column transposition) and `cache_key_collision` (wrong-entity serve) are the measured OUT-of-budget tails -> the documented scope cliff, exactly the faults a validation stage is meant to catch (schema-version / key integrity checks; motivates the per-stage eps shrink #19 and the out-of-budget red team #21). The budget is thus MEASURED, not chosen to make the attack exist; deriving a per-domain eps_emp and re-sweeping R_allow is #17/#20.
