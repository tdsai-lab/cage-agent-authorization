# EXP-CX2 — deployment-horizon confidence for randomized smoothing

Source: NEW_EXP_OPA_CHECK.md (P0). ε=0.1, σ=0.1, τ=0.9, α_total=0.01, fixed n_mc=2000, seeds=[0, 1, 2], certifying ≤200 exact robust-safe records/domain. d=1.

### finance

**RS R_allow vs horizon T (fixed MC budget), + Lipschitz (horizon-invariant):**

| scheme | lifetime bound | T=1e3 | T=1e4 | T=1e5 | T=1e6 |
|---|--:|--:|--:|--:|--:|
| per_record_const (R_allow) | min(1,T·1e-3) | 0.125 | 0.125 | 0.125 | 0.125 |
| bonferroni (R_allow) | 0.01 | 0.035 | 0.02 | 0.01 | 0.005 |
| alpha_spending (R_allow early/late) | 0.01 | 0.21/0.005 | 0.21/0.0 | 0.21/0.0 | 0.21/0.0 |
| adaptive_mc (R_allow) | 0.01 | 0.285 | 0.26 | 0.245 | 0.215 |
| adaptive_mc (median/p95 n_mc) | — | 8000/8000 | 8000/8000 | 8000/8000 | 8000/8000 |
| **lip_fallback (R_allow)** | **0** | **0.6383** | **0.6383** | **0.6383** | **0.6383** |

### sre

**RS R_allow vs horizon T (fixed MC budget), + Lipschitz (horizon-invariant):**

| scheme | lifetime bound | T=1e3 | T=1e4 | T=1e5 | T=1e6 |
|---|--:|--:|--:|--:|--:|
| per_record_const (R_allow) | min(1,T·1e-3) | 0.145 | 0.145 | 0.145 | 0.145 |
| bonferroni (R_allow) | 0.01 | 0.065 | 0.025 | 0.005 | 0.0 |
| alpha_spending (R_allow early/late) | 0.01 | 0.185/0.0 | 0.185/0.0 | 0.185/0.0 | 0.185/0.0 |
| adaptive_mc (R_allow) | 0.01 | 0.295 | 0.275 | 0.25 | 0.24 |
| adaptive_mc (median/p95 n_mc) | — | 8000/8000 | 8000/8000 | 8000/8000 | 8000/8000 |
| **lip_fallback (R_allow)** | **0** | **0.5717** | **0.5717** | **0.5717** | **0.5717** |

### ops

**RS R_allow vs horizon T (fixed MC budget), + Lipschitz (horizon-invariant):**

| scheme | lifetime bound | T=1e3 | T=1e4 | T=1e5 | T=1e6 |
|---|--:|--:|--:|--:|--:|
| per_record_const (R_allow) | min(1,T·1e-3) | 0.12 | 0.12 | 0.12 | 0.12 |
| bonferroni (R_allow) | 0.01 | 0.055 | 0.025 | 0.005 | 0.0 |
| alpha_spending (R_allow early/late) | 0.01 | 0.18/0.0 | 0.18/0.0 | 0.18/0.0 | 0.18/0.0 |
| adaptive_mc (R_allow) | 0.01 | 0.275 | 0.255 | 0.23 | 0.22 |
| adaptive_mc (median/p95 n_mc) | — | 8000/8000 | 8000/8000 | 8000/8000 | 8000/8000 |
| **lip_fallback (R_allow)** | **0** | **0.6583** | **0.6583** | **0.6583** | **0.6583** |

**Verdict.** KILL-CRITERION MET (as pre-registered): under a fixed MC budget the RS lifetime correction (Bonferroni α_total/T) drives R_allow down as T grows — RS goes toward vacuous beyond a small horizon, so RS must be scoped to bounded batches / offline decisions. The deterministic 1-Lipschitz certificate is horizon-INVARIANT (no α, no MC) and stays the PRIMARY runtime backend; adaptive MC can buy back utility only at a growing sample cost (median/p95 n_mc reported).
