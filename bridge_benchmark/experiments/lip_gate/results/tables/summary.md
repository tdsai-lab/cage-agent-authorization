# EXP_LIP_VS_RS — Lipschitz vs smoothing backend (summary)

policy_provenance = **authored_provenance_conditioned_rego**. The deterministic certificate certifies the learned Lipschitz gate; oracle false-allows are empirical against the OPA policy. `R_allow == cert_recovery_vs_exact`.

## Table L1 — operating points (R_allow = recovery of exact robust-safe)

| domain | ε | backend | n_mc | R_allow | C_allow | U_allow | cert_false_allow | cost_ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| finance | 0.03 | exact_oracle | 0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0003 |
| finance | 0.03 | uncertified_lipgate | 0 | 0.975 | 0.8235 | 0.05 | 0.3953 | 7.8285 |
| finance | 0.03 | mlp_smoothing | 1500 | 0.525 | 0.0 | 0.0 | 0.0 | 6.8408 |
| finance | 0.03 | mlp_smoothing | 2000 | 0.55 | 0.0 | 0.0 | 0.0 | 8.1441 |
| finance | 0.03 | mlp_smoothing | 10000 | 0.5875 | 0.0 | 0.0 | 0.0 | 41.866 |
| finance | 0.03 | lipgate_smoothing | 2000 | 0.0375 | 0.0 | 0.0 | 0.0 | 46.5533 |
| finance | 0.03 | lipgate_smoothing | 10000 | 0.0625 | 0.0 | 0.0 | 0.0 | 62.8803 |
| finance | 0.03 | lipgate_deterministic | 0 | 0.55 | 0.0 | 0.0 | 0.0 | 7.8486 |
| finance | 0.03 | naive_marginal | 0 | 1.0 | 1.0 | 0.0 | 0.1753 | 0.0093 |
| finance | 0.1 | exact_oracle | 0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0004 |
| finance | 0.1 | uncertified_lipgate | 0 | 0.9875 | 0.96 | 0.0375 | 0.5241 | 7.8479 |
| finance | 0.1 | mlp_smoothing | 1500 | 0.1 | 0.0 | 0.0 | 0.0 | 6.8881 |
| finance | 0.1 | mlp_smoothing | 2000 | 0.15 | 0.0 | 0.0 | 0.0 | 8.2221 |
| finance | 0.1 | mlp_smoothing | 10000 | 0.3 | 0.0 | 0.0 | 0.0 | 47.3606 |
| finance | 0.1 | lipgate_smoothing | 2000 | 0.0 | 0.0 | 0.0 | 0.0 | 46.5881 |
| finance | 0.1 | lipgate_smoothing | 10000 | 0.0 | 0.0 | 0.0 | 0.0 | 62.9679 |
| finance | 0.1 | lipgate_deterministic | 0 | 0.2625 | 0.0 | 0.0 | 0.0 | 7.7932 |
| finance | 0.1 | naive_marginal | 0 | 1.0 | 1.0 | 0.0 | 0.3846 | 0.011 |
| sre | 0.03 | exact_oracle | 0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0003 |
| sre | 0.03 | uncertified_lipgate | 0 | 0.975 | 0.8235 | 0.0375 | 0.3953 | 7.7814 |
| sre | 0.03 | mlp_smoothing | 1500 | 0.5125 | 0.0 | 0.0 | 0.0 | 6.8512 |
| sre | 0.03 | mlp_smoothing | 2000 | 0.5125 | 0.0 | 0.0 | 0.0 | 8.1818 |
| sre | 0.03 | mlp_smoothing | 10000 | 0.6 | 0.0 | 0.0 | 0.0 | 46.8276 |
| sre | 0.03 | lipgate_smoothing | 2000 | 0.05 | 0.0 | 0.0 | 0.0 | 46.5742 |
| sre | 0.03 | lipgate_smoothing | 10000 | 0.075 | 0.0 | 0.0 | 0.0 | 62.959 |
| sre | 0.03 | lipgate_deterministic | 0 | 0.5625 | 0.0 | 0.0 | 0.0 | 7.7901 |
| sre | 0.03 | naive_marginal | 0 | 1.0 | 1.0 | 0.0 | 0.1753 | 0.0097 |
| sre | 0.1 | exact_oracle | 0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0003 |
| sre | 0.1 | uncertified_lipgate | 0 | 0.9875 | 0.96 | 0.025 | 0.5241 | 7.8108 |
| sre | 0.1 | mlp_smoothing | 1500 | 0.125 | 0.0 | 0.0 | 0.0 | 6.877 |
| sre | 0.1 | mlp_smoothing | 2000 | 0.1375 | 0.0 | 0.0 | 0.0 | 8.1676 |
| sre | 0.1 | mlp_smoothing | 10000 | 0.3125 | 0.0 | 0.0 | 0.0 | 47.1987 |
| sre | 0.1 | lipgate_smoothing | 2000 | 0.0 | 0.0 | 0.0 | 0.0 | 46.5472 |
| sre | 0.1 | lipgate_smoothing | 10000 | 0.0 | 0.0 | 0.0 | 0.0 | 62.9462 |
| sre | 0.1 | lipgate_deterministic | 0 | 0.2375 | 0.0 | 0.0 | 0.0 | 7.79 |
| sre | 0.1 | naive_marginal | 0 | 1.0 | 1.0 | 0.0 | 0.3846 | 0.011 |
| ops | 0.03 | exact_oracle | 0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0003 |
| ops | 0.03 | uncertified_lipgate | 0 | 0.975 | 0.8235 | 0.05 | 0.3906 | 7.7877 |
| ops | 0.03 | mlp_smoothing | 1500 | 0.525 | 0.0 | 0.0 | 0.0 | 6.9204 |
| ops | 0.03 | mlp_smoothing | 2000 | 0.5625 | 0.0 | 0.0 | 0.0 | 8.2063 |
| ops | 0.03 | mlp_smoothing | 10000 | 0.5875 | 0.0 | 0.0 | 0.0 | 48.8452 |
| ops | 0.03 | lipgate_smoothing | 2000 | 0.075 | 0.0 | 0.0 | 0.0 | 46.5206 |
| ops | 0.03 | lipgate_smoothing | 10000 | 0.075 | 0.0 | 0.0 | 0.0 | 62.88 |
| ops | 0.03 | lipgate_deterministic | 0 | 0.6 | 0.0 | 0.0 | 0.0 | 7.8176 |
| ops | 0.03 | naive_marginal | 0 | 1.0 | 1.0 | 0.0 | 0.1753 | 0.0094 |
| ops | 0.1 | exact_oracle | 0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0003 |
| ops | 0.1 | uncertified_lipgate | 0 | 0.9875 | 0.98 | 0.0375 | 0.5241 | 7.8078 |
| ops | 0.1 | mlp_smoothing | 1500 | 0.125 | 0.0 | 0.0 | 0.0 | 6.9336 |
| ops | 0.1 | mlp_smoothing | 2000 | 0.1625 | 0.0 | 0.0 | 0.0 | 8.2352 |
| ops | 0.1 | mlp_smoothing | 10000 | 0.325 | 0.0 | 0.0 | 0.0 | 45.4773 |
| ops | 0.1 | lipgate_smoothing | 2000 | 0.0 | 0.0 | 0.0 | 0.0 | 46.6471 |
| ops | 0.1 | lipgate_smoothing | 10000 | 0.0 | 0.0 | 0.0 | 0.0 | 62.9694 |
| ops | 0.1 | lipgate_deterministic | 0 | 0.4 | 0.0 | 0.0 | 0.0 | 7.7957 |
| ops | 0.1 | naive_marginal | 0 | 1.0 | 1.0 | 0.0 | 0.3846 | 0.011 |

## Table L2 — recovery decomposition (same LipGate: smoothing vs deterministic)

| domain | ε | lip_det | finite_mc_tax | smoothing_transition_tax | learned_margin_deficiency | det_gain_over_lowM | valid |
| --- | --- | --- | --- | --- | --- | --- | --- |
| finance | 0.03 | 0.55 | 0.025 | 0.4875 | 0.45 | 0.5125 | True |
| finance | 0.1 | 0.2625 | 0.0 | 0.2625 | 0.7375 | 0.2625 | True |
| ops | 0.03 | 0.6 | 0.0 | 0.525 | 0.4 | 0.525 | True |
| ops | 0.1 | 0.4 | 0.0 | 0.4 | 0.6 | 0.4 | True |
| sre | 0.03 | 0.5625 | 0.025 | 0.4875 | 0.4375 | 0.5125 | True |
| sre | 0.1 | 0.2375 | 0.0 | 0.2375 | 0.7625 | 0.2375 | True |

## Table L3 — cost (per-example latency)

| backend | ε | n_mc | mean_ms | p95_ms | relative_cost |
| --- | --- | --- | --- | --- | --- |
| opa_exact_oracle | 0.1 | 0 | 12.6282 | 14.9394 | 1.61 |
| mlp_smoothing | 0.1 | 1500 | 6.8883 | 6.9715 | 0.88 |
| mlp_smoothing | 0.1 | 2000 | 8.0119 | 8.4282 | 1.02 |
| mlp_smoothing | 0.1 | 10000 | 46.0364 | 55.658 | 5.87 |
| lipgate_deterministic | 0.1 | 0 | 7.8463 | 8.0694 | 1.0 |

**Reading.** At ε=0.10 smoothing is conservative; the deterministic margin certificate on the same 1-Lipschitz gate recovers more of the exact robust-safe set at lower cost and stays sound (C_allow=U_allow=cert_false_allow=0). The residual gap to exact is learned-margin deficiency, reported honestly. Smoothing remains the model-agnostic backend for non-Lipschitz / black-box gates.

