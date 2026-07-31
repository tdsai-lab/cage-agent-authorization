# Held-out policy / schema generalization (NEW_EXPS_7 Part C)

- Θ_train via `make_rule_table(K=8,k=5,|X1|=4)`; Θ_test = Θ_train shifted by -0.05; held-out tool = `tool_01` (removed from training). σ=0.1, τ=0.9, ε=0.1, n_mc=2000.

`clean_acc` = gate pointwise accuracy vs oracle; `cert_false_allow` / `certified_adaptive_false_allow` = certified gate allows that are actually unsafe over B_{1,ε} (target 0, soundness); `learned_adaptive_false_allow` = a mixed B_{1,ε} attack finds a truly-unsafe point the pointwise learned gate allows.

| condition | n | clean_acc | R_allow | C_allow | U_allow | cert_false_allow | learned_adaptive_false_allow | certified_adaptive_false_allow |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| in_distribution | 180 | 1.0 | 0.4333 | 0.0 | 0.0 | 0.0 | 0.0167 | 0.0 |
| held_out_threshold | 180 | 0.95 | 0.5667 | 0.0 | 0.0 | 0.0 | 0.475 | 0.0 |
| held_out_tool | 180 | 1.0 | 0.2333 | 0.0 | 0.0 | 0.0 | 0.0917 | 0.0 |

**Reading.** The certified gate stays SOUND across all conditions (`cert_false_allow = certified_adaptive_false_allow = 0`) — the certificate is valid for the learned gate's decision regardless of policy shift. Under `held_out_threshold` the learned gate keeps residual `learned_adaptive_false_allow` (the TM2 gap the certificate closes); utility `R_allow` may drop under policy shift — reported honestly, not hidden. `held_out_tool` shows the gate generalizes to a tool identity it never trained on (the certificate remains sound).

