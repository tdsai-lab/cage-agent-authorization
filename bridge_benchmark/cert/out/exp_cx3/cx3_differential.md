# EXP-CX3 — differential validation of CAGE-Exact (fragment.py)

Source: PLAN_CX3.md. OPA 1.17.1, ε=0.1, d=1, seed=0. 200 fragment policies × 1000 returns (200000 total) vs OPA-point + solver + dense-grid(k≤2); probes {'n_ball': 12, 'n_adv': 6, 'grid_steps': 21, 'n_samp': 200, 'n_opa_returns': 6}.

| metric | value |
|---|--:|
| total semantic mismatches | **1** |
| out-of-fragment refused | **20/20** |
| runtime median (µs/decision) | 38.927 |
| runtime log-log slope (|N_d|·m·k) | 0.65 |

**Verdict.** FAIL: 1 mismatches (0 hard) and/or 0 unsupported misses — minimise the counterexample and FIX THE CODE (never the test).
