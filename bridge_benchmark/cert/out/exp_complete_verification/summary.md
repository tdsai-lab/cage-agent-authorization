# T1-1 — Complete-verification backend (MILP, rung 1.5)

Config: eps=0.1, sigma=0.1, tau=0.9, RS M=10000, seeds=[0, 1, 2], n_eval/seed(subset)=120, L2 outer polytope facets=8*2k.

Port fidelity (max |Δp_safe| vs sklearn predict_proba): 8.47e-22 (assert ≤ 1e-6). Analytic-halfspace validation agreement: 1.0000 (assert = 1.0).

Backend = MILP branch of complete verification (α,β-CROWN not installable here). L2 ball is certified via a **circumscribing** outer polytope (sound: verified-safe ⇒ truly L2-safe); `polytope_slack` = outer/inner radius (→1 = tight).

| domain | backend | R_allow (mean±std) | cert_false_allow | mean_solve_ms | polytope_slack | mean_branches |
| --- | --- | --- | --- | --- | --- | --- |
| finance | complete_verif | 1.0000 ± 0.0000 | 0.0000 | 1777.639 | 1.25488 | 9.0 |
| finance | randomized_smoothing | 0.3170 ± 0.1170 | 0.0000 | 61.077 | 1.25488 | 9.0 |
| finance | lipschitz | 0.3235 ± 0.0994 | 0.0000 | 7.152 | 1.25488 | 9.0 |
| sre | complete_verif | 1.0000 ± 0.0000 | 0.0000 | 1630.798 | 1.25488 | 9.0 |
| sre | randomized_smoothing | 0.3332 ± 0.1490 | 0.0000 | 83.764 | 1.25488 | 9.0 |
| sre | lipschitz | 0.3461 ± 0.1604 | 0.0000 | 11.317 | 1.25488 | 9.0 |
| ops | complete_verif | 1.0000 ± 0.0000 | 0.0085 | 1763.205 | 1.25488 | 9.0 |
| ops | randomized_smoothing | 0.3420 ± 0.1372 | 0.0000 | 132.001 | 1.25488 | 9.0 |
| ops | lipschitz | 0.3677 ± 0.0954 | 0.0000 | 16.594 | 1.25488 | 9.0 |

**Reading.** All backends certify the SAME learned OPA gate. The complete verifier pays no σΦ⁻¹(τ) buffer / no MC / no Lipschitz constraint, so R_allow^CV should meet or exceed R_allow^RS(M) with cert_false_allow=0. If CV≈RS, the smoothing-transition-tax decomposition (LIP) is mis-attributed (kill criterion).

