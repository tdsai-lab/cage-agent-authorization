# M3 = R2 — NAB fscale held-out selection (S29 protocol on NAB)

Rule: **largest fscale with cert_false_allow==0 on the SELECTION half; report on EVAL half**. ε=0.1, δ=0.08, grid=[2.0, 3.0, 4.0, 6.0], seeds=[0, 1, 2], d=1 (d=2 note).

| seed | selection grid (d=1) | fscale* (d1) | eval cfa (d1) | eval R_allow (d1) | eval acc | sound | fscale* (d2) |
|--:|---|--:|--:|--:|--:|:--:|--:|
| 0 | fs2.0:cfa0.0/R1.0 ; fs3.0:cfa0.0/R1.0 ; fs4.0:cfa0.0/R1.0 ; fs6.0:cfa0.0/R1.0 | 6.0 | 0.0 | 1.0 | 0.855 | Y | 6.0 |
| 1 | fs2.0:cfa0.0/R1.0 ; fs3.0:cfa0.0/R1.0 ; fs4.0:cfa0.0/R1.0 ; fs6.0:cfa0.0/R1.0 | 6.0 | 0.0 | 1.0 | 0.849 | Y | 6.0 |
| 2 | fs2.0:cfa0.0/R1.0 ; fs3.0:cfa0.0/R1.0 ; fs4.0:cfa0.0/R1.0 ; fs6.0:cfa0.0/R1.0 | 6.0 | 0.0 | 1.0 | 0.833 | Y | 6.0 |

Overall EVAL cert_false_allow max (d=1) **0.0**, eval R_allow mean **1.0**, all eval sound **True**, selection rule binds **False**.

**Verdict.** SELECTION OBJECTION RESOLVED on NAB: the held-out-selected fscale (d=1 selections [6.0, 6.0, 6.0]) keeps cert_false_allow=0 on the untouched EVAL half for every seed (max 0.0), eval R_allow mean 1.000; no soundness cliff appears in the grid on NAB (every fscale is sound on the selection half), so the rule does not bind but soundness generalizes to eval. d=2 note: sound fscales per seed [6.0, 6.0, 6.0] (the d≥2 threat-model operating point).
