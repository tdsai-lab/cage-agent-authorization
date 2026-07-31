# EXP-C4/B4 — fscale held-out selection

Reuses d_sweep (T2-8) build_synthetic/build_opa/train_lipgate_generic/certify_lip_at_d. Rule: **largest fscale with cert_false_allow==0 on the SELECTION half; report on EVAL half**. ε=0.1, grid=[2.0, 3.0, 4.0, 6.0], seeds=[0, 1, 2], d=1.

### track synthetic

selected fscale*(s) [6.0, 6.0, 6.0]; **eval cert_FA max 0.0**, eval R_allow mean 0.9667, all eval sound **True**, selection rule binds **True**.

### track opa:finance

selected fscale*(s) [6.0, 6.0, 6.0]; **eval cert_FA max 0.0**, eval R_allow mean 0.7814, all eval sound **True**, selection rule binds **False**.

### Per-seed detail (all tracks in order)

| seed | selection grid | fscale* | eval cert_FA | eval R_allow | eval acc | sound |
|--:|---|--:|--:|--:|--:|:--:|
| 0 | fs2.0:cfa0.1/R0.45 ; fs3.0:cfa0.0/R0.675 ; fs4.0:cfa0.0/R0.775 ; fs6.0:cfa0.0/R0.925 | 6.0 | 0.0 | 0.9 | 0.932 | Y |
| 1 | fs2.0:cfa0.0/R0.55 ; fs3.0:cfa0.0/R0.85 ; fs4.0:cfa0.0/R0.925 ; fs6.0:cfa0.0/R1.0 | 6.0 | 0.0 | 1.0 | 0.9447 | Y |
| 2 | fs2.0:cfa0.0/R0.5 ; fs3.0:cfa0.0/R0.675 ; fs4.0:cfa0.0/R0.875 ; fs6.0:cfa0.0/R0.975 | 6.0 | 0.0 | 1.0 | 0.9393 | Y |
| 0 | fs2.0:cfa0.0/R0.0256 ; fs3.0:cfa0.0/R0.4872 ; fs4.0:cfa0.0/R0.5897 ; fs6.0:cfa0.0/R0.7692 | 6.0 | 0.0 | 0.85 | 0.9333 | Y |
| 1 | fs2.0:cfa0.0/R0.1842 ; fs3.0:cfa0.0/R0.4737 ; fs4.0:cfa0.0/R0.6579 ; fs6.0:cfa0.0/R0.8421 | 6.0 | 0.0 | 0.7692 | 0.9 | Y |
| 2 | fs2.0:cfa0.0/R0.125 ; fs3.0:cfa0.0/R0.575 ; fs4.0:cfa0.0/R0.8 ; fs6.0:cfa0.0/R0.9 | 6.0 | 0.0 | 0.725 | 0.9167 | Y |

Overall EVAL cert_false_allow max **0.0**, all eval sound **True**.

**Verdict.** SELECTION OBJECTION RESOLVED: fscale chosen by the largest-cfa=0-on-SELECTION rule keeps cert_false_allow=0 on the untouched EVAL split (all tracks/seeds); the rule genuinely EXCLUDES the fscale(s) that break soundness on the SELECTION half (binds on ['synthetic']: at least one seed drops an fscale with sel cfa>0), and eval confirms cfa=0 with non-vacuous R_allow ⇒ the fscale headline is not outcome-conditioned.
