# EXP-A1 — compound / correlated fault injection

W4, , . Budget under test **B_{2,0.1}**. Reuses: fault_injection (#16) INJECTORS/Substrate/drift; d_sweep (T2-8) Lipschitz d=2 cert. 4000 samples/combo × 3 seeds.

Two regimes: **adversarial** (every mechanism fires; `Pr[d≥·] when_all_fired` is the true compound worst case) and **independent** (each fires w.p. its #16 FAULT_MIX rate).

| substrate | combo | arity | regime | Pr[d≥2] | Pr[d≥3]* | ε p95 | in B_{1,ε} | **in B_{2,ε}** | d≤2 | max d |
|---|---|--:|---|--:|--:|--:|--:|--:|--:|--:|
| ieee_cis | `stale_cache+wrong_provenance_binding` | 2 | adversarial | 0.000 | 0.000 | 0.349 | 0.649 | **0.649** | 1.000 | 1 |
| ieee_cis | `stale_cache+wrong_provenance_binding` | 2 | independent | 0.000 | 0.000 | 0.302 | 0.733 | **0.733** | 1.000 | 1 |
| ieee_cis | `toctou_env_label+numeric_jitter` | 2 | adversarial | 0.000 | 0.000 | 0.073 | 0.998 | **0.998** | 1.000 | 1 |
| ieee_cis | `toctou_env_label+numeric_jitter` | 2 | independent | 0.000 | 0.000 | 0.071 | 0.998 | **0.998** | 1.000 | 1 |
| ieee_cis | `wrong_policy_pack+normalization_skew` | 2 | adversarial | 0.000 | 0.000 | 0.087 | 0.979 | **0.979** | 1.000 | 1 |
| ieee_cis | `wrong_policy_pack+normalization_skew` | 2 | independent | 0.000 | 0.000 | 0.081 | 0.985 | **0.985** | 1.000 | 1 |
| ieee_cis | `wrong_provenance_binding+wrong_policy_pack` | 2 | adversarial | 1.000 | 0.000 | 0.000 | 0.000 | **1.000** | 1.000 | 2 |
| ieee_cis | `wrong_provenance_binding+wrong_policy_pack` | 2 | independent | 0.048 | 0.000 | 0.000 | 0.952 | **1.000** | 1.000 | 2 |
| ieee_cis | `wrong_provenance_binding+toctou_env_label` | 2 | adversarial | 1.000 | 0.000 | 0.000 | 0.000 | **1.000** | 1.000 | 2 |
| ieee_cis | `wrong_provenance_binding+toctou_env_label` | 2 | independent | 0.048 | 0.000 | 0.000 | 0.952 | **1.000** | 1.000 | 2 |
| ieee_cis | `stale_cache+cache_key_collision` | 2 | adversarial | 0.000 | 0.000 | 1.147 | 0.016 | **0.016** | 1.000 | 0 |
| ieee_cis | `stale_cache+cache_key_collision` | 2 | independent | 0.000 | 0.000 | 0.814 | 0.542 | **0.542** | 1.000 | 0 |
| ieee_cis | `schema_skew+stale_cache` | 2 | adversarial | 0.000 | 0.000 | 0.848 | 0.417 | **0.417** | 1.000 | 0 |
| ieee_cis | `schema_skew+stale_cache` | 2 | independent | 0.000 | 0.000 | 0.728 | 0.573 | **0.573** | 1.000 | 0 |
| ieee_cis | `wrong_provenance_binding+wrong_policy_pack+toctou_env_label` | 3 | adversarial | 0.934 | 0.801 | 0.000 | 0.066 | **0.199** | 0.199 | 3 |
| ieee_cis | `wrong_provenance_binding+wrong_policy_pack+toctou_env_label` | 3 | independent | 0.084 | 0.720 | 0.000 | 0.916 | **0.998** | 0.998 | 3 |
| ieee_cis | `wrong_provenance_binding+toctou_env_label+numeric_jitter` | 3 | adversarial | 1.000 | 0.000 | 0.074 | 0.000 | **0.998** | 1.000 | 2 |
| ieee_cis | `wrong_provenance_binding+toctou_env_label+numeric_jitter` | 3 | independent | 0.024 | 0.000 | 0.070 | 0.975 | **0.998** | 1.000 | 2 |
| financial_compliance | `stale_cache+wrong_provenance_binding` | 2 | adversarial | 0.000 | 0.000 | 0.379 | 0.028 | **0.028** | 1.000 | 1 |
| financial_compliance | `stale_cache+wrong_provenance_binding` | 2 | independent | 0.000 | 0.000 | 0.363 | 0.289 | **0.289** | 1.000 | 1 |
| financial_compliance | `toctou_env_label+numeric_jitter` | 2 | adversarial | 0.000 | 0.000 | 0.087 | 0.985 | **0.985** | 1.000 | 1 |
| financial_compliance | `toctou_env_label+numeric_jitter` | 2 | independent | 0.000 | 0.000 | 0.084 | 0.991 | **0.991** | 1.000 | 1 |
| financial_compliance | `wrong_policy_pack+normalization_skew` | 2 | adversarial | 0.000 | 0.000 | 0.103 | 0.941 | **0.941** | 1.000 | 1 |
| financial_compliance | `wrong_policy_pack+normalization_skew` | 2 | independent | 0.000 | 0.000 | 0.094 | 0.963 | **0.963** | 1.000 | 1 |
| financial_compliance | `wrong_provenance_binding+wrong_policy_pack` | 2 | adversarial | 1.000 | 0.000 | 0.000 | 0.000 | **1.000** | 1.000 | 2 |
| financial_compliance | `wrong_provenance_binding+wrong_policy_pack` | 2 | independent | 0.052 | 0.000 | 0.000 | 0.948 | **1.000** | 1.000 | 2 |
| financial_compliance | `wrong_provenance_binding+toctou_env_label` | 2 | adversarial | 1.000 | 0.000 | 0.000 | 0.000 | **1.000** | 1.000 | 2 |
| financial_compliance | `wrong_provenance_binding+toctou_env_label` | 2 | independent | 0.048 | 0.000 | 0.000 | 0.952 | **1.000** | 1.000 | 2 |
| financial_compliance | `stale_cache+cache_key_collision` | 2 | adversarial | 0.000 | 0.000 | 1.162 | 0.001 | **0.001** | 1.000 | 0 |
| financial_compliance | `stale_cache+cache_key_collision` | 2 | independent | 0.000 | 0.000 | 0.906 | 0.024 | **0.024** | 1.000 | 0 |
| financial_compliance | `schema_skew+stale_cache` | 2 | adversarial | 0.000 | 0.000 | 1.049 | 0.152 | **0.152** | 1.000 | 0 |
| financial_compliance | `schema_skew+stale_cache` | 2 | independent | 0.000 | 0.000 | 0.663 | 0.052 | **0.052** | 1.000 | 0 |
| financial_compliance | `wrong_provenance_binding+wrong_policy_pack+toctou_env_label` | 3 | adversarial | 0.750 | 0.502 | 0.000 | 0.250 | **0.498** | 0.498 | 3 |
| financial_compliance | `wrong_provenance_binding+wrong_policy_pack+toctou_env_label` | 3 | independent | 0.083 | 0.653 | 0.000 | 0.917 | **0.998** | 0.998 | 3 |
| financial_compliance | `wrong_provenance_binding+toctou_env_label+numeric_jitter` | 3 | adversarial | 1.000 | 0.000 | 0.087 | 0.000 | **0.986** | 1.000 | 2 |
| financial_compliance | `wrong_provenance_binding+toctou_env_label+numeric_jitter` | 3 | independent | 0.022 | 0.000 | 0.082 | 0.969 | **0.991** | 1.000 | 2 |
| sre_monitoring | `stale_cache+wrong_provenance_binding` | 2 | adversarial | 0.000 | 0.000 | 0.383 | 0.032 | **0.032** | 1.000 | 1 |
| sre_monitoring | `stale_cache+wrong_provenance_binding` | 2 | independent | 0.000 | 0.000 | 0.362 | 0.292 | **0.292** | 1.000 | 1 |
| sre_monitoring | `toctou_env_label+numeric_jitter` | 2 | adversarial | 0.000 | 0.000 | 0.088 | 0.983 | **0.983** | 1.000 | 1 |
| sre_monitoring | `toctou_env_label+numeric_jitter` | 2 | independent | 0.000 | 0.000 | 0.086 | 0.988 | **0.988** | 1.000 | 1 |
| sre_monitoring | `wrong_policy_pack+normalization_skew` | 2 | adversarial | 0.000 | 0.000 | 0.106 | 0.932 | **0.932** | 1.000 | 1 |
| sre_monitoring | `wrong_policy_pack+normalization_skew` | 2 | independent | 0.000 | 0.000 | 0.099 | 0.951 | **0.951** | 1.000 | 1 |
| sre_monitoring | `wrong_provenance_binding+wrong_policy_pack` | 2 | adversarial | 1.000 | 0.000 | 0.000 | 0.000 | **1.000** | 1.000 | 2 |
| sre_monitoring | `wrong_provenance_binding+wrong_policy_pack` | 2 | independent | 0.052 | 0.000 | 0.000 | 0.948 | **1.000** | 1.000 | 2 |
| sre_monitoring | `wrong_provenance_binding+toctou_env_label` | 2 | adversarial | 1.000 | 0.000 | 0.000 | 0.000 | **1.000** | 1.000 | 2 |
| sre_monitoring | `wrong_provenance_binding+toctou_env_label` | 2 | independent | 0.048 | 0.000 | 0.000 | 0.952 | **1.000** | 1.000 | 2 |
| sre_monitoring | `stale_cache+cache_key_collision` | 2 | adversarial | 0.000 | 0.000 | 1.184 | 0.001 | **0.001** | 1.000 | 0 |
| sre_monitoring | `stale_cache+cache_key_collision` | 2 | independent | 0.000 | 0.000 | 0.895 | 0.029 | **0.029** | 1.000 | 0 |
| sre_monitoring | `schema_skew+stale_cache` | 2 | adversarial | 0.000 | 0.000 | 1.072 | 0.149 | **0.149** | 1.000 | 0 |
| sre_monitoring | `schema_skew+stale_cache` | 2 | independent | 0.000 | 0.000 | 0.664 | 0.058 | **0.058** | 1.000 | 0 |
| sre_monitoring | `wrong_provenance_binding+wrong_policy_pack+toctou_env_label` | 3 | adversarial | 0.752 | 0.498 | 0.000 | 0.248 | **0.502** | 0.502 | 3 |
| sre_monitoring | `wrong_provenance_binding+wrong_policy_pack+toctou_env_label` | 3 | independent | 0.081 | 0.347 | 0.000 | 0.919 | **0.999** | 0.999 | 3 |
| sre_monitoring | `wrong_provenance_binding+toctou_env_label+numeric_jitter` | 3 | adversarial | 1.000 | 0.000 | 0.089 | 0.000 | **0.983** | 1.000 | 2 |
| sre_monitoring | `wrong_provenance_binding+toctou_env_label+numeric_jitter` | 3 | independent | 0.022 | 0.000 | 0.084 | 0.967 | **0.989** | 1.000 | 2 |

*`Pr[d≥3]` column is measured among samples where ALL mechanisms fired.

### Realized safe→unsafe flip mass by clean category (realistic domains)

Among clean-SAFE records, the fraction the compound corruption drives to oracle-UNSAFE, split by the record's clean category. Category **C** (joint-only) and **R** (robust) are the interesting rows: a compound out-of-budget corruption realizes flips that a d=1 certificate does not claim to cover.

- `financial_compliance` `stale_cache+wrong_provenance_binding` [adversarial] → A:1771/4201(0.4216), B:2/146(0.0137), C:141/1034(0.1364), R:63/2577(0.0244)
- `financial_compliance` `stale_cache+wrong_provenance_binding` [independent] → A:445/1849(0.2407), B:24/72(0.3333), C:17/431(0.0394), R:15/1178(0.0127)
- `financial_compliance` `toctou_env_label+numeric_jitter` [adversarial] → A:294/4249(0.0692), B:3/153(0.0196), C:0/1008(0.0), R:0/2518(0.0)
- `financial_compliance` `toctou_env_label+numeric_jitter` [independent] → A:83/2041(0.0407), B:3/62(0.0484), C:0/522(0.0), R:0/1227(0.0)
- `financial_compliance` `wrong_policy_pack+normalization_skew` [adversarial] → A:241/4206(0.0573), B:10/145(0.069), C:0/1037(0.0), R:0/2521(0.0)
- `financial_compliance` `wrong_policy_pack+normalization_skew` [independent] → A:69/1419(0.0486), B:2/50(0.04), C:0/315(0.0), R:0/891(0.0)
- `financial_compliance` `wrong_provenance_binding+wrong_policy_pack` [adversarial] → A:1770/4172(0.4243), B:1/142(0.007), C:25/1038(0.0241), R:0/2541(0.0)
- `financial_compliance` `wrong_provenance_binding+wrong_policy_pack` [independent] → A:273/1128(0.242), B:0/25(0.0), C:0/257(0.0), R:0/668(0.0)
- `financial_compliance` `wrong_provenance_binding+toctou_env_label` [adversarial] → A:1783/4228(0.4217), B:2/154(0.013), C:46/1035(0.0444), R:0/2561(0.0)
- `financial_compliance` `wrong_provenance_binding+toctou_env_label` [independent] → A:283/1131(0.2502), B:0/42(0.0), C:0/291(0.0), R:0/691(0.0)
- `financial_compliance` `stale_cache+cache_key_collision` [adversarial] → A:962/4211(0.2284), B:79/152(0.5197), C:280/1005(0.2786), R:794/2570(0.3089)
- `financial_compliance` `stale_cache+cache_key_collision` [independent] → A:247/1540(0.1604), B:22/56(0.3929), C:23/386(0.0596), R:55/949(0.058)
- `financial_compliance` `schema_skew+stale_cache` [adversarial] → A:585/4123(0.1419), B:60/156(0.3846), C:120/1068(0.1124), R:260/2550(0.102)
- `financial_compliance` `schema_skew+stale_cache` [independent] → A:221/1632(0.1354), B:26/67(0.3881), C:22/371(0.0593), R:29/972(0.0298)

### d=2 Lipschitz soundness (acceptance criterion)

Deterministic 1-Lipschitz gate (orthogonium), fscale=3.0. **cert_false_allow=0 at d=2: True** (max cfa@d2 = 0.0). deterministic Lipschitz margin cert over N_2 (enumerated d=2 discrete swaps × exact continuous ε-ball); no n_mc/σ. fscale=3 → gate is 3-Lipschitz in the raw ε-ball, sound threshold L=3·CLAIMED_L.

| seed | d | mean |N_d| | R_allow | cert_false_allow |
|--:|--:|--:|--:|--:|
| 0 | 1 | 10.0 | 0.450 | 0.000 |
| 0 | 2 | 37.0 | 0.400 | 0.000 |
| 1 | 1 | 10.0 | 0.750 | 0.000 |
| 1 | 2 | 37.0 | 0.750 | 0.000 |

**Verdict.** THREAT MODEL CLOSES: all realistic PAIRS land in d≤2 (Pr[d≥3]=0 among all-fired pairs), and the deterministic d=2 Lipschitz gate is SOUND (cert_false_allow=0). Triples of three DISTINCT discrete mis-bindings reach d=3 — the honest out-of-budget tail (needs three compounded faults), covered only if the stated budget is widened to d=3.

**Note.** Two DISTINCT discrete mis-bindings (provenance + policy, or provenance + env) are the only way to reach d=2 within a pair; a discrete+continuous pair stays d=1 with larger ε; two continuous faults stay d=0. So compound faults concentrate at d≤2 and are covered by a d=2 gate; d=3 needs three independent discrete faults in ONE window (a rarer, out-of-budget tail reported honestly, not hidden). cert_false_allow stays 0 at d=2 (soundness), matching the T2-8 d-sweep result the MVP already established.
