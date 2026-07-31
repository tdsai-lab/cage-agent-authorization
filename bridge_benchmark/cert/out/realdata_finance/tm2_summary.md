# Real-data finance — TM2 certificate over B_{1,ε}(z) (NEW_EXPS_7 Part B)

- source: **IEEE-CIS** real transaction features; risk model AUC grounds `risk_score`. Oracle = constructed provenance-threshold policy (θ_base=0.489, δ=0.08, ε=0.1). backend=`mock_injection` model=`mock`.

Certificate soundness / non-vacuity on real-data records. `R_allow` = robust-safe records allowed (utility); `C_allow`/`U_allow` ≈ 0 (soundness on joint-only-unsafe and clean-unsafe); `cert_false_allow` = fraction of allowed privileged executions that are actually unsafe over B_{1,ε} (target 0).

| gate | n | R_allow | C_allow | U_allow | A_allow | B_allow | cert_false_allow |
| --- | --- | --- | --- | --- | --- | --- | --- |
| none | 600 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 0.8 |
| rule | 600 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 0.75 |
| learned | 600 | 1.0 | 1.0 | 0.0 | 0.9917 | 1.0 | 0.7495 |
| certified | 600 | 0.2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

**Reading.** The certified gate is sound (`C_allow`/`U_allow`/`cert_false_allow`≈0) and non-vacuous (`R_allow`>0) on the real-data feature distribution; the learned gate has residual `C_allow` (the TM2 gap the certificate closes).

