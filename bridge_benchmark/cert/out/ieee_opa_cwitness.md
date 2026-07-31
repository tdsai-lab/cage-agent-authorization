# PLAN #9b — engine-labelled Category-C witness on a continuous executable policy (real IEEE-CIS)

OPA **1.17.1** (policy hash `df47234e472bac80`) evaluating `ieee_fraud.rego` over **4000 REAL IEEE-CIS transactions**, eps=0.1. Every safe/unsafe label below is the OPA engine's, not our analytic oracle.

- engine category distribution: U=800 A=800 B=800 **C=800 (20.0%)** R=800
- engine vs stored analytic category agreement: **1.0** (C-set Jaccard 1.0) — the real engine reproduces the taxonomy
- fraud rate among engine-C (external plausibility only): 0.035

## Engine-verified C-witness traces (each label is OPA's)

| clean tool | provenance swap | risk_score | clean safe | swap-only | +eps-only | **swap+eps** |
|---|---|---:|:--:|:--:|:--:|:--:|
| payment_gateway_loose | →identity_risk_strict | 0.4466 | safe | safe | safe | **UNSAFE** |
| payment_gateway_loose | →identity_risk_strict | 0.4671 | safe | safe | safe | **UNSAFE** |
| payment_gateway_loose | →identity_risk_strict | 0.3905 | safe | safe | safe | **UNSAFE** |
| manual_screen_loose | →device_risk_strict | 0.4565 | safe | safe | safe | **UNSAFE** |
| payment_gateway_loose | →identity_risk_strict | 0.4092 | safe | safe | safe | **UNSAFE** |

**Reads.** The OPA engine itself labels real transactions where neither the d=1 provenance swap alone nor the eps risk move alone flips safety, but the JOINT move does — Category C, on a continuous executable policy over real data, engine-verified. The discrete half of each witness IS the #16 `wrong_provenance_binding` fault (loose↔strict, d=1) and the continuous half is risk_score staleness within eps, so the witness lies in B_{1,eps} and is reachable by a real fault → the #29 agent would execute it and the certified joint gate blocks it. This closes #9 → #9b → #16 → #29.
