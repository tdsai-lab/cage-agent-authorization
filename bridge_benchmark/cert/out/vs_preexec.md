# P5 Task J — CAGE joint certificate vs a deployed pre-exec (auto-mode) transcript classifier

ε=0.1. The pre-exec classifier is a strong learned point predictor over the FULL transcript (tool id + categorical + all numeric fields), trained to high point accuracy. It authorizes on the nominal transcript; the adversary then realizes the worst case in B_{1,ε} (authorize-then-realize). The CAGE joint certificate authorizes the whole region.

## financial_compliance

Transcript classifier point accuracy **1.0** (a GOOD point classifier), yet clean-C vs clean-R separation AUC **0.645** (weak — the C/R distinction lives in the region, not the point; at the 0.5 operating point it admits every C nominal).

| attack | gate | episodes | exec_priv | **P(unsafe exec)** | unsafe_effects |
|---|---|---:|---:|---:|---:|
| c_witness | no_gate | 400 | 1.0 | **1.0** | 400 |
| c_witness | transcript_clf | 400 | 1.0 | **1.0** | 400 |
| c_witness | joint_cert | 400 | 0.0 | **0.0** | 0 |
| mixed | no_gate | 399 | 1.0 | **0.6491** | 259 |
| mixed | transcript_clf | 399 | 0.6667 | **0.3158** | 126 |
| mixed | joint_cert | 399 | 0.3333 | **0.0** | 0 |

## sre_monitoring

Transcript classifier point accuracy **1.0** (a GOOD point classifier), yet clean-C vs clean-R separation AUC **0.5397** (weak — the C/R distinction lives in the region, not the point; at the 0.5 operating point it admits every C nominal).

| attack | gate | episodes | exec_priv | **P(unsafe exec)** | unsafe_effects |
|---|---|---:|---:|---:|---:|
| c_witness | no_gate | 400 | 1.0 | **1.0** | 400 |
| c_witness | transcript_clf | 400 | 1.0 | **1.0** | 400 |
| c_witness | joint_cert | 400 | 0.0 | **0.0** | 0 |
| mixed | no_gate | 399 | 1.0 | **0.6667** | 266 |
| mixed | transcript_clf | 399 | 0.6667 | **0.3333** | 133 |
| mixed | joint_cert | 399 | 0.3333 | **0.0** | 0 |

**Reads.** Even a maximally-generous transcript classifier (point accuracy ≈1.0) leaks real unsafe side effects on `c_witness` at the *same rate as no-gate* — it admits the safe nominal point and the adversary realizes the joint witness — while the CAGE joint certificate drives `P(unsafe exec)=0` and stays non-vacuous on `mixed`. The weak clean-C vs clean-R AUC is the structural reason: no point-level (transcript) defense can reliably separate the joint-gap-vulnerable points from the robust ones, because the distinction lives in the region B_{1,ε}, not the observed point, and the C nominal is safe there. A certificate that reasons over the region is required; a deployed pre-exec/auto-mode classifier is not a substitute.
