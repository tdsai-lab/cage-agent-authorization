# PLAN_2_RESCAN_BIS B2 — engine-verified C-witness on a REAL production rule engine (GoRules ZEN)

Engine: **GoRules ZEN / JDM** (`zen-engine`), a real production decision engine. Rule (authored, real constants): `safe = risk_score < theta(provenance); theta_strict=0.488808, theta_loose=0.568808`. `s` = **provenance_upstream (screening-tool / list-source class; pipeline-set)**. 4000 REAL IEEE-CIS transactions, eps=0.1. Every label is the ZEN engine's.

- engine category distribution: U=800 A=800 B=800 **C=800 (20.0%)** R=800
- ZEN-engine vs analytic taxonomy agreement: **1.0** (C-set Jaccard 1.0)

## Engine-verified C-witness traces (each label is ZEN's)

| provenance | swap | risk_score | clean | swap-only | +ε-only | **swap+ε** |
|---|---|---:|:--:|:--:|:--:|:--:|
| loose | →strict | 0.4466 | safe | safe | safe | **UNSAFE** |
| loose | →strict | 0.4671 | safe | safe | safe | **UNSAFE** |
| loose | →strict | 0.3905 | safe | safe | safe | **UNSAFE** |
| loose | →strict | 0.4565 | safe | safe | safe | **UNSAFE** |
| loose | →strict | 0.4092 | safe | safe | safe | **UNSAFE** |

**Reads.** A SECOND independent production engine (GoRules ZEN, after OPA in #9b) labels real transactions as Category-C joint-gap witnesses, and reproduces the analytic taxonomy. Here `s` is a **provenance / list-source class** — genuinely upstream-set, so the swap is exactly the #16 `wrong_provenance_binding` fault that an agent's upstream pipeline can realize, making this MORE threat-model-relevant than a subject-keyed threshold. Epistemic rank = #9b (real engine, authored rule, real data); NOT a claim the idiom was found in deployed AML rules (those thresholds are confidential — see the Workstream-C regulatory anchor).
