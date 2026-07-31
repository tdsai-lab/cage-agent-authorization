# RUNBOOK closure — engine-verified C-witness inside a REAL purpose-built AML engine (Marble)

Engine: **Marble (checkmarble/marble) v1.4.0** — a purpose-built AML/fraud engine, run via its own **decision API (POST /v1/decisions), X-Api-Key** (rootless podman, host-net). Rule (authored, real IEEE-CIS constants): `safe = risk_score < theta(provenance); theta_strict=0.488808, theta_loose=0.568808`, encoded as a Marble score classifier (score classifier: rule fires (score) iff risk>=theta(prov); score>=review_threshold => REVIEW(unsafe)). `s` = **provenance_upstream (screening-tool / list-source class; pipeline-set)**. 800 REAL IEEE-CIS transactions × 4 decisions = 3200 engine decisions, eps=0.1. Every label is Marble's own decision output.

- engine category distribution: U=160 A=160 B=160 **C=160 (20.0%)** R=160
- Marble-engine vs analytic taxonomy agreement: **1.0** (C-set Jaccard 1.0)

## Engine-verified C-witness traces (each label is Marble's decision outcome)

| provenance | swap | risk_score | clean | swap-only | +ε-only | **swap+ε (joint)** |
|---|---|---:|:--:|:--:|:--:|:--:|
| loose | →strict | 0.4664 | safe | safe | safe | **UNSAFE** |
| loose | →strict | 0.4466 | safe | safe | safe | **UNSAFE** |
| loose | →strict | 0.454 | safe | safe | safe | **UNSAFE** |
| loose | →strict | 0.3905 | safe | safe | safe | **UNSAFE** |
| loose | →strict | 0.4647 | safe | safe | safe | **UNSAFE** |

**Reads.** A **purpose-built AML/fraud engine** (Marble) — one rung above the general engines OPA (#9b) and GoRules ZEN (B2) on domain authenticity — labels real transactions as Category-C joint-gap witnesses through its own decision API, and reproduces the analytic taxonomy. `s` is a **provenance / list-source class** (genuinely upstream-set), so the swap is exactly the #16 `wrong_provenance_binding` fault an agent's pipeline can realize. Epistemic rank: real AML engine, AUTHORED rule, real data — NOT a claim the idiom was mined from confidential deployed AML rules (that gap is the regulatory documentary anchor).
