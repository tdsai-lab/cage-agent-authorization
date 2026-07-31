# PLAN_2 P1 Task B — pre-registered third-party idiom scan

Pre-registration hash `9cf6325dadd5f5e0` · detector `4620bb6be4d8911b`. Funnel: Pr[C|corpus] = idiom_rate * Pr[C|idiom]; Pr[C|idiom]~1 for continuous theta

| corpus | lang | commit | files | numeric-θ | **keyed-θ (idiom)** | idiom_rate |
|---|---|---|---:|---:|---:|---:|
| gatekeeper_library_NULLCTRL | rego | `ebf08c47` | 10 | 0 | **0** | 0.0 |
| kyverno_policies | kyverno | `76be98a2` | 1188 | 37 | **0** | 0.0 |
| cloud_custodian | cloud_custodian | `726657d5` | 226 | 2 | **0** | 0.0 |

*numeric-θ* = files with any numeric threshold comparison; *keyed-θ* = of those, the threshold is selected by a discrete/provenance key (the idiom). A null with numeric-θ≫0 but keyed-θ=0 is credible: thresholds exist but are CONSTANT, not provenance-conditioned.

**Decision: NULL.** Null control (gatekeeper-library) reproduced: True (idiom_rate must be 0). idiom_rate≈0 for continuous theta(s) across third-party executable corpora → **informative null, localized at the corpus stage** (exactly as gatekeeper already shows). The regulatory-authored executable track (#9b + PSD2/FinCEN) is the documented one-rung-lower fallback; a textual-substrate scan backs the plausibility argument. Honest null, not papered over.
