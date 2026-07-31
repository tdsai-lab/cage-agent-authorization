# EXP-POLICY-THIRD-PARTY — third-party Rego/Gatekeeper grounding

Frozen detector `4620bb6be4d8911b` (idiom predicate unchanged). ε=0.1, cap=300 files/corpus, seed=0.

**The distinction (do not conflate):** a *third-party policy* gives a **prevalence / grounding** signal (does the conditioned-threshold idiom occur in code we did NOT author?); an *authored Rego* gives a **controlled mechanism** signal (where the idiom IS present, does the C joint-gap witness arise under a real engine?). This experiment reports both, kept separate by `source`.

## Part A — 5-level taxonomy (frozen-detector-derived)

| corpus | source | language | scanned | discrete_only | fixed_θ | **conditioned_θ** | affine/mv | unknown |
|---|---|---|---:|---:|---:|---:|---:|---:|
| gatekeeper_library | third_party | rego | 10 | 0 | 0 | **0** | 0 | 10 |
| kyverno_policies | third_party | kyverno | 300* | 295 | 5 | **0** | 0 | 0 |
| cloud_custodian | third_party | cloud_custodian | 226 | 216 | 2 | **0** | 0 | 8 |
| authored__ieee_fraud | authored_control | rego | 1 | 0 | 0 | **1** | 0 | 0 |
| authored__constant_control | authored_control | rego | 1 | 1 | 0 | **0** | 0 | 0 |

`*` = file cap hit (count is the scanned cap, not the full corpus). Levels: discrete_only (no numeric comparison) · fixed_numeric_threshold (numeric vs a CONSTANT) · conditioned_numeric_threshold (= the frozen idiom θ=θ(s)) · affine_or_multivariate_numeric (conditioned + ≥2 numeric fields) · unknown_or_unsupported (parse error / unsupported).

### Third-party totals (prevalence denominator)

- policies scanned (third_party): **536** (parse_success=520, unknown=18)
- conditioned_numeric_threshold (the idiom): **0** ; affine/multivariate: **0**
- ⇒ third-party idiom-eligible policies: **0** of 536

## Part B — executable OPA categorize (unmodified Gatekeeper set)

Real `opa eval` over B_{1,ε} on n=300 sampled k8s manifests (clean / d=1 discrete neighbor / continuous worst-case / joint), labeled by the UNMODIFIED Gatekeeper policy SET (Safe ⇔ zero violations).

| category | count |
|---|---:|
| R | 0 |
| A | 131 |
| B | 0 |
| C | 0 |
| U | 169 |

**C-witnesses under third-party Gatekeeper: 0** (C_rate=0.0).

## Part C — C-witness search (where idiom > 0)

- **Third-party C-witnesses: 0** across 0 policies (C_rate over third-party policies = 0.0).
- Authored mechanism control (`ieee_fraud.rego`, θ(provenance)): **C_count=31** of 400 probes (C_rate=0.0775) — engine-labeled by real OPA. This is NOT prevalence; it confirms that WHERE the conditioned-threshold idiom is present, the joint-gap witness arises under a real policy engine.

## Interpretation

**Result: informative NULL, localized at the corpus stage.** The conditioned-threshold idiom `op(f_num, θ(s))` is essentially absent from the third-party executable policy corpora scanned (Gatekeeper / kyverno / cloud-custodian): their numeric rules use FIXED thresholds (containerlimits, resource caps) and their categorical rules are discrete-only allow-lists (allowedrepos, requiredlabels) — neither produces a provenance-conditioned numeric boundary, so no Category-C joint-gap witness is possible. The executable OPA categorize over the unmodified Gatekeeper set confirms this directly (C=0). **We do NOT claim all industrial policies have C-witnesses.** The null localizes at *idiom prevalence in this habitat* (k8s/cloud guardrails), not at the certificate. The authored-Rego mechanism control shows the complementary fact: where the idiom IS authored (θ(provenance)), the engine produces C-witnesses — so the third-party signal is *prevalence/grounding* and the authored signal is *controlled mechanism*.

## Limitations

- The detector is CONSERVATIVE (frozen): alternative threshold encodings can be missed, so the idiom rate is a LOWER bound (under-counts, never inflates).
- File caps (`*` in Part A) bound runtime; per-corpus counts above the cap are not exhaustive.
- Executable OPA categorize is only available for the in-tree Gatekeeper corpus (kyverno/cloud-custodian are taxonomy-only here: different admission engines).
- kyverno/cloud-custodian are scanned via structured-YAML detectors (confidence < the Rego AST path); a YAML parse failure lands in `unknown_or_unsupported`, not in a false idiom.
- The authored row is a MECHANISM control, never mixed into the third-party prevalence denominator (`source=authored_control`).
