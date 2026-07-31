# PLAN_2 P1-B — re-scan the right habitat (idiom in compliance/legislative rule logic)

Frozen Phase-1 predicate `4620bb6be4d8911b` (unchanged; P1-B adds parsers only). Prereg `29497a63603701b8`. Funnel: Pr[C_security|corpus] = idiom_rate(structural) * Pr[provenance_upstream|idiom]

| corpus | habitat | commit | files | **structural idiom_rate** | provenance_upstream_rate |
|---|---|---|---:|---:|---:|
| openfisca_france | H2_legislation | `a9d8dcbe` | 132 | **0.06818** (9) | 0.0 (0) |
| jube_aml | H1_fraud_engine | `1b9777fa` | 62 | **0.0** (0) | 0.0 (0) |
| tazama_rule_executer | H1_fraud_engine | `2d979902` | 4 | **0.0** (0) | 0.0 (0) |
| dmn_tck | H3_decision_tables | `370ceb5e` | 162 | **0.04938** (8) | 0.0 (0) |
| kogito_examples | H3_decision_tables | `6fc9f665` | 52 | **0.11538** (6) | 0.0 (0) |
| H0_k8s_admission(scoping_control) | H0 | — | 1424 | 0.0 | 0.0 |

**Decision: STRUCTURAL_PRESENT_PROVENANCE_NULL.**

**Reads.** The structural idiom `op(f_num, θ(s))` IS present in third-party executable rule logic across TWO independent habitats — it is NOT confined to our testbed. (i) **Legislation-as-code** (OpenFisca, H2): numeric eligibility thresholds subscripted by an enum attribute. (ii) **Committed decision tables** (DMN, H3): a numeric input column whose ordered-comparison threshold takes ≥2 distinct values selected by a sibling categorical/bucket input column — including the **OMG DMN specification's own canonical chapter-11 lending example** (`CreditScore`/`ApplicationRiskScore` thresholds keyed by `ExistingCustomer`) and Kogito's shipped `LoanEligibility` (debt-ratio limit keyed by salary bracket). The idiom being the textbook decision-table is the strongest possible refutation of 'you invented the pattern'. But in BOTH habitats the discrete key `s` is a SUBJECT/status attribute (household type, housing zone, existing-customer, risk-category) -> `subject_self_reported`, not pipeline-set, so it is not security-relevant in the post-return agent threat model (provenance_upstream_rate = 0). The fraud/AML engines (the highest-`provenance_upstream` habitat) keep their rules at RUNTIME (DB/config), so committed code under-measures them — reported as a scoping limitation, not inferred absence. H0 (k8s admission) stays the negative control. Conclusion: the pattern is **present-but-domain-specific** (≈7% of OpenFisca model files; ≈5% of DMN-TCK and ≈12% of Kogito decision tables — concrete subject-keyed thresholds); the security-relevant (upstream-set) variant is concentrated where provenance is pipeline-set, i.e. the regulatory-authored executable track demonstrated by #9b (engine-labeled, agreement 1.0) and PSD2/FinCEN. Abundance dissolves 'you invented the pattern'; the threat-model argument carries the security relevance.

### Sample structural hits — openfisca_france (H2_legislation)

- `logement.py` f_num=(eligibility_input) s=region op=< → s_semantics=**subject_self_reported**
- `livret_epargne_populaire.py` f_num=(eligibility_input) s=residence op=< → s_semantics=**subject_self_reported**
- `aides_logement.py` f_num=(eligibility_input) s=zone_apl op=< → s_semantics=**subject_self_reported**
- `aides_logement.py` f_num=(eligibility_input) s=type_aide op=< → s_semantics=**subject_self_reported**
- `aides_logement.py` f_num=(eligibility_input) s=categorie op=< → s_semantics=**subject_self_reported**
- `aides_logement.py` f_num=(eligibility_input) s=statut_couple op=< → s_semantics=**subject_self_reported**

### Sample structural hits — dmn_tck (H3_decision_tables)

- `0108-first-hitpolicy.dmn` f_num=Age s=RiskCategory op=>= → s_semantics=**subject_self_reported**
- `0109-ruleOrder-hitpolicy.dmn` f_num=Age s=RiskCategory op=>= → s_semantics=**subject_self_reported**
- `0117-multi-any-hitpolicy.dmn` f_num=Age s=RiskCategory op=>= → s_semantics=**subject_self_reported**
- `0004-lending.dmn` f_num=ApplicationRiskScore s=ExistingCustomer op=< → s_semantics=**static_config**
- `0004-lending.dmn` f_num=ApplicationRiskScore s=ExistingCustomer op=< → s_semantics=**static_config**
- `0004-lending.dmn` f_num=CreditScore s=ExistingCustomer op=< → s_semantics=**static_config**

### Sample structural hits — kogito_examples (H3_decision_tables)

- `LoanEligibility.dmn` f_num=((Client.existing payments + Loan.installment) / Client.salary) * 100 s=Client.salary op=<= → s_semantics=**subject_self_reported**
- `LoanEligibility.dmn` f_num=((Client.existing payments + Loan.installment) / Client.salary) * 100 s=Client.salary op=<= → s_semantics=**subject_self_reported**
- `Prequalification.dmn` f_num=Credit Score s=LTV op=>= → s_semantics=**static_config**
- `Prequalification.dmn` f_num=LTV s=Credit Score op=<= → s_semantics=**static_config**
- `Prequalification.dmn` f_num=Credit Score s=LTV op=>= → s_semantics=**static_config**
- `LoanEligibility.dmn` f_num=((Client.existing payments + Loan.installment) / Client.salary) * 100 s=Client.salary op=<= → s_semantics=**subject_self_reported**
