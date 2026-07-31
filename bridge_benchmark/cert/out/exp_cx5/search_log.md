# CX5 search log (frozen eligibility + why BRS qualifies)

**Eligibility criterion (PLAN_CX5, frozen verbatim):** (i) compares ≥1 numeric field to a threshold; (ii) the threshold varies with a categorical/provenance-like field (source/env/channel/tier/region/income-category/...); (iii) third-party authored, for operations, independently of our threat model; (iv) mechanically translatable into the verified affine fragment (Def 1) — here a scalar threshold, membership trivially in-fragment.

**Search list (PLAN_CX5 §2), family 2 (decision-table / legislation-as-code):** OpenFisca-France legislation-as-code (already cloned; P1-B identified subject-keyed numeric thresholds at 6.8% structural rate). Selected the **Bail Réel Solidaire `plafonds_par_zones`** parameter: income ceilings keyed by geographic zone.

**Why it qualifies:** (i) resources vs ceiling ✓; (ii) ceiling varies with **zone** (region-like categorical, explicitly admitted by (ii)) ✓; (iii) authored by OpenFisca transcribing Arrêté du 11/12/2023 / Art. R255-1 CCH, for real housing-eligibility operations, before/independently of this work ✓; (iv) scalar threshold, in-fragment ✓.

**Honest scope (claim ladder):** zone is a SUBJECT/REGION attribute, not a pipeline-provenance key — so this is a deployed-threshold EXISTENCE anchor (the `x▷θ(s)` idiom occurs in a real third-party rule), complementary to the pipeline-provenance null (P1/registry), NOT a claim that deployed pipelines spontaneously carry the provenance-set substrate.
