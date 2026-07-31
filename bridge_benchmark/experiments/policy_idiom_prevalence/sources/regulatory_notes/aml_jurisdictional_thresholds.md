# Source note: AML jurisdictional thresholds (scope limit)

- **source_note_id:** `aml_jurisdictional`
- **source_type:** scope-limiting note (no new thresholds invented)
- **date_accessed:** 2026-06-10
- **thresholds_used:** none beyond `aml_ctr_us`.
- **manual_interpretation:** Only the **US** CTR threshold ($10,000, `aml_ctr_us`) is source-locked in
  this build. EU / JP / "other" cash-reporting thresholds are **NOT reliably sourced here** and are
  therefore **excluded** from the AML policy's categorical domain: the `aml_ctr` family fixes
  `jurisdiction = US` and varies only the source-locked / authored axes (`source_type`,
  `customer_risk_tier`). Per the spec's rule "if jurisdiction-specific thresholds cannot be sourced
  reliably, only use the sourced jurisdictions and mark the others as excluded," non-US jurisdictions
  are listed as excluded rather than assigned invented numbers.
- **excluded:** `jurisdiction ∈ {EU, JP, other}` (no source-locked threshold in this build).
