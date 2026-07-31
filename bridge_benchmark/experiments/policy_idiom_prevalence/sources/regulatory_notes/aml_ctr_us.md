# Source note: US AML Currency Transaction Report (CTR) threshold

- **source_note_id:** `aml_ctr_us`
- **source_url:**
  - https://www.fincen.gov/resources/frequently-asked-questions-regarding-fincen-currency-transaction-report-ctr
  (FinCEN — official)
  - https://www.ecfr.gov/current/title-31/subtitle-B/chapter-X/part-1010/subpart-C/section-1010.311
  (31 CFR 1010.311 — official, eCFR)
- **source_type:** official (regulator / federal regulation)
- **date_accessed:** 2026-06-10
- **thresholds_used:**
  - **CTR**: currency (cash) transactions **> $10,000** in a single business day (aggregated) must be
  reported (Bank Secrecy Act; 31 CFR 1010.311). Used as the source-locked hard reporting/escalation
  boundary on `amount` and `daily_aggregate_amount`.
  - **SAR**: $5,000 reference (31 CFR 1020.320) — recorded for context; not the binding amount
  threshold in this policy.
- **exact quoted phrase:** "domestic financial institutions must file a CTR on each … transaction in
  currency of more than $10,000"; "report any cash transactions exceeding $10,000 within a single
  business day."
- **manual_interpretation:** the **$10,000 CTR boundary is source-locked** and applies to currency
  (cash). The categorical `source_type ∈ {cash, wire, card, crypto}` selects WHETHER the cash CTR
  boundary binds, and `customer_risk_tier` selects an AUTHORED operational `auto_clear` ceiling on
  `amount` BELOW the regulatory limit (low=$9000, medium=$7000, high=$5000) — these per-tier ceilings
  are authored operational thresholds grounded in (and strictly below) the regulatory CTR limit, and
  are labelled authored, not regulatory. This gives a category-conditioned continuous amount threshold
  with the $10k regulatory hard limit as the U-region boundary.
