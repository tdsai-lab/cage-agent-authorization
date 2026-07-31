# PLAN_2_RESCAN_BIS Workstream C — documentary anchor for the provenance-keyed threshold variant

The security-relevant variant of the idiom `x ▷ θ(s)` (a numeric threshold whose value is selected by a
discrete **pipeline-/institution-set** category) is **not observable from public code corpora** —
institution-specific AML/fraud thresholds are confidential and loaded at deployment. This is a property
of the domain, not a gap in our scan. The best available third-party evidence that **deployed**
thresholds are category-conditioned is **regulatory and supervisory documentation**. This table
consolidates it (it sits one rung above "the engine permits it" and supports the security-relevant
prevalence that corpora cannot estimate).

| source | the discrete key `s` | category-conditioned threshold `θ(s)` documented | note file |
|---|---|---|---|
| **PSD2 RTS (EU) 2018/389, Art. 16** | payment context (remote vs contactless; cumulative count) | SCA exemption thresholds: remote low-value **€30** (cumulative €100 / 5 txns); contactless **€50** (cumulative €150 / 5 txns) — the exemption *threshold* is selected by the payment-context category | `psd2_sca_low_value.md` |
| **PSD2 RTS Art. 18 (TRA)** | the PSP's **reference fraud-rate band** (a tiered class) | the transaction-value exemption ceiling is **€100 / €250 / €500**, selected by which fraud-rate tier the PSP currently sits in — a numeric threshold keyed on a discrete (and pipeline-computed) class | `psd2_sca_tra.md` |
| **FinCEN CTR (31 CFR 1010.311)** | report type / instrument category | currency-transaction reporting threshold **$10,000** (and the **$3,000** recordkeeping rule for certain instruments) — the threshold is selected by the transaction/instrument category | `aml_ctr_us.md` |
| **Jurisdictional AML thresholds** | **jurisdiction / counterparty geography** (an upstream-resolved provenance class) | cash/transaction reporting thresholds vary by country (e.g. EUR 10,000 EU cash limit vs national variants) — the threshold is selected by the geography category | `aml_jurisdictional_thresholds.md` |
| **Supervisory / vendor guidance** (HKMA AML/CFT transaction-monitoring guidance; commercial rule vendors) | geography, product, customer segment, risk appetite | guidance explicitly directs institutions to **calibrate monitoring thresholds by customer base, product, and geography** — i.e. the deployed threshold *is* `θ(s)` with `s` an institution-/pipeline-set category | (cite) |

## How this fits the evidence hierarchy (v2)

- **Existence / mechanism:** Theorem 1 (the joint-gap C-window has length `min(Δ,ε)>0` whenever `θ`
  differs across a discrete swap) + engine-verified C-witnesses on real engines (**#9b** OPA, **B2**
  GoRules ZEN) + real-data return-dependence without an authored predicate (**#32**).
- **Structural prevalence (written in code):** present in third-party executable legislation-as-code
  (P1-B, OpenFisca ≈6.8%), but subject-keyed there.
- **Security-relevant deployed prevalence (this table):** not estimable from public artifacts; the
  documentary record shows deployed thresholds **are** category-conditioned, and supervisory guidance
  tells institutions to key them on upstream-resolved categories (geography, product, customer, fraud
  tier). The provenance-keyed variant is therefore real in deployment, even though confidential.

**Claim discipline.** This is documentary support that the *deployed* threshold is category-conditioned;
it is not a measured prevalence rate and is never presented as one. Combined with the engine-verified
witnesses, it answers "does the security-relevant variant exist in the wild?" with the strongest
evidence the domain permits.
