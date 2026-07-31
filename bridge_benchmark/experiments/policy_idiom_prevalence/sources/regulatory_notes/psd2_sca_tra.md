# Source note: PSD2 SCA Transaction Risk Analysis (TRA) exemption thresholds

- **source_note_id:** `psd2_tra`
- **source_url:**
  - https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018R0389 (Commission Delegated
  Regulation (EU) 2018/389, Article 18 + Annex — official)
  - https://www.eba.europa.eu/single-rule-book-qa/qna/view/publicId/2018_4032 (EBA Single Rulebook
  Q&A 2018_4032, TRA fraud-rate methodology — regulator)
  - https://blog.mangopay.com/en<local-dir> (secondary)
- **source_type:** official (regulation) + regulator (EBA Q&A)
- **date_accessed:** 2026-06-10
- **thresholds_used (Exemption Threshold Value ↔ reference fraud rate, remote card payments):**
  - amount ≤ **€100**  allowed when PSP fraud rate ≤ **0.13%**
  - amount ≤ **€250**  allowed when PSP fraud rate ≤ **0.06%**
  - amount ≤ **€500**  allowed when PSP fraud rate ≤ **0.01%**
- **exact quoted phrase:** "up to €100 with a 0.13% fraud rate threshold, €100–€250 with a 0.06% fraud
  rate threshold, and €250–€500 with a 0.01% fraud rate threshold" — i.e. "100 euros for fraud rates
  below 0.13%, 250 euros for fraud rates below 0.06%, 500 euros for fraud rates below 0.01%."
- **manual_interpretation:** the categorical `fraud_rate_tier` (the PSP's achieved fraud band) SELECTS
  the Exemption Threshold Value on the continuous `amount_eur` (`θ_amount ∈ {€100, €250, €500}`), and
  the policy additionally requires the measured `fraud_rate` to stay below the tier's reference rate.
  This is a documented category-conditioned numeric threshold on a fully continuous amount channel
  (the cleanest continuous-C substrate of the corpus). Tier→amount mapping used:
  `tier_1` (fraud ≤ 0.01%) → €500, `tier_2` (≤ 0.06%) → €250, `tier_3` (≤ 0.13%) → €100.
