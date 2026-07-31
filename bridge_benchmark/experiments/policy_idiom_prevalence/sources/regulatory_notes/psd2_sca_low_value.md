# Source note: PSD2 SCA low-value / contactless exemption thresholds

- **source_note_id:** `psd2_low_value`
- **source_url:**
  - https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018R0389 (Commission Delegated Regulation (EU) 2018/389, SCA-RTS — official)
  - https://www.sidley.com/en/insights/newsupdates/2019/09/payment-services-directive-eu-strong-customer-authentication (secondary, legal analysis)
- **source_type:** official (regulation) + secondary (legal summary for the plain-language phrasing)
- **date_accessed:** 2026-06-10
- **thresholds_used:**
  - Article 16 (remote low-value, card-not-present): per-transaction **€30**; cumulative since last
  SCA **€100**; OR **≤ 5** consecutive remote transactions without SCA.
  - Article 11 (contactless at point of sale): per-transaction **€50**; cumulative **€150**; OR
  **≤ 5** consecutive contactless without SCA.
- **exact quoted phrase:**
  - (Art. 16) "Low-value remote transactions … are exempt from SCA when the transaction value doesn't
  exceed €30 and the total amount of previous remote transactions without SCA doesn't exceed €100 or
  there are no more than five consecutive remote transactions executed without SCA."
  - (Art. 11) "Contactless payments at point of sale of €50 or less are exempt from SCA, provided that
  they do not exceed a cumulative value of €150, or the number of previous contactless payments is
  less than five."
- **manual_interpretation:** the categorical `payment_channel ∈ {remote, contactless}` SELECTS the
  applicable per-transaction amount threshold (`θ_amount = €30` vs `€50`) and the cumulative threshold
  (`€100` vs `€150`). This is a documented category-conditioned numeric threshold with a genuinely
  continuous amount channel, plus discrete velocity counters (cumulative amount, consecutive count) —
  the documented hybrid discrete–continuous structure. `customer_risk_tier` adjustments below the
  regulatory ceiling are AUTHORED operational policy (not regulatory) and labelled as such in the
  oracle.
