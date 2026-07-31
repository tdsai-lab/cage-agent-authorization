# Experiments summary — scaling & realism

Three claims for the experimental section:

1. **C exists systematically** (not a hand-crafted artifact).
2. **R_allow remains non-vacuous at scale.**
3. **Marginal / naive certificates fail reproducibly**, while the hybrid enumerate-discrete + Gaussian-RS certificate stays sound (C_allow = cert_false_allow = 0).

### Scaling study (synthetic typed tools) (10 settings)
- Category C present everywhere: min C% = 7.8  (YES)
- C_allow (hybrid cert): max = 0.000  (SOUND (0))
- certified false allow: max = 0.000  (SOUND (0))
- R_allow (non-vacuity): min = 0.350, max = 0.625  (NON-VACUOUS everywhere)
- naive-composition falsely certifies C: min = 1.00  (marginal cert fails)
- uncertified gate robust false-allow: min = 0.90  (attack succeeds w/o cert)

### Realistic schemas (finance / monitoring / ops-security) (3 settings)
- Category C present everywhere: min C% = 8.0  (YES)
- C_allow (hybrid cert): max = 0.000  (SOUND (0))
- certified false allow: max = 0.000  (SOUND (0))
- R_allow (non-vacuity): min = 0.240, max = 0.380  (NON-VACUOUS everywhere)
- naive-composition falsely certifies C: min = 1.00  (marginal cert fails)
- uncertified gate robust false-allow: min = 0.96  (attack succeeds w/o cert)

## Overall: ALL THREE CLAIMS HOLD across every setting.
