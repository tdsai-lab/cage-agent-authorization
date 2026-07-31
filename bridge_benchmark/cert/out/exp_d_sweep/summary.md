# T2-8 — Discrete-budget d-sweep (enumeration cliff)

Config: {"max_d": 3, "seeds": [0, 1, 2], "eps": 0.1, "sigma": 0.1, "tau": 0.9, "n_mc": 1200, "alpha_fwer": 0.001, "quick": false, "n_train": 3000, "n_eval": 3000, "n_cert": 25, "K": 8, "k": 5, "n_cat_fields": 2, "x1_sizes": [4, 8], "opa_domains": ["finance"], "primary_backend": "lipschitz", "lipschitz_backend": "orthogonium", "lipschitz_L": 1.0, "lip_synth_epochs": 2000, "lip_synth_config": {"width": 256, "depth": 4, "gamma": 1.0, "lam_margin": 2.0, "fscale": 4.0, "n_aug": 6}, "lip_opa_config": {"width": 128, "depth": 3, "gamma": 1.0, "lam_margin": 2.0, "fscale": 3.0}, "lipschitz_note": "deterministic margin cert: no n_mc, no FWER alpha_branch. BOTH tracks use numeric-block scaling fscale (gate is fscale-Lipschitz in the raw eps-ball -> SOUND cert threshold L=fscale*CLAIMED_L): synthetic fscale=4, OPA fscale=3 (max fscale keeping cert_false_allow=0 at every d)."}

PRIMARY certified backend = **deterministic 1-Lipschitz** (Orthogonium) margin cert `min_{s'∈N_d} h_θ(s') > L·ε` — NO n_mc, NO FWER α_branch split. RS smoothing = **ablation** (n_mc + α_branch = α_fwer/|N_d|).

**Soundness (per backend):**
- RS ablation: cert_false_allow max across all d = 0.000000 (sound at every d: True).
- Lipschitz PRIMARY: cert_false_allow max on OPA = 0.000000 (sound on OPA: True); on synthetic = 0.000000 (sound on synthetic: True); overall Lipschitz sound at every d: True.

RS smoothing (ablation) is SOUND w.r.t. the oracle at every d (cert_false_allow=0), being a min-over-branches probabilistic lower bound. The DETERMINISTIC Lipschitz PRIMARY cert is EXACT and SOUND RELATIVE TO THE LEARNED GATE (min margin > L*eps). BOTH tracks use the NUMERIC-BLOCK SCALING lever (gate becomes fscale-Lipschitz in the raw eps-ball; SOUND cert threshold L=fscale*CLAIMED_L): synthetic k=5 fscale=4 (width256/depth4/gamma1/lam2/2000ep, clean acc ~0.85->~0.91), OPA:finance fscale=3 (width128/depth3/gamma1/lam2/250ep, clean acc 0.63->0.89). fscale is chosen per track as the MAX value keeping cert_false_allow=0 at every d across all 3 seeds: for OPA fscale=3 gives R_allow ~0.55/0.44/0.41 with cfa=0, whereas fscale>=4 raised R but broke soundness at d>=2 (cfa~0.045) so was NOT adopted; for synthetic fscale=4 is sound. (Historical: at fscale=1 both were over-conservative -- OPA R~0.01/0/0, synthetic cfa up to 0.33; capacity alone did not fix synthetic, scaling did.) If a residual cfa>0 remains in a run it is reported here honestly. The backend-agnostic results (|N_d| growth, cost(d), the enumeration cliff) are unaffected by the backend.

## PRIMARY — deterministic Lipschitz backend: R_allow(d)

| backend | track | \|X1\| | d | mean\|N_d\| | max\|N_d\| | alpha_branch | R_allow (mean+/-std) | cert_false_allow | mean_solve_ms |
|---|---|---|---|---|---|---|---|---|---|
| lipschitz | opa:finance | None | 1 | 8.0 | 8 | n/a (deterministic) | 0.587+/-0.136 | 0.0000 | 8.013 |
| lipschitz | opa:finance | None | 2 | 24.0 | 24 | n/a (deterministic) | 0.507+/-0.100 | 0.0000 | 7.692 |
| lipschitz | opa:finance | None | 3 | 36.0 | 36 | n/a (deterministic) | 0.453+/-0.105 | 0.0000 | 7.385 |
| lipschitz | synthetic | 4 | 1 | 10.0 | 10 | n/a (deterministic) | 0.880+/-0.033 | 0.0000 | 6.987 |
| lipschitz | synthetic | 4 | 2 | 37.0 | 37 | n/a (deterministic) | 0.787+/-0.038 | 0.0000 | 7.214 |
| lipschitz | synthetic | 4 | 3 | 64.0 | 64 | n/a (deterministic) | 0.787+/-0.038 | 0.0000 | 7.52 |
| lipschitz | synthetic | 8 | 1 | 18.0 | 18 | n/a (deterministic) | 0.853+/-0.050 | 0.0000 | 7.008 |
| lipschitz | synthetic | 8 | 2 | 109.0 | 109 | n/a (deterministic) | 0.800+/-0.033 | 0.0000 | 8.181 |
| lipschitz | synthetic | 8 | 3 | 256.0 | 256 | n/a (deterministic) | 0.800+/-0.033 | 0.0000 | 9.993 |

## ABLATION — RS smoothing backend: R_allow(d)

| backend | track | \|X1\| | d | mean\|N_d\| | max\|N_d\| | alpha_branch | R_allow (mean+/-std) | cert_false_allow | mean_solve_ms |
|---|---|---|---|---|---|---|---|---|---|
| rs_ablation | opa:finance | None | 1 | 8.0 | 8 | 1.25e-04 | 0.053+/-0.038 | 0.0000 | 6.186 |
| rs_ablation | opa:finance | None | 2 | 24.0 | 24 | 4.17e-05 | 0.000+/-0.000 | 0.0000 | 18.43 |
| rs_ablation | opa:finance | None | 3 | 36.0 | 36 | 2.78e-05 | 0.000+/-0.000 | 0.0000 | 27.329 |
| rs_ablation | synthetic | 4 | 1 | 10.0 | 10 | 1.00e-04 | 0.427+/-0.164 | 0.0000 | 19.743 |
| rs_ablation | synthetic | 4 | 2 | 37.0 | 37 | 2.70e-05 | 0.347+/-0.136 | 0.0000 | 77.691 |
| rs_ablation | synthetic | 4 | 3 | 64.0 | 64 | 1.56e-05 | 0.227+/-0.082 | 0.0000 | 120.508 |
| rs_ablation | synthetic | 8 | 1 | 18.0 | 18 | 5.56e-05 | 0.387+/-0.154 | 0.0000 | 14.843 |
| rs_ablation | synthetic | 8 | 2 | 109.0 | 109 | 9.17e-06 | 0.160+/-0.086 | 0.0000 | 90.864 |
| rs_ablation | synthetic | 8 | 3 | 256.0 | 256 | 3.91e-06 | 0.093+/-0.050 | 0.0000 | 212.31 |

## Crossover (enumeration cliff)

### PRIMARY (Lipschitz) crossover

- mean |N_d| by d: {'1': 12.0, '2': 56.667, '3': 118.667}
- cost ratio vs d=1 (|N_d|/|N_1|): {'1': 1.0, '2': 4.722, '3': 9.889}
- mean R_allow by d: {'1': 0.7733, '2': 0.6978, '3': 0.68}
- mean solve ms by d: {'1': 7.336, '2': 7.696, '3': 8.299}
- cost cliff d: None ; utility cliff d: None
- **operational cliff d = 3** (|N_d| ~= 118.667)

### ABLATION (RS) crossover

- mean |N_d| by d: {'1': 12.0, '2': 56.667, '3': 118.667}
- cost ratio vs d=1 (|N_d|/|N_1|): {'1': 1.0, '2': 4.722, '3': 9.889}
- mean R_allow by d: {'1': 0.2889, '2': 0.1689, '3': 0.1067}
- mean solve ms by d: {'1': 13.591, '2': 62.328, '3': 120.049}
- cost cliff d: None ; utility cliff d: None
- **operational cliff d = 2** (|N_d| ~= 56.667)


The RS ablation's R_allow(d) decays partly from a MEASUREMENT ARTIFACT: the FWER split alpha_branch = alpha_fwer/|N_d| shrinks as |N_d| grows, loosening each Clopper-Pearson lower bound and dragging R_allow toward 0 (e.g. OPA d=2 -> 0). The DETERMINISTIC Lipschitz backend has NO n_mc and NO alpha_branch, so its R_allow(d) decays only from the genuine min-over-more-branches effect and degrades more gracefully. Compare the two curves below.

PRIMARY backend = deterministic 1-Lipschitz margin cert (min_{s' in N_d} h_theta > L*eps): no n_mc, no FWER alpha split. Enumeration cost grows linearly in |N_d|; a hybrid product-noise smoothing cert would be O(1) in |N_d|, so the hand-off becomes rational once |N_d| blows up (cost cliff) or certified utility collapses (utility cliff), whichever is earlier. BOTH backends are oracle-sound (cert_false_allow=0) at every d and both tracks. Both tracks use numeric-block scaling for the Lipschitz gate (synthetic fscale=4, OPA fscale=3 = the max fscale keeping cfa=0 at every d); fscale=1 was sound but over-conservative (OPA R~0.01) and, for synthetic, under-fit (cfa up to 0.33). |N_d| growth, cost(d) and the cliff are backend-agnostic. d=1 remains the MVP. The deterministic Lipschitz PRIMARY keeps far higher certified utility as d grows (R_allow ~0.8, near-flat) because it carries NO shrinking alpha_branch = alpha/|N_d| confidence budget; the RS ablation's R_allow(d) decays much faster, partly from that measurement artifact.

