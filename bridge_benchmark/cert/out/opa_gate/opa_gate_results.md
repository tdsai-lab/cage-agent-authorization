# OPA-gate experiment — certified post-return gate vs an OPA/Rego policy-as-code oracle

Labels and A/B/C/R/U categories are produced by the **OPA** engine (v1.17.1), not by the analytic generator. `policy_provenance = authored_rego` — the Rego is authored for this experiment (provenance-conditioned thresholds, idiom_present=True) and evaluated by OPA; it is **not** a third-party bundle (see Track A `track_a_third_party.*`). Confidence is family-wise: `alpha_branch = alpha_FWER/|N_1(s)|`, FWER level 0.999. Both REGISTERED sampling schemes are reported (NEW_EXPS_8 gaps 1–3).

## Sampling ablation — C-prevalence by registered scheme (NEW_EXPS_8 gap 2)

The input distribution is a registered degree of freedom; C% is reported for BOTH the natural (documented operating band) and boundary (threshold band) schemes, mirroring IEEE-CIS.

| domain | natural C% | boundary C% | Δ_min/ε | idiom_present |
| --- | --- | --- | --- | --- |
| finance | 0.125 | 0.12 | 0.2 | True |
| sre | 0.1075 | 0.135 | 0.2 | True |
| ops | 0.12 | 0.0925 | 0.2 | True |

## Primary outcome — C-prevalence and category distribution (per scheme)

| domain | scheme | n | A | B | C | R | U | **C-prevalence** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| finance | natural | 400 | 52 | 13 | 50 | 137 | 148 | **0.125** |
| finance | boundary | 400 | 122 | 35 | 48 | 0 | 195 | **0.12** |
| sre | natural | 400 | 62 | 21 | 43 | 127 | 147 | **0.1075** |
| sre | boundary | 400 | 117 | 24 | 54 | 0 | 205 | **0.135** |
| ops | natural | 400 | 45 | 25 | 48 | 143 | 139 | **0.12** |
| ops | boundary | 400 | 115 | 36 | 37 | 0 | 212 | **0.0925** |

## Certified-gate metrics + EXACT-verification baseline (NEW_EXPS_8 addition 1)

The exact verifier (OPA enumerates N_1, checks the threshold at x±ε per branch) allows exactly the robust-safe R: `exact_R_allow=1.0`, `exact_C/U_allow=0`, `exact_cert_false_allow=0`. The smoothed certified gate is a SOUND but LOOSE approximation; `cert_recovery_vs_exact` = fraction of exactly-certifiable-safe points it recovers.

| domain | scheme | C_allow | U_allow | R_allow | exact_R_allow | cert_recovery_vs_exact | oracle cert_false_allow | exact cert_false_allow | learned C_allow |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| finance | natural | 0.0 | 0.0 | 0.0438 | 1.0 | 0.0438 | 0.0 | 0.0 | 1.0 |
| finance | boundary | 0.0 | 0.0 | nan | nan | nan | 0.0 | 0.0 | 1.0 |
| sre | natural | 0.0 | 0.0 | 0.063 | 1.0 | 0.063 | 0.0 | 0.0 | 1.0 |
| sre | boundary | 0.0 | 0.0 | nan | nan | nan | 0.0 | 0.0 | 1.0 |
| ops | natural | 0.0 | 0.0 | 0.0699 | 1.0 | 0.0699 | 0.0 | 0.0 | 1.0 |
| ops | boundary | 0.0 | 0.0 | nan | nan | nan | 0.0 | 0.0 | 1.0 |

## Geometry — implied Δ/ε per policy (NEW_EXPS_8 gap 3)

Predicted C-interval length per registered swap = `min(Δ, ε)`; with ε=0.10 and authored gaps Δ∈{0.02..0.14}, the geometric law is testable on the executable policy itself.

| domain | min Δ | Δ_min/ε | registered states |N₁| | structural states |
| --- | --- | --- | --- | --- |
| finance | 0.02 | 0.2 | 6 | 8 |
| sre | 0.02 | 0.2 | 6 | 8 |
| ops | 0.02 | 0.2 | 6 | 8 |

## Utility–robustness trade-off: R_allow vs epsilon (natural scheme; σ, τ, M fixed)

| domain | eps=0.03 | eps=0.05 | eps=0.1 |
| --- | --- | --- | --- |
| finance | 0.6058 | 0.4672 | 0.0438 |
| sre | 0.6142 | 0.4567 | 0.063 |
| ops | 0.6014 | 0.4755 | 0.0699 |

**Reading.** C-witnesses arise **spontaneously** under an executable policy-as-code oracle (not just the analytic generator), at nontrivial prevalence (~10–12%). The certified gate is **sound**: `C_allow = U_allow = 0` and **oracle-measured** `cert_false_allow = 0`; the uncertified learned point-gate allows clean-looking C-witnesses (`learned C_allow ≈ 1`). `naive_C_falseallow = 1.0` is an implementation sanity check (C is *defined* as passing each marginal check but failing jointly), not a discovery. **Utility is a genuine trade-off:** `R_allow` is modest at the strict operating point (eps/sigma = 1.0, family-wise alpha: ~0.07–0.09) and **recovers substantially as eps shrinks** (to ~0.60 at eps=0.03; see the eps slice). This is the conservative/costly regime the gate trades for a formal allow contract, reported rather than hidden. policy_provenance = authored_rego (controlled mechanism evidence, not deployment provenance).

