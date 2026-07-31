# EXP-CX5 — independent-policy case study (OpenFisca BRS zone ceilings)

Source: OpenFisca-France Bail Réel Solidaire plafonds_par_zones — commit `a9d8dcbe900e`, 2025-01-01. s = zone (region categorical), θ(zone,size) real income ceiling; cap €120598. n=20000, seed=0.

**Freeze-first:** `policy_bundle/PROVENANCE.md`, `search_log.md`.

### Real θ(zone) income ceilings (€, 2025) — a provenance-conditioned boundary

| household size | A | Abis | B1 | B2 | C | raw gap € | norm δ |
|--:|--:|--:|--:|--:|--:|--:|--:|
| 1 | 38508 | 38508 | 38508 | 33479 | 33479 | 5029 | 0.0417 |
| 2 | 57555 | 57555 | 57555 | 44710 | 44710 | 12845 | 0.10651 |
| 3 | 75447 | 75447 | 69183 | 53766 | 53766 | 21681 | 0.17978 |
| 4 | 90078 | 90078 | 82871 | 64910 | 64910 | 25168 | 0.20869 |
| 5 | 107173 | 107173 | 98101 | 76357 | 76357 | 30816 | 0.25553 |
| 6 | 120598 | 120598 | 110396 | 86055 | 86055 | 34543 | 0.28643 |

### Battery (analytic taxonomy; exact certificate = category R)

| ε | Pr(A) | Pr(B) | **Pr(C)** | Pr(R) | Pr(U) | R_allow | C-witnesses | point grants | neighborhood grants | point-unsafe-under-swap |
|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| 0.03 | 0.14955 | 0.0237 | **0.035** | 0.34175 | 0.45 | 0.34175 | 700 | 700 | 0 | 700 |
| 0.1 | 0.14955 | 0.09355 | **0.08865** | 0.21825 | 0.45 | 0.21825 | 1773 | 1773 | 0 | 1773 |

**Verdict.** POSITIVE CASE STUDY: a real, deployed, THIRD-PARTY-authored provenance-conditioned numeric threshold (OpenFisca-France BRS income ceilings by zone, commit a9d8dcbe900e) exhibits the joint-gap substrate. A provenance-conditioned boundary EXISTS (zone-varying ceiling, real gap up to €34543); Category-C witnesses arise naturally (Pr(C)=0.035 at ε=0.03); the exact neighborhood certificate blocks them (point gate grants the zone-swap exploit, neighborhood cert refuses) — the substrate is NOT authored by us. Framing: zone is a subject/region categorical (criterion (ii)), not a pipeline-provenance key — a deployed-threshold existence anchor, complementary to the pipeline-provenance null.
