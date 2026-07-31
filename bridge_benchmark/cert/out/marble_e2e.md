# B2-Marble e2e — certified gate + real committed side effect on Marble's decision API

Engine **Marble v1.4.0 (purpose-built AML engine)**; the side effect is a **persisted decision record** (POST /v1/decisions persists it, GET /v1/decisions reads it back). ε=0.1. `wrong_provenance_binding` serves nominal `loose`; the adversary realizes the worst case `(strict, risk+ε)` in the ball. Category-C witnesses: nominal approved, worst case unsafe.

| arm | committed unsafe approvals | note |
|---|---:|---|
| engine_only | **100/100** (P=1.0) | Marble persists the decision records (GET /v1/decisions: page=25, has_more=True) |
| certified_gate | **0/100** (P=0.0) | gate blocked the ball; only 0 submitted |
| oracle (strict,risk+ε) | — | engine REVIEWS 40/40 (rate 1.0) = ground truth unsafe |
| non-vacuity (R) | — | gate allowed 100/100 (rate 1.0) → engine approved 100 (safe side effects) |

**Reads.** On a REAL purpose-built AML engine, the deployed decision path trusts the served provenance and **commits real approve decision records** on Category-C witnesses whose realized worst case Marble itself would REVIEW (the oracle row). The certified joint gate — enumerating the provenance neighbourhood and testing the ε-shifted threshold — drives committed unsafe approvals to **0** while still letting genuinely-safe (R) transactions through to Marble (non-vacuous). This lifts B2 (engine-labelled C-witness) and #29 (in-process side effect) to a **real AML engine committing a real side effect**, gated soundly.
