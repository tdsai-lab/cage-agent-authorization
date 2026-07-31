# CX6 — real adapter-stack budget calibration through the Marble AML engine

Engine **Marble v1.4.0 decision API**. #16 fault mechanisms run through a real adapter → the real Marble decision API; Marble-relevant drift `d`=provenance swap, `ε`=|Δrisk|. **ε_cal (p95, integrity+freshness, calibrate half n=400) = 0.0524**; evaluated on a disjoint holdout (n=400, 1658 unique real decisions).

| mechanism | d̄ | ε_p95 | frac in-budget | engine decision-flip | **budget-escape** |
|---|---:|---:|---:|---:|---:|
| wrong_provenance_binding | 1.0 | 0.0 | 1.0 | 0.235 | **0.0** |
| stale_cache | 0.0 | 0.105 | 0.855 | 0.0251 | **0.0196** |
| numeric_jitter | 0.0 | 0.0297 | 1.0 | 0.025 | **0.0** |
| normalization_skew | 0.0 | 0.0502 | 0.96 | 0.03 | **0.005** |
| schema_skew | 0.0 | 0.5304 | 0.695 | 0.1088 | **0.1034** |
| cache_key_collision | 0.0 | 0.417 | 0.292 | 0.3175 | **0.31** |

**Holdout budget-escape:** integrity+freshness **0.0062** vs out-of-budget tail **0.2067**.

**Reads.** Calibrating ε on one half and evaluating on a disjoint holdout — with the REAL Marble engine deciding — the certified budget `B_{1,ε_cal}` **covers the integrity + freshness faults** (near-zero escape: their real-engine decision flips fall inside the ball), while the **schema/identity tail** (`schema_skew`, `cache_key_collision`) escapes, reproducing #16's measured out-of-budget cliff on a real deployed engine. The certified gate is sound in-budget; CX6 shows a *calibrated* budget generalizes to held-out data and localizes exactly which real adapter faults a schema/identity validation layer must catch (the honest precondition, not a hidden assumption).
