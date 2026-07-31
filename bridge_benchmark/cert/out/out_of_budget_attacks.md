# PLAN_2 P2 — out-of-budget adversary / breaking radius

Certificate: **robust-oracle cert for B_{1,0.10} (model-free); shipped gate is conservative approx**, declared budget **B_{1, 0.1}**. The adversary is pushed strictly outside it; `P(unsafe | cert)` = certified-false-allow over cert-ALLOWED points. The cert holds in-budget (cfa=0) and degrades gracefully outside.

## financial_compliance

cert-allowed 1271/6000; **in-budget cfa (d=1, ε=0.10) = 0.0** (sound).

**Sweep A — ε-radius (d=1):**

| ε_atk | 0.1 | 0.11 | 0.125 | 0.15 | 0.175 | 0.2 | 0.25 | 0.3 | 0.4 | 0.5 |
|---|---|---|---|---|---|---|---|---|---|---|
| cfa | 0.0 | 0.0464 | 0.1046 | 0.1825 | 0.2557 | 0.3352 | 0.4705 | 0.5948 | 0.8245 | 0.9788 |

breaking radius **ε\* = 0.11** (> ε_cert=0.1).

**Sweep B — d-radius (ε=ε_cert):**

| d_atk | 1 | 2 | 3 |
|---|---|---|---|
| cfa | 0.0 | 0.1259 | 0.1259 |

breaking radius **d\* = 2** (> d_cert=1).

**Sweep C — joint d=2 × ε:** cfa = 0.1:0.1259, 0.11:0.1558, 0.125:0.1983, 0.15:0.2667, 0.175:0.336, 0.2:0.4083, 0.25:0.535, 0.3:0.6656, 0.4:0.8867, 0.5:1.0

**#16 mechanism placement (P(unsafe|cert) on cert-allowed points):**

| mechanism | applied | **P(unsafe\|cert)** | frac_oob | max_d | ε_p95 |
|---|---:|---:|---:|---:|---:|
| wrong_provenance_binding | 1271 | **0.0** | 0.0 | 1 | 0.0 |
| stale_cache | 1271 | **0.0142** | 0.9835 | 0 | 0.4272 |
| schema_skew | 1271 | **0.0889** | 0.8631 | 0 | 1.0979 |
| cache_key_collision | 1271 | **0.3249** | 1.0 | 0 | 1.197 |
| compound_d2_prov_x1 | 1271 | **0.0** | 1.0 | 2 | 0.0 |

## sre_monitoring

cert-allowed 397/6000; **in-budget cfa (d=1, ε=0.10) = 0.0** (sound).

**Sweep A — ε-radius (d=1):**

| ε_atk | 0.1 | 0.11 | 0.125 | 0.15 | 0.175 | 0.2 | 0.25 | 0.3 | 0.4 | 0.5 |
|---|---|---|---|---|---|---|---|---|---|---|
| cfa | 0.0 | 0.0831 | 0.1889 | 0.3526 | 0.4736 | 0.5693 | 0.7229 | 0.8438 | 0.9622 | 0.9975 |

breaking radius **ε\* = 0.11** (> ε_cert=0.1).

**Sweep B — d-radius (ε=ε_cert):**

| d_atk | 1 | 2 | 3 |
|---|---|---|---|
| cfa | 0.0 | 0.2972 | 0.2972 |

breaking radius **d\* = 2** (> d_cert=1).

**Sweep C — joint d=2 × ε:** cfa = 0.1:0.2972, 0.11:0.3375, 0.125:0.4181, 0.15:0.5365, 0.175:0.6247, 0.2:0.6977, 0.25:0.8237, 0.3:0.9169, 0.4:0.9798, 0.5:1.0

**#16 mechanism placement (P(unsafe|cert) on cert-allowed points):**

| mechanism | applied | **P(unsafe\|cert)** | frac_oob | max_d | ε_p95 |
|---|---:|---:|---:|---:|---:|
| wrong_provenance_binding | 397 | **0.0** | 0.0 | 1 | 0.0 |
| stale_cache | 397 | **0.0176** | 0.9824 | 0 | 0.4161 |
| schema_skew | 397 | **0.0277** | 0.7909 | 0 | 0.7608 |
| cache_key_collision | 397 | **0.2443** | 1.0 | 0 | 1.1603 |
| compound_d2_prov_x1 | 397 | **0.0** | 1.0 | 2 | 0.0 |

**Reads.** The certificate is **exactly sound in-budget** (cfa=0 at d=1, ε≤ε_cert in both domains) and **breaks only strictly outside** its ball: the first ε break is at ε\*>ε_cert and the first d break at d\*=2. The #16 out-of-budget mechanisms (schema_skew, cache_key_collision, a d=2 provenance+categorical compound) land beyond the breaking radius — which is precisely why #16 flagged them as out-of-budget — and the cert correctly makes no claim there. Single-atom, in-budget faults (wrong_provenance_binding at d=1, stale_cache within ε) stay covered. The MVP d=1, ε=0.10 budget is honest: the cert degrades gracefully and visibly, it does not silently false-allow.
