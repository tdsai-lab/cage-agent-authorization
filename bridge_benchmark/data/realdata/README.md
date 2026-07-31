# IEEE-CIS real-data-grounded experiment

A **grounding** supplement — not the main proof experiment. The synthetic experiments remain the main
proof experiments (exact oracle control, exact C-witnesses, controlled Δ/ε geometry). This experiment
tests whether the typed gate and hybrid certificate remain non-vacuous on **real transaction feature
marginals** after constructing a provenance-dependent authorization policy with analytic joint-gap
witnesses.

> Public transaction datasets provide real feature marginals and outcome labels, but they do not
> provide post-tool-return authorization labels or joint discrete–continuous witnesses. This
> experiment therefore uses IEEE-CIS transaction features to ground the continuous channel and
> constructs a typed provenance-dependent authorization policy with analytic witnesses.

The correct claim is **real transaction marginals + constructed typed authorization policy** — *not*
real-world certified fraud detection, *not* a real production authorization policy, *not* an
end-to-end robust LLM agent.

## What is real / constructed / certified / not certified

| layer | status |
| --- | --- |
| transaction feature marginals (amount, dist1/2, C1–C14, D1–D15, V1–V20 aggregates) | **real** |
| `isFraud` label | **real**, used ONLY to train the risk score + as an external diagnostic |
| `risk_score` (continuous channel) | held-out logistic risk model over real features (or `fixture_deterministic`) |
| provenance tools, thresholds θ_t(x1), `Safe(z, approve_transaction)` | **constructed** |
| continuous perturbation policy `B_{1,ε}` (risk_score only) | **constructed** |
| **certified object** | the post-tool-return typed authorization gate |
| **NOT certified** | real fraud detection, production compliance, end-to-end agent behavior |

## The constructed policy

`Safe(z, approve_transaction) = 1  ⟺  risk_score ≤ θ_t(x1)`, with provenance regimes
`θ_strict(x1)=θ(x1)` and `θ_loose(x1)=θ(x1)+δ` (loose tools trust the surfaced state more).
`θ(x1)` is the `--theta-quantile` quantile of the gate-pool risk scores. Discrete budget `d=1` is a
single related-pair provenance swap (`payment_gateway_loose ↔ identity_risk_strict`,
`manual_screen_loose ↔ device_risk_strict`); only `risk_score` moves continuously (`‖·‖₂ ≤ ε`).

This is the scalar-threshold geometry of the synthetic oracle, so the analytic Category-C interval for
a loose-tool record is `r ∈ (θ−ε, θ] ∩ (−∞, θ+δ−ε]`, of length `min(δ, ε)`. A brute-force enumeration
(discrete swaps × risk endpoints `{r, r±ε}`) cross-checks every analytic label, and both agree with
the shared `oracle.py` over the generated rule_table (asserted in tests).

## Data layout (no internet)

```
bridge_benchmark/data/raw/ieee_cis/train_transaction.csv  # real (you provide; not downloaded)
bridge_benchmark/data/raw/ieee_cis/train_identity.csv  # optional
bridge_benchmark/data/fixtures/ieee_cis_tiny/train_*.csv  # tiny synthetic fixture (for tests)
```

If the real CSVs are absent the generator prints the expected path and stops. It also runs without
`train_identity.csv`.

## How to run

```bash
# generate (real data)
python -m bridge_benchmark.experiments.realdata_ieee_cis \
  --input-dir bridge_benchmark/data/raw/ieee_cis \
  --out bridge_benchmark/data/realdata/ieee_cis_records.jsonl \
  --sampling boundary_balanced --n-records 10000 \
  --theta-quantile 0.70 --delta 0.08 --epsilon 0.10 --seed 0

# certify
python -m bridge_benchmark.experiments.run_realdata_ieee_cis_cert \
  --records bridge_benchmark/data/realdata/ieee_cis_records.jsonl \
  --epsilon 0.10 --d 1 --n-mc 2000 --seed 0 \
  --out bridge_benchmark/cert/out/realdata_ieee_cis_seed0

# fixture smoke test (no real dataset)
python -m bridge_benchmark.experiments.realdata_ieee_cis \
  --input-dir bridge_benchmark/data/fixtures/ieee_cis_tiny \
  --out bridge_benchmark/data/realdata/ieee_cis_fixture_records.jsonl \
  --sampling c_targeted --n-records 200 --seed 0

# small grid
INPUT_DIR=bridge_benchmark/data/raw/ieee_cis bash scripts/run_ieee_cis_realdata_grid.sh
```

## Sampling modes — natural vs C-targeted

- **`natural`** — gate-pool rows as-is. Real marginals rarely sit in the narrow C-interval, so this
  produces **few C points** — that is expected and is reported, not hidden.
- **`boundary_balanced`** — round-robin balance across the present categories (oversamples near θ).
- **`c_targeted`** — selects rows whose risk lies in the analytic C-interval and assigns them a loose
  provenance so the strict-swap joint witness exists; fills the remainder with a trainable mix. If
  fewer than `--min-c-records` C rows exist, it **warns** and saves the actual count.

Interpretation: `natural` answers "does C occur spontaneously under real marginals?" (rarely);
`c_targeted` answers "when C does occur, does the non-composition gap hold and does the hybrid
certificate stay sound + non-vacuous?" (yes).

## How to interpret the metrics

`cert_false_allow` must be **0** (soundness). `naive_C_falseallow` should be **high** on C records
(the discrete-only and continuous-only certificates each certify C safe, so their naive composition is
false), while the hybrid certificate keeps `C_allow` at/near 0 and stays non-vacuous on R (`R_allow>0`).
`fraud_rate_*` are **diagnostics only**: certified-allowed transactions should carry lower risk_score
(and typically lower fraud rate) than blocked/abstained ones — an external plausibility signal, never
a certified property.

Outputs: generation → `ieee_cis_records.jsonl`, `ieee_cis_generation_config.json`,
`ieee_cis_generation_report.md`; certification → `metrics.json`, `report.md`, `config.json`,
`records_with_predictions.jsonl`. Generated `*.jsonl` are git-ignored (regenerable); the fixture CSVs
are committed.
