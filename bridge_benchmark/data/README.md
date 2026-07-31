# `bridge_benchmark/data/` — datasets, fixtures, licensing

What is here, what is not, and how to obtain what is not.

| dataset | status in this artifact | licence / redistribution |
|---|---|---|
| Synthetic benchmark records (`*.jsonl` for finance / monitoring / ops) | **regenerated in seconds** — `python bridge_benchmark/generators/generate.py` | ours |
| `fixtures/ieee_cis_tiny/` | **included** | synthetic fixture we generated with the IEEE-CIS *column layout*; contains no competition data. Used by tests and by the no-dataset smoke path |
| `realdata/nab/` (Numenta Anomaly Benchmark CPU telemetry) | **vendored** (`data/`, `labels/`, `LICENSE.txt`) | MIT — redistribution permitted |
| IEEE-CIS Fraud Detection (`raw/ieee_cis/train_transaction.csv`, `train_identity.csv`) | **NOT included** | Kaggle competition data: redistribution is prohibited by the competition rules. Fetch it yourself (below) |
| Derived IEEE-CIS records (`realdata/ieee_cis_*.jsonl`) | **NOT included** (derived from the above) | regenerate deterministically after the download |
| Third-party policy corpora (`external/corpora/`) | **NOT included** | upstream repositories; each scan script prints its expected path and upstream URL |

## Getting IEEE-CIS

```bash
python scripts/download_ieee_cis.py --out bridge_benchmark/data/raw/ieee_cis
export IEEE_CIS_DIR=$PWD/bridge_benchmark/data/raw/ieee_cis
```

The script uses the Kaggle CLI (`pip install kaggle`, API token in `~/.kaggle/kaggle.json`) and the
competition `ieee-fraud-detection`; **you must accept the competition rules on the competition page
once** before the API will serve the files. It verifies what it downloaded against the SHA-256 and row
counts of the exact files used for the reported results:

| file | bytes | lines (incl. header) | SHA-256 |
|---|---|---|---|
| `train_transaction.csv` | 683,351,067 | 590,541 | `3a5c83ab6b3cc13dcabe5ffa9f522307fd5f7f7b6e6f6a60c32284ca6283d642` |
| `train_identity.csv` | 26,529,680 | 144,234 | `b63c725d8377be90a995268d97f347c17d456b95db45807adcf9f59cd603c37c` |

If the hashes match, everything downstream is deterministic.

## Reproducing our exact records from the raw download

The preprocessing (feature extraction, the held-out `risk_score` logistic model trained on the real
`isFraud` label, the constructed provenance-dependent authorization policy, and the sampling) is
seeded and deterministic:

```bash
# the canonical record set used by the real-data experiments (seed 0)
python -m bridge_benchmark.experiments.realdata_ieee_cis \
  --input-dir "$IEEE_CIS_DIR" \
  --out bridge_benchmark/data/realdata/ieee_cis_boundary_balanced_s0.jsonl \
  --sampling boundary_balanced --n-records 10000 \
  --theta-quantile 0.70 --delta 0.08 --epsilon 0.10 --seed 0

# certify them
python -m bridge_benchmark.experiments.run_realdata_ieee_cis_cert \
  --records bridge_benchmark/data/realdata/ieee_cis_boundary_balanced_s0.jsonl \
  --epsilon 0.10 --d 1 --n-mc 2000 --seed 0 \
  --out bridge_benchmark/cert/out/realdata_ieee_cis_seed0
```

Some experiments (the freshness-SLA and raw-unit-ε rows) additionally re-join the raw CSVs for the
real `TransactionDT` wall-clock column; they read `$IEEE_CIS_DIR` directly and say so when it is unset.

## Without the download

Everything except the rows tagged `ieee` in [`../../REPRODUCE.md`](../../REPRODUCE.md) runs without it,
including the entire analytic core, the certificate backends, the scaling/realism studies, the frozen
scans, the NAB real-data leg, and the aggregated post-processing rows (§9 of REPRODUCE.md) which read
the shipped `cert/out/` files. The IEEE-CIS experiments also have a fixture path
(`--input-dir bridge_benchmark/data/fixtures/ieee_cis_tiny`) that exercises the same code with no
licensed data — useful to check the pipeline runs, not to reproduce numbers.

## What the real data is and is not used for

Real IEEE-CIS transaction features ground the **continuous channel** (real marginals) and the real
`isFraud` label trains the held-out risk model and serves as an external diagnostic. The provenance
tools, the thresholds θ_t(x₁) and the safety predicate `Safe(z, approve_transaction)` are
**constructed** — the honest claim is *real transaction marginals + a constructed typed authorization
policy*, never real-world certified fraud detection. See `realdata/README.md` for the full
real/constructed/certified/not-certified breakdown.
