# models/ — learned gate s_θ(z, a) and baselines (PLAN3 §§1–6)

The learned object is a small **tabular** binary gate `s_θ(z, a) ∈ {safe, unsafe}` approximating the
analytic oracle `Safe(z, a)`. Not an LLM. Feature map: `[onehot(domain), onehot(tool),
onehot(action), onehot(x1 categoricals), x2 standardized]` (~15–30 dims).

## Files
- **`dataset.py`** — `build_records` densely sweeps each `(domain, tool, action, categorical_context)`
  over a numeric grid and labels with the oracle (pointwise `Safe`); `FeatureEncoder` with maskable
  feature groups and a `numeric_block` helper for vectorized smoothing.
- **`split.py`** — deterministic stratified split by `(domain, candidate_action, category, safety_label)`.
  Category is an **evaluation stratum**, never the training target.
- **`baselines.py`** — `train_all` fits the 8 baselines with asymmetric class weights
  (`λ_unsafe=2 > λ_safe=1`, false-allow penalized); `evaluate` reports clean acc, safe/unsafe recall,
  false-allow/false-block, accuracy by A/B/C/R/U. `train_certified_gate` is the **pointwise**
  certified base gate trained with **oracle-relabelled** Gaussian augmentation (PLAN3 §2: each noisy
  sample `z̃` gets label `Safe(z̃,a)`, NEVER the clean label — the benchmark is not label-preserving).

## Run
```bash
python baselines.py  # Table 2: clean classifier performance by category
python dataset.py / split.py  # dataset + split sanity
```

## Result (Table 2)
Joint models (`joint_mlp`, `certified_mlp`) reach ~0.99 clean accuracy near the oracle ceiling;
marginal views fail as expected (`categorical_only` false-allow 1.0, fails U; `numeric_only` weak on
A — can't separate tools). This is the expressivity half of the story; the certificate half is in
`../cert/`.
