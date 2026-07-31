# OPA-gate experiment (NEW_EXP_OPA_GATE)

Re-runs the certified post-tool-return gate evaluation against an **OPA / Rego policy-as-code oracle**
instead of the inlined analytic `Safe(z,a)`. Labels and the A/B/C/R/U categories are produced by the
OPA engine; the gate/certificate machinery is reused unchanged.

## Files
- `policies/authored/{finance,sre,ops}.rego` — authored Rego (provenance-conditioned thresholds),
  `policy_provenance = authored_rego`. Evaluated by OPA; **not** a third-party bundle.
- `policies/third_party/` — drop a vendored third-party Rego/Gatekeeper bundle here (record source,
  license, commit/tag, hash) to upgrade to `policy_provenance = third_party_rego`. None vendored here.
- `opa_bridge.py` — batched `opa eval` wrapper (one subprocess per batch). Locates the binary at
  `bin/opa`, `$OPA_BIN`, or PATH.
- `schema.py` — typed schema + sampler, matched to the Rego (rt compatible with FeatureEncoder /
  oracle.discrete_swaps / cert.smoothed_gate.certify).
- `opa_oracle.py` — `safe` + A/B/C/R/U over `B_{1,eps}` via OPA (exact d=1 discrete enumeration +
  continuous worst-case probe).
- `run_opa_gate.py` — quick-mode runner → `cert/out/opa_gate/{opa_gate_results.csv,.md,provenance.json,
  opa_gate_snippet.tex}`. Family-wise Clopper–Pearson confidence (`alpha_branch = alpha_FWER/|N_1(s)|`).

## Setup (the OPA binary is gitignored — ~53 MB, downloadable)
```bash
cd bridge_benchmark/experiments/opa_gate
curl -L -o bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static && chmod +x bin/opa
```

## Run
```bash
python bridge_benchmark/experiments/opa_gate/run_opa_gate.py --domains finance,sre,ops \
  --n-train 1000 --n-eval 350 --n-mc 1500 --eps-grid 0.03,0.05,0.10
# quick smoke: add --quick
```

## Multi-seed headline (n_eval=400/domain × 5 seeds, sigma=0.10, tau=0.90, alpha_FWER=0.001, OPA 1.17.1)
Run: add `--seeds 0,1,2,3,4` → `opa_gate_multiseed.{csv,md}` (mean ± std).
- **C-witnesses arise spontaneously under OPA**: C-prevalence finance 0.112±0.007, sre 0.107±0.016,
  ops 0.122±0.011.
- Certified gate **sound with zero variance**: `C_allow = U_allow = oracle cert_false_allow = 0.000 ±
  0.000`.
- Uncertified learned point-gate allows clean-looking C-witnesses (`learned C_allow ≈ 1.0`).
- `naive_C_falseallow = 1.0` — implementation sanity check (C is *defined* as marginal-pass/joint-fail).
- Utility trade-off (stable): `R_allow` ≈ 0.065–0.073 at eps/sigma=1.0, recovering to ≈0.58–0.60 at eps=0.03.

**Scope:** `policy_provenance = authored_rego` is *controlled* policy-as-code evidence — it reduces the
analytic-generator-artifact risk but is **not** external-policy validation (needs a vendored
third-party Rego/Gatekeeper bundle in `policies/third_party/`).
