# Track A — third-party Gatekeeper-library prevalence test

Policies: **unmodified** `open-policy-agent/gatekeeper-library` @ commit `6364bd191edb` (Apache-2.0): allowedrepos (`K8sAllowedRepos`, discrete (image prefix)), requiredlabels (`K8sRequiredLabels`, discrete (labels/regex)), containerlimits (`K8sContainerLimits`, numeric (cpu/memory)), hostnetworkports (`K8sPSPHostNetworkingPorts`, numeric/discrete (hostPort)), privileged (`K8sPSPPrivilegedContainer`, discrete (privileged)). Safe(z) iff the policy SET reports zero violations. Manifests sampled (n=400/split, eps=0.1); **policy thresholds NOT tuned**, only manifests vary. Discrete neighborhood = the FROZEN mechanism-tagged registry (`discrete_neighborhoods.json`; `env` excluded — no mechanism). C-witnesses categorized via OPA as a black-box oracle.

## Table P1 — two-stage prevalence funnel (NEW_EXPS_8 gap 1)

The prevalence claim is a PRODUCT: `P(C | corpus) = idiom_rate(corpus) × C_rate_given_idiom`. Stage 1 asks whether the corpus even contains the provenance-conditioned-threshold idiom (a numeric threshold indexed by a categorical).

| stage | quantity | value |
| --- | --- | --- |
| 1 | files scanned | 10 |
| 1 | files with idiom (`has_category_conditioned_threshold`) | 0 |
| 1 | **idiom_rate** | **0.0** |
| 2 | C_rate given idiom | n/a — no idiom-positive policy |
| ✕ | **P(C \| corpus) bound = idiom_rate × C_rate** | **0.0** |

## Category distribution by sampling scheme

| split | n | R% | **C%** | U% | A% | B% |
| --- | --- | --- | --- | --- | --- | --- |
| natural | 400 | 0.0 | **0.0** | 0.1525 | 0.8475 | 0.0 |
| boundary | 400 | 0.0 | **0.0** | 0.985 | 0.015 | 0.0 |

**Reading.** C-prevalence is ~0 under unmodified third-party Gatekeeper policies (an **informative null**), and Table P1 localizes WHY: the null is driven by **stage 1** — `idiom_rate = 0.0` (no vendored policy conditions a numeric threshold on a categorical) — **not** by the sampler. The boundary scheme over-samples the policy limits yet still yields C≈0 (only the discrete-only (A) and continuous-only (B) vulnerabilities of hard validation constraints). The scientific statement: **C-witnesses require policies where discrete provenance shifts a numerical decision boundary** — exactly the idiom Table P1 measures the rate of. Pure Gatekeeper validation policies lack it; the authored provenance-conditioned Rego (Track C, `opa_gate_results.*`) supplies it (idiom_present=True) and yields C ~ 10-12%. Unmodified third-party policies give **prevalence evidence**; authored Rego gives **controlled mechanism evidence**. We do not tune third-party thresholds, the sampler is pre-registered (natural + boundary), and the discrete neighborhood is the frozen mechanism-tagged registry.

