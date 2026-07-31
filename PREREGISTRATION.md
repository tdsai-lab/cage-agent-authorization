# PREREGISTRATION.md — freeze evidence for the prevalence scans

Four of this paper's results are **prevalence scans over third-party corpora**, and all four returned
nulls or near-nulls. A null is only worth anything if the predicate that produced it was fixed
*before* the corpus was seen. This file is the audit trail for that: what was frozen, its SHA-256, when
it was frozen, what decision rule was registered in advance, and what the scan actually returned.

Nothing here has to be taken on trust. Every detector **self-hashes at run time** (`frozen_spec()`
recomputes the SHA-256 of its own source file), every scan writes that hash into its output JSON, and
the hashes below are recomputable from the shipped source with `sha256sum`. If a detector had been
edited after the fact, the hash in the shipped result file would not match the shipped source.

```bash
# recompute every frozen hash from the shipped source
sha256sum bridge_benchmark/experiments/detector/idiom_detector.py \
          bridge_benchmark/experiments/detector/idiom_rescan.py \
          bridge_benchmark/experiments/mcp_substrate/substrate_detector.py \
          bridge_benchmark/experiments/mcp_substrate/openapi_detector.py \
          bridge_benchmark/experiments/mcp_substrate/registry_adjudicate.py

# and read back the hash recorded inside each scan result
python - <<'PY'
import json, pathlib
for f, k in [("bridge_benchmark/cert/out/idiom_scan.json", "prereg.detector_sha256"),
             ("bridge_benchmark/cert/out/idiom_rescan.json", "prereg.frozen_phase1_detector_sha256"),
             ("bridge_benchmark/cert/out/mcp_substrate/stage0_substrate.json", "frozen_detector_sha256"),
             ("bridge_benchmark/cert/out/mcp_substrate/openapi_substrate.json", "frozen_detector_sha256"),
             ("bridge_benchmark/cert/out/exp_mcp_registry_adjudication/summary.json", "stage1_detector_sha256")]:
    d = json.loads(pathlib.Path(f).read_text())
    for part in k.split("."):
        d = d[part]
    print(f"{k:55s} {d}  <- {f}")
PY
```

## 1. Frozen artifacts

The binding evidence is cryptographic, not chronological: each detector hashes **its own source file**
at run time and writes that hash into the result file, so the predicate that produced a reported number
is provably the predicate shipped here. A detector edited after seeing a corpus would not reproduce the
hash recorded in the shipped result.

| artifact | SHA-256 | decides |
|---|---|---|
| `experiments/detector/idiom_detector.py` | `4620bb6be4d8911be5c8dd63e83fef770280e86f57a07040045b7263925c23a3` | the AST idiom predicate: does a policy compare a continuous field against a threshold that is *keyed by a categorical/provenance field*? |
| `experiments/detector/idiom_rescan.py` | `2308fd3f9373eb47bd31475300042d2a1d60f11ca262ff7c87be72f7a4588b70` | the same predicate applied through additional format parsers (OpenFisca AST, JSON rules, DMN decision tables); the parsers were added later, the **predicate is unchanged** and still hashes to the detector above |
| `experiments/mcp_substrate/substrate_detector.py` | `221aa906dca8a79e5ad3d47abfad1756d93a6ea44a825a0a21e241834b9b57f6` | the *data-half* predicate: does a typed tool return carry a continuous operational field `x` **and** a pipeline-set provenance field `s`? |
| `experiments/mcp_substrate/openapi_detector.py` | `466e9dfb8f2da0dacb26be8e21a3c20d5603f5631ef9dd2be1e1427444a329b0` | the same data-half predicate, independently frozen for OpenAPI/Swagger response schemas |
| `experiments/mcp_substrate/registry_adjudicate.py` | `f26b57a976210cb8257c867f1aa7266dcbf360958d6b58d11b27814ce0b49f73` | the two-pass (lexical + frozen semantic table) Stage-2 adjudication rule; disagreement ⇒ OUT |
| `experiments/opa_gate/methodology.py` | `e1338af041131a653a79ef1dd43ccb8f48a21ddb56a1904863889c8d0d3fc970` | the OPA-track sampling schemes, normalization/Δ-ε convention, and mechanism-tagged discrete neighborhoods |

Scan drivers, frozen together with their detectors: `detector/scan_corpus.py` (`be37427ff2e6a16d…`),
`mcp_substrate/stage0_static.py` (`e5e92bcd0b40a36b…`), `mcp_substrate/openapi_scan.py`
(`1e496cd24ac79d63…`), `mcp_substrate/registry_scan.py` (`e165baf9515d1036…`),
`mcp_substrate/openapi_adjudicate.py` (`058296070b3141a1…`). Each scan additionally digests its own
registered protocol block (`prereg_hash`) into its output.

## 2. Registered protocol, per scan

Each scan writes its own pre-registration block into its result JSON (`prereg`, plus a `prereg_hash`
digest of that block), so the registered protocol travels with the numbers.

### P1 — third-party executable policy corpora (`detector/scan_corpus.py`)
- **Population.** All policy files matching the language glob in the listed third-party corpora, each
  pinned to a resolved upstream commit (recorded in `prereg.corpora`).
- **Sampling.** No sampling: every matching file is scanned.
- **Statistic.** A two-stage funnel, registered in advance:
  `Pr[C | corpus] = idiom_rate(corpus) × Pr[C | idiom]`. For a *continuous* θ(s) the C-window has
  length `min(Δ, ε) > 0` so `Pr[C | idiom] ≈ 1`; the factor is kept explicit because a *quantized* θ
  (Azure `keySize`-style) gives `Pr[C | idiom] < 1`.
- **Decision rule (registered before the scan).** HIT if ≥1 continuous θ(s) appears in third-party
  executable code → promote it to the mechanism substrate. NULL if idiom_rate ≈ 0 → record the null,
  **localized at the corpus stage**, and fall back one rung to the regulatory-authored executable
  track. The vendored Gatekeeper library is the **positive null control** and must reproduce
  `idiom_rate = 0`.
- **Detector bias, stated in advance.** The predicate targets the `base[tool] + adj[x₁.field]`
  representation; its error is conservative — it can only *under*-count, never inflate, prevalence.
- **Outcome.** `decision = NULL`, `null_control_reproduced = true`. 1424 k8s-admission policies
  scanned: 39 numeric thresholds, **0 provenance-keyed**. Recorded in `cert/out/idiom_scan.json`
  (`prereg_hash = 9cf6325dadd5f5e0`).

### P1-B / A-DMN — re-scan of the right habitat (`detector/idiom_rescan.py`)
- **Change from P1.** Format parsers only (OpenFisca AST, JSON rules, DMN/XML decision tables). The
  predicate is unchanged and still hashes to the P1 detector — recorded as
  `prereg.frozen_phase1_detector_sha256` and `rescan_adds = "format parsers only … predicate unchanged"`.
- **Two registered axes.** (i) structural idiom present; (ii) whether the key `s` is
  *provenance/pipeline-set* rather than *subject-set*. Reported separately, never merged.
- **Outcome.** `decision = STRUCTURAL_PRESENT_PROVENANCE_NULL`: structural idiom present in
  legislation-as-code and decision tables (OpenFisca 6.8%, DMN-TCK 4.9%, Kogito 11.5%, including the
  OMG DMN specification's own chapter-11 lending example), `provenance_upstream = 0` everywhere; the
  k8s-admission corpus is retained as the H0 scoping control at `idiom_rate_structural = 0.0`.
  Recorded in `cert/out/idiom_rescan.json` (`prereg_hash = 29497a63603701b8`).

### MCP data-half — typed tool returns (`mcp_substrate/stage0_static.py`)
- **Execution.** **Zero.** Static parse only; no third-party code is run. The live-introspection
  escalation (`introspect.py`) was deliberately declined — supply-chain risk against a bonus
  experiment whose null was the expected outcome — and ships unrun behind `--allow-execution`.
- **Population.** The public MCP reference servers, corpus commit `b2a94a21a53f` (overlapping the
  MCPTox 45-server population, whose released artifact contained only poisoning cases, not schemas).
- **Registered funnel.** `Pr[native C | corpus] = Pr[substrate] × Pr[θ-cond | substrate] × Pr[Δ/ε | cond]`.
  Stage 0 reports the first factor and the *location* of any null; Stage 2 runs **only if
  substrate > 0** (an anti-forcing rule fixed in advance).
- **Outcome.** 43 tools, 14 typed returns / 29 untyped, parse coverage 1.0, continuous `x` = 1,
  pipeline-set `s` = 0 ⇒ `substrate_rate = 0.0`, `outcome = NULL_no_typed_return_substrate`, null
  localized at the substrate stage. Recorded in `cert/out/mcp_substrate/stage0_substrate.json`.

### OpenAPI data-half — typed API ecosystem (`mcp_substrate/openapi_{scan,detector,adjudicate}.py`)
- **Rationale for a third scan.** OpenAPI response schemas are mandatorily typed, so the MCP
  untyped-return failure mode cannot recur — a strictly more favourable habitat.
- **Population.** APIs.guru `openapi-directory`, corpus commit `f04b8d0bcd39`: 4138 specs / 701 APIs,
  parse coverage 0.9886 (failures itemised in the output).
- **Two-step registered decision.** Step 1 (frozen detector) yields *candidates*; Step 2 adjudicates
  every candidate `s` field conservatively into `SCHEMA_RESOURCE_META` / `SUBJECT_INSTRUMENT` /
  `DUALUSE_AMBIGUOUS` / `CONFIRMED_PIPELINE`, with dual-use ⇒ OUT; Step 3 requires a **documented
  third-party θ(s)** — authoring one ourselves is explicitly a protocol violation.
- **Outcome.** Candidate substrate 9.8% full corpus / 22.4% financial habitat, but Step 2 gives
  `CONFIRMED_PIPELINE = 0` (driven by `apiVersion`/`resourceVersion` schema metadata — the same k8s
  specs as the policy-half null — plus `routing_number`/`fundingSource` subject attributes), and Step 3
  finds no documented θ(s) ⇒ `outcome = NULL_security_relevant_substrate`. Recorded in
  `cert/out/mcp_substrate/openapi_{substrate,adjudication}.json`.

### A2 — registry-scale adjudication (`mcp_substrate/registry_adjudicate.py`)
- **Input.** The 31 substrate-candidate tools across 8 servers from the registry scan (frozen Stage-1
  detector `221aa906…`, cached schemas). Zero compute, zero execution.
- **Rule.** Two independent passes — lexical, and a frozen per-field semantic table — with
  **disagreement ⇒ OUT**; `CONFIRMED_PIPELINE` only if both agree; a strong hit additionally requires a
  documented third-party θ(s).
- **Outcome.** **1/31** structurally confirmed (`cache_respected`, a cache-freshness boolean; rate
  0.0016 of typed returns, Wilson-95% [0.0003, 0.009]) and **0/31** with a documented θ(s)
  (Wilson-95% [0, 0.006]) ⇒ `outcome = STRUCTURAL_PIPELINE_SET_no_documented_theta`. Per-field verdicts
  and rationales for all 17 distinct `s` fields are in
  `cert/out/exp_mcp_registry_adjudication/summary.json`.

### OPA track — methodological controls (`experiments/opa_gate/methodology.py`)
Registered in code, and hashed above: the two-stage prevalence product
`Pr[C | corpus] = idiom_rate × Pr[C | idiom]`; the two sampling schemes (`natural`, uniform over the
documented operating band, and `boundary`, clustered in the threshold band) — **both** always reported,
labelled, for every domain; the normalization and Δ/ε convention; the frozen mechanism-tagged discrete
neighborhoods (`discrete_neighborhoods.json`); and the exact-verification baseline. For the vendored
Gatekeeper corpus `idiom_rate = 0/10`, so that null is localized at stage 1 — the corpus does not
contain the idiom — rather than manufactured by the sampler.

## 3. What the frozen scans license us to claim

- **Existence and mechanism: yes.** The provenance-keyed continuous threshold exists in third-party
  and regulatory sources (Azure Key Vault `keyType → keySize`; PSD2/AML source-locked thresholds), and
  the joint-gap mechanism is reproduced by real engines (OPA 1.17.1, GoRules ZEN, Marble) on real data.
- **Prevalence in commodity ecosystems: no — and we say so.** Three independent frozen scans (policy
  half: k8s admission; data half: MCP; data half: OpenAPI) plus the A2 registry adjudication agree that
  the substrate is **not spontaneous** in commodity typed ecosystems. These are reported as informative
  nulls with the funnel stage at which each null is localized, never as evidence of prevalence and
  never quietly dropped.
- The abstract, introduction and results text are scoped to *existence + mechanism + engine
  validation*. Any sentence that would read as a prevalence claim is a bug; this file is the standard
  against which to check.
