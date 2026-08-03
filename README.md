# CAGE — Certified Authorization under Typed-Return Uncertainty for Tool-Using Agents

Code for the paper [*CAGE: Certified Authorization under Typed-Return Uncertainty for Tool-Using Agents*](https://arxiv.org/abs/2607.29190).

Tool-using LLM agents act on **typed tool returns** — records pairing provenance and categorical
fields `s` with numerical values `x`. Runtime permission systems generally evaluate only the observed
return–action pair. CAGE asks whether a candidate action stays authorized over a **declared
neighborhood** of plausible correctly-bound returns: one admissible binding fault plus bounded
numerical drift,

```
B_{d,ε}(z) = { z' :  D_disc((t,x₁),(t',x₁')) ≤ d   and   ‖x₂ − x₂'‖₂ ≤ ε }      (MVP: d = 1)
```

The core result is that **marginal checks do not compose**: there are returns (Category **C**) where a
discrete-only certificate is sound *and* a continuous-only certificate is sound, yet the joint move
makes the same action unsafe. Only a certificate over the joint neighborhood is correct. CAGE
enumerates the discrete branches exactly and certifies each continuous branch with a sound backend
from an assumption ladder (exact predicate ▸ deterministic 1-Lipschitz ▸ randomized smoothing ▸
complete verification as a ceiling).

## Start here

| file | what it is |
|---|---|
| [`PAPER_MAPPING.md`](PAPER_MAPPING.md) | **every table in the paper → the command that produces it** (Tables 1–6, S1–S51, Fig. 4, and the formal claims → code) |
| [`REPRODUCE.md`](REPRODUCE.md) | one row per experiment: command, what it needs (CPU / GPU / `opa` / LLM / licensed data), where its numbers land |
| [`PREREGISTRATION.md`](PREREGISTRATION.md) | freeze evidence for the four prevalence scans: detector SHA-256s, registered protocols, and the nulls they returned |

## Quick start (CPU-only, no dataset, ~5 minutes)

```bash
bash setup.sh                 # checks Python, dependencies and optional backends
python -m pytest -q           # test suite (GPU / data / engine / cluster tests self-skip)

# the core claim, model-free and dependency-free (pure standard library):
python bridge_benchmark/generators/test_oracle.py        # 10/10 oracle unit tests
python bridge_benchmark/generators/generate.py           # records + "C-witness invariant violations: 0"
python bridge_benchmark/cert/certificate_oracles.py      # non-composition: C rows naive=FALSE, R rows hybrid=safe

# the learned + certified gate (needs numpy / scipy / scikit-learn):
python bridge_benchmark/cert/evaluate_certificates.py    # ~8 s
```

## Layout

```
bridge_benchmark/
  generators/     analytic policy oracle Safe(z,a), category verifier, record generator (pure stdlib)
  schemas/        action-indexed rule tables + record schemas
  models/         learned tabular gate s_θ(z,a) + baselines
  attacks/        empirical mixed attack over B_{1,ε}; adaptive gate attack
  cert/           certificate backends + evaluation (exact fragment, RS, audits, ablations)
    out/            aggregated results the paper's tables are built from
  comparators/    CaMeL-style and pre-execution-classifier comparators
  experiments/    every experiment script (see PAPER_MAPPING.md / REPRODUCE.md)
    lip_gate/       deterministic 1-Lipschitz backend (primary certified backend)
    opa_gate/       OPA/Rego policy-as-code oracle + third-party Gatekeeper track
    detector/       frozen AST idiom detector + pre-registered corpus scans
    mcp_substrate/  frozen MCP / OpenAPI typed-return substrate scans
    policy_idiom_prevalence/  Azure + PSD2/AML source-locked policy grounding
    e2e/real_harness/  Kubernetes + Kyverno + MCP end-to-end harness
  agents/         LLM-agent integration (the gate is certified, the LLM is not)
  realdata/       IEEE-CIS and NAB adapters
  benchmarks/     AmPermBench-grounded adapter
  data/           datasets and fixtures — see bridge_benchmark/data/README.md for licensing
tests/            pytest suite
scripts/          dataset download and helper scripts
notes/            record format, interaction taxonomy (A/B/C/D/R), rule provenance, seed payloads
```

## Environment

`setup.sh` verifies the environment and reports, per capability, whether it is available.

- **Python 3.12** (3.11+ should work).
- `requirements.txt` — numpy / scipy / scikit-learn / pandas / matplotlib / PyYAML / pytest. The
  analytic core (`generators/`, `cert/certificate_oracles.py`, `cert/fragment.py`, the frozen
  detectors) needs **none** of these: it is pure standard library.
- `requirements-optional.txt` — `torch` + `orthogonium` (deterministic 1-Lipschitz backend, GPU
  recommended) and `zen-engine` (GoRules decision engine).
- **OPA 1.17.1** — not vendored; `setup.sh` prints the download command for
  `bridge_benchmark/experiments/opa_gate/bin/opa`.
- **Ollama** with `qwen2.5:7b-instruct`, `qwen2.5:32b`, `qwen3.6:latest` for the real-LLM rows. Every
  LLM experiment also runs offline with `--llm-backend mock`; the LLM is a validation layer, never
  part of a certificate.

## Data

`bridge_benchmark/data/` ships the synthetic fixtures and the MIT-licensed NAB telemetry. The
IEEE-CIS competition data is **not** redistributable — `scripts/download_ieee_cis.py` fetches it from
Kaggle and verifies it against the SHA-256 of the exact files used, after which the seeded
preprocessing reproduces our records bit-for-bit. See
[`bridge_benchmark/data/README.md`](bridge_benchmark/data/README.md).

Third-party policy corpora (for the prevalence scans) are cloned into `external/corpora/`; each scan
script prints its expected path and upstream URL when a corpus is missing.

## Citation

```bibtex
@inproceedings{cage2026,
  title     = {{CAGE}: Certified Authorization under Typed-Return Uncertainty for Tool-Using Agents},
  author    = {TODO: author list},
  booktitle = {TODO: venue},
  year      = {2026}
}
```

## License

MIT — see [`LICENSE`](LICENSE). The vendored NAB telemetry under
`bridge_benchmark/data/realdata/nab/` is MIT-licensed by its authors; IEEE-CIS data is not
redistributed.
