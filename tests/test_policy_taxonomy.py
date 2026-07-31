#!/usr/bin/env python3
"""
test_policy_taxonomy.py — EXP-POLICY-THIRD-PARTY. Tests the thin 5-level classification WRAPPER on top
of the FROZEN idiom detector:
  (a) the 5-level classifier returns a valid label for representative fixture snippets
      (discrete_only / fixed_numeric_threshold / conditioned_numeric_threshold / affine);
  (b) the frozen detector sha256 recorded by the script matches idiom_detector.frozen_spec();
  (c) the script runs end-to-end on a TINY fixture dir and emits the 4 output files.
Fast + deterministic; uses inline Rego fixtures (no cloned-corpus dependency).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
_DET = _BB / "experiments" / "detector"
_EXP = _BB / "experiments"
sys.path.insert(0, str(_DET))
sys.path.insert(0, str(_EXP))

import shutil  # noqa: E402
import pytest  # noqa: E402

if not ((_BB / "experiments" / "opa_gate" / "bin" / "opa").exists() or shutil.which("opa")):
    pytest.skip("opa binary not available (see REPRODUCE.md, rows tagged 'opa')",
                allow_module_level=True)

import idiom_detector as idet  # noqa: E402
import exp_policy_third_party as exp  # noqa: E402


# --- tiny Rego fixtures (no opa needed: classification uses detect_file's AST path; opa eval is only
#     needed for Part B/C, which the end-to-end test exercises via the real binary if present) -------
_REGO_DISCRETE = """package t.discrete
deny := true if { input.image != "registry.company.com/app" }
"""

_REGO_FIXED = """package t.fixed
deny := true if { input.cpu > 1000 }
"""

_REGO_CONDITIONED = """package t.cond
theta_base := 0.4
delta := 0.1
loose := {"loose"}
threshold(tool) := theta_base + delta if loose[tool]
threshold(tool) := theta_base if not loose[tool]
deny := true if { input.risk_score >= threshold(input.tool) }
"""


def _detect(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body)
    return p, idet.detect_file(p, "rego")


# --------------------------------------------------------------------------- #
# (a) 5-level classifier on representative snippets
# --------------------------------------------------------------------------- #
def test_classifier_valid_labels_per_snippet(tmp_path):
    for name, body in [("discrete.rego", _REGO_DISCRETE), ("fixed.rego", _REGO_FIXED),
                       ("cond.rego", _REGO_CONDITIONED)]:
        p, hit = _detect(tmp_path, name, body)
        label = exp.classify_taxonomy(hit, exp._count_numeric_fields(p, "rego"))
        assert label in exp.TAX_LEVELS, f"{name} -> {label} not a valid level"

    # conditioned snippet: the frozen detector recognises θ(tool) -> conditioned (or affine if ≥2 fields)
    p, hit = _detect(tmp_path, "cond.rego", _REGO_CONDITIONED)
    assert hit.idiom_present is True
    label = exp.classify_taxonomy(hit, exp._count_numeric_fields(p, "rego"))
    assert label in (exp.TAX_CONDITIONED, exp.TAX_AFFINE)

    # discrete snippet: no numeric comparison -> discrete_only
    p, hit = _detect(tmp_path, "discrete.rego", _REGO_DISCRETE)
    assert hit.idiom_present is False
    assert exp.classify_taxonomy(hit, exp._count_numeric_fields(p, "rego")) == exp.TAX_DISCRETE


def test_classifier_decision_tree_is_pure_function_of_signals():
    # parse error -> unknown
    bad = idet.IdiomHit("rego", False, evidence="parse_error:x")
    assert exp.classify_taxonomy(bad, 0) == exp.TAX_UNKNOWN
    # numeric but constant -> fixed
    fixed = idet.IdiomHit("rego", False, numeric_threshold=True, evidence="no_provenance_threshold")
    assert exp.classify_taxonomy(fixed, 1) == exp.TAX_FIXED
    # idiom present, 1 field -> conditioned ; ≥2 fields -> affine
    cond = idet.IdiomHit("rego", True, numeric_threshold=True, evidence="ast:function_call")
    assert exp.classify_taxonomy(cond, 1) == exp.TAX_CONDITIONED
    assert exp.classify_taxonomy(cond, 3) == exp.TAX_AFFINE
    # nothing numeric -> discrete
    disc = idet.IdiomHit("rego", False, numeric_threshold=False, evidence="no_provenance_threshold")
    assert exp.classify_taxonomy(disc, 0) == exp.TAX_DISCRETE


# --------------------------------------------------------------------------- #
# (b) recorded frozen-detector sha256 matches the frozen spec
# --------------------------------------------------------------------------- #
def test_recorded_detector_hash_matches_frozen_spec(tmp_path):
    fixt = tmp_path / "corpus"
    fixt.mkdir()
    (fixt / "discrete.rego").write_text(_REGO_DISCRETE)
    out = tmp_path / "out"
    sys.argv = ["exp", "--policy-dir", str(fixt), "--epsilon", "0.10",
                "--out", str(out), "--max-files", "50", "--n-opa", "20"]
    summary = exp.main()
    assert summary["frozen_detector_sha256"] == idet.frozen_spec()["detector_sha256"]
    # and it is persisted to summary.json identically
    js = json.loads((out / "summary.json").read_text())
    assert js["frozen_detector_sha256"] == idet.frozen_spec()["detector_sha256"]


# --------------------------------------------------------------------------- #
# (c) end-to-end on a tiny fixture dir emits the 4 output files
# --------------------------------------------------------------------------- #
def test_end_to_end_emits_four_outputs(tmp_path):
    # a tiny fixture "corpus" that does NOT match any known third-party subdir name, so the third-party
    # corpora are all skipped (logged) and only authored controls + any matched files are classified.
    fixt = tmp_path / "corpus"
    fixt.mkdir()
    out = tmp_path / "out"
    sys.argv = ["exp", "--policy-dir", str(fixt), "--epsilon", "0.10",
                "--out", str(out), "--max-files", "50", "--n-opa", "20"]
    summary = exp.main()

    for fname in ("policy_taxonomy.csv", "c_witnesses.jsonl", "summary.json", "summary.md"):
        assert (out / fname).exists(), f"missing output {fname}"

    # authored controls are always present and labeled authored_control (never mixed with third_party)
    rows = (out / "policy_taxonomy.csv").read_text().splitlines()
    assert any("authored_control" in r for r in rows)
    # taxonomy distribution keys are exactly the 5 levels
    assert set(summary["tax_counts_all"].keys()) == set(exp.TAX_LEVELS)
    # all the missing third-party corpora were skipped + logged
    assert len(summary["skipped_corpora"]) >= 1
