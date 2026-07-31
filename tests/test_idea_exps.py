#!/usr/bin/env python3
"""
test_idea_exps.py — IDEA #3 (tool-selection poisoning as a controlled limit) and #4 (low-dim policy-state
projection). Both reuse the synthetic tool table + analytic oracle (+ smoothed cert for #4). sklearn/numpy.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
for p in ("experiments", "generators", "models", "cert"):
    sys.path.insert(0, str(_BB / p))

pytest.importorskip("numpy")
pytest.importorskip("sklearn")


# --------------------------------------------------------------------------- #
# IDEA #3 — tool-selection poisoning
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def sel():
    import tool_selection_attack as ts
    return ts.run_table(K=12, k=4, seed=0, n=6000, poison_boost=1.0)


def _regime(res, name):
    return next(r for r in res["regimes"] if r["regime"] == name)


def test_selection_poisoning_flips_selection(sel):
    for r in sel["regimes"]:
        assert r["retrieval_asr"] >= 0.5              # metadata poisoning does flip the top-1 selection


def test_gate_covers_in_budget_misselection(sel):
    wg = _regime(sel, "within_group")
    assert wg["P_unsafe_no_gate"] > 0.5               # dangerous mis-selection is harmful undefended
    assert wg["P_unsafe_certified"] == 0.0            # correct tool is a d=1 neighbour -> gate covers it


def test_gate_does_not_certify_cross_action_selection(sel):
    ca = _regime(sel, "cross_action")
    # the limit: a selection error across the action boundary is out of the per-action budget
    assert ca["P_unsafe_certified"] > 0.0
    assert ca["P_unsafe_certified"] < ca["P_unsafe_no_gate"]   # still reduced vs no-gate


# --------------------------------------------------------------------------- #
# IDEA #4 — low-dim policy-state projection
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def proj_cell():
    import policy_state_projection as pp
    # a small but non-trivial cell: 5 active fields inside a 60-dim return, data-limited
    return pp.run_cell(k_active=5, k_raw=60, n=2000, n_cert=60, n_mc=400, sigma=0.10, n_aug=6, seed=0)


def test_oracle_projection_high_fidelity(proj_cell):
    g = proj_cell["gates"]["oracle_proj"]
    assert g["n_fields_used"] == 5                     # the true policy state
    assert g["fidelity"] >= 0.9                        # seeing exactly the policy fields -> high fidelity


def test_projection_sound_and_nonvacuous(proj_cell):
    g = proj_cell["gates"]["oracle_proj"]
    assert g["cert_false_allow"] == 0.0                # sound
    assert g["R_allow"] is not None and g["R_allow"] > 0.0   # non-vacuous


def test_all_gates_sound(proj_cell):
    # soundness (cert_false_allow=0) is the invariant; utility (fidelity/R_allow) is what the projection buys
    for name, g in proj_cell["gates"].items():
        assert g["cert_false_allow"] == 0.0, f"{name} cert_false_allow={g['cert_false_allow']}"
