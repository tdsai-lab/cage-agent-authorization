#!/usr/bin/env python3
"""
test_ieee_opa_cwitness.py — PLAN #9b: Category-C witness on a continuous EXECUTABLE policy over REAL
IEEE-CIS data, labelled by the OPA engine. Skips if the OPA binary or the IEEE-CIS data is absent.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
_OPA = _BB / "experiments" / "opa_gate"
for p in (_OPA, _BB / "realdata", _BB / "generators"):
    sys.path.insert(0, str(p))

opa_bridge = pytest.importorskip("opa_bridge")
try:
    opa_bridge.opa_path()
except FileNotFoundError:
    pytest.skip("OPA binary not available", allow_module_level=True)

import ieee_cis_opa_cwitness as cw  # noqa: E402

if not cw.IEEE_PATH.exists():
    pytest.skip("IEEE-CIS data not present", allow_module_level=True)


@pytest.fixture(scope="module")
def labelled():
    recs = cw.load_records(n=1500)
    cats = cw.categorize_via_opa(recs, eps=0.10)
    return recs, cats


def test_engine_produces_C_on_real_data(labelled):
    recs, cats = labelled
    n_c = sum(1 for c in cats if c["category"] == "C")
    assert n_c > 0, "the OPA engine must label some real transactions Category C"


def test_each_engine_C_is_a_real_joint_gap_witness(labelled):
    recs, cats = labelled
    c_idx = [i for i, c in enumerate(cats) if c["category"] == "C"][:8]
    assert c_idx
    for i in c_idx:
        w = cw.witness_trace(recs[i], eps=0.10)
        # the C definition, every label produced by OPA:
        assert w["engine_clean_safe"] is True
        assert w["engine_after_swap_only"] is True      # no provenance swap alone flips
        assert w["engine_after_eps_only"] is True        # no eps move alone flips
        assert w["engine_after_joint"] is False          # the JOINT move flips -> unsafe


def test_engine_reproduces_analytic_taxonomy(labelled):
    recs, cats = labelled
    both = [(c["category"], r["analytic_category"]) for c, r in zip(cats, recs)
            if r["analytic_category"] in ("A", "B", "C", "R", "U")]
    agree = sum(1 for e, a in both if e == a) / max(1, len(both))
    assert agree > 0.8, f"engine should reproduce the analytic taxonomy (agreement={agree:.3f})"
