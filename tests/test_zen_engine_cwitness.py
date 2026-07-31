#!/usr/bin/env python3
"""
test_zen_engine_cwitness.py — PLAN_2_RESCAN_BIS B2. A REAL production engine (GoRules ZEN/JDM) must
label real IEEE-CIS transactions as Category-C joint-gap witnesses and reproduce the analytic taxonomy.
Skips if zen-engine or the IEEE-CIS data is absent.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
sys.path.insert(0, str(_BB / "experiments"))
sys.path.insert(0, str(_BB / "realdata"))

pytest.importorskip("zen")
import zen_engine_cwitness as zc  # noqa: E402

if not zc.IEEE_PATH.exists():
    pytest.skip("IEEE-CIS data not present", allow_module_level=True)


@pytest.fixture(scope="module")
def labelled():
    recs = zc.load_records(n=1500)
    gate = zc.ZenGate()
    return recs, gate, zc.categorize(gate, recs, eps=0.10)


def test_zen_decision_table_threshold_semantics():
    gate = zc.ZenGate()
    # loose threshold (theta+delta) is higher than strict (theta): a mid-risk txn flips on the swap
    assert gate.safe("loose", zc.THETA + 0.04) is True       # < 0.5688
    assert gate.safe("strict", zc.THETA + 0.04) is False     # >= 0.4888


def test_engine_produces_C_on_real_data(labelled):
    _, _, cats = labelled
    assert sum(1 for c in cats if c["category"] == "C") > 0


def test_each_engine_C_is_a_joint_gap_witness(labelled):
    _, _, cats = labelled
    cwits = [c for c in cats if c["category"] == "C"][:10]
    assert cwits
    for w in cwits:
        assert w["engine_clean_safe"] is True
        assert w["engine_swap_only"] is True      # provenance swap alone does not flip
        assert w["engine_eps_only"] is True        # eps move alone does not flip
        assert w["engine_joint"] is False          # the JOINT move flips -> unsafe


def test_engine_reproduces_analytic_taxonomy(labelled):
    recs, _, cats = labelled
    both = [(c["category"], r["analytic_category"]) for c, r in zip(cats, recs)
            if r["analytic_category"] in ("A", "B", "C", "R", "U")]
    agree = sum(1 for e, a in both if e == a) / max(1, len(both))
    assert agree > 0.9, f"ZEN engine vs analytic agreement {agree:.3f}"
