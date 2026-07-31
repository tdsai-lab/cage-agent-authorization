#!/usr/bin/env python3
"""
test_marble_cwitness.py — RUNBOOK closure. A REAL purpose-built AML engine (Marble, checkmarble/marble)
must label real IEEE-CIS transactions as Category-C joint-gap witnesses through its own decision API and
reproduce the analytic taxonomy. Skips unless Marble is live locally AND the published scenario + API key
exist (external infra: rootless podman + Marble backend, see HANDOFF_MARBLE_PODMAN.md).
"""
from __future__ import annotations

import sys
import os
from pathlib import Path

import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
sys.path.insert(0, str(_BB / "experiments"))
sys.path.insert(0, str(_BB / "realdata"))

import marble_cwitness as mc  # noqa: E402

if not mc.IEEE_PATH.exists():
    pytest.skip("IEEE-CIS data not present", allow_module_level=True)

_MARBLE_DIR = Path(os.environ.get("MARBLE_DIR", "external/marble_src"))


def _marble_ready():
    try:
        code, _ = mc._http("GET", f"{mc.API}/liveness")
    except Exception:
        return False
    return code == 200 and (_MARBLE_DIR / ".scenario_id").exists() and (_MARBLE_DIR / ".api_key").exists()


if not _marble_ready():
    pytest.skip("Marble backend not live / scenario not published (external infra)",
                allow_module_level=True)


@pytest.fixture(scope="module")
def labelled():
    scenario_id = (_MARBLE_DIR / ".scenario_id").read_text().strip()
    api_key = (_MARBLE_DIR / ".api_key").read_text().strip()
    gate = mc.MarbleGate(api_key, scenario_id)
    recs = mc.load_records(n=200)
    return recs, gate, mc.categorize(gate, recs, eps=0.10)


def test_marble_threshold_semantics():
    scenario_id = (_MARBLE_DIR / ".scenario_id").read_text().strip()
    api_key = (_MARBLE_DIR / ".api_key").read_text().strip()
    gate = mc.MarbleGate(api_key, scenario_id)
    # loose threshold (theta+delta) is higher than strict (theta): a mid-risk txn flips on the swap
    assert gate.safe("loose", mc.THETA + 0.04) is True       # < 0.5688 -> approve
    assert gate.safe("strict", mc.THETA + 0.04) is False     # >= 0.4888 -> review


def test_engine_produces_C_on_real_data(labelled):
    _, _, cats = labelled
    assert sum(1 for c in cats if c["category"] == "C") > 0


def test_each_engine_C_is_a_joint_gap_witness(labelled):
    _, _, cats = labelled
    cwits = [c for c in cats if c["category"] == "C"][:10]
    assert cwits
    for w in cwits:
        assert w["engine_clean_safe"] is True
        assert w["engine_swap_only"] is True       # provenance swap alone does not flip
        assert w["engine_eps_only"] is True         # eps move alone does not flip
        assert w["engine_joint"] is False           # the JOINT move flips -> unsafe


def test_engine_reproduces_analytic_taxonomy(labelled):
    recs, _, cats = labelled
    both = [(c["category"], r["analytic_category"]) for c, r in zip(cats, recs)
            if r["analytic_category"] in ("A", "B", "C", "R", "U")]
    agree = sum(1 for e, a in both if e == a) / max(1, len(both))
    assert agree > 0.9, f"Marble engine vs analytic agreement {agree:.3f}"
