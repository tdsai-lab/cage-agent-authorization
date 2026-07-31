#!/usr/bin/env python3
"""
test_adaptive.py — PLAN_2 P2 (Task D): the out-of-budget breaking-radius sweep. The certificate must be
SOUND for every in-budget point (cfa=0 at d=1, ε≤ε_cert) and each break must occur STRICTLY OUTSIDE
B_{1,ε_cert}. Reuses the analytic oracle + #16 fault injectors (numpy only).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
sys.path.insert(0, str(_BB / "experiments" / "adaptive"))
sys.path.insert(0, str(_BB / "generators"))
sys.path.insert(0, str(_BB / "agents"))
sys.path.insert(0, str(_BB / "experiments"))

pytest.importorskip("numpy")
import out_of_budget_attacks as oob  # noqa: E402


@pytest.fixture(scope="module")
def finance():
    return oob.run_domain("financial_compliance", n_pool=4000, seed=0,
                          eps_grid=[0.10, 0.125, 0.15, 0.20, 0.30], d_grid=[1, 2, 3])


def test_cert_sound_in_budget(finance):
    assert finance["in_budget_cfa"] == 0.0
    # cfa at the declared budget point (d=1, ε=ε_cert) is exactly 0 in the ε-sweep too
    assert finance["sweep_eps_radius"]["cfa"][0] == 0.0
    assert finance["sweep_d_radius"]["cfa"][0] == 0.0


def test_eps_break_strictly_outside(finance):
    br = finance["sweep_eps_radius"]["breaking_radius_eps"]
    assert br is not None and br > oob.EPS_CERT     # first ε leak is strictly outside the ball


def test_d_break_strictly_outside(finance):
    br = finance["sweep_d_radius"]["breaking_radius_d"]
    assert br is not None and br > oob.D_CERT       # first d leak needs d>=2
    assert br == 2


def test_eps_cfa_monotone_nondecreasing(finance):
    cfa = finance["sweep_eps_radius"]["cfa"]
    assert all(b >= a - 1e-9 for a, b in zip(cfa, cfa[1:]))   # graceful, monotone degradation


def test_in_budget_mechanism_covered(finance):
    row = next((m for m in finance["mechanism_placement"]
                if m["mechanism"] == "wrong_provenance_binding"), None)
    assert row is not None
    assert row["max_d"] <= oob.D_CERT               # a single provenance swap is d=1
    assert row["P_unsafe_given_cert"] == 0.0        # in-budget → cert covers it
