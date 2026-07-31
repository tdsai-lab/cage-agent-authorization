#!/usr/bin/env python3
"""
test_a7_second_adapter.py — A7. A second, independent real adapter (k8s cost admission via real Kyverno)
reproduces the A/B/C/R/U taxonomy + non-composition. Pure taxonomy logic runs always; the real-Kyverno
arms need the cluster + the cost policy applied.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

_H = Path(__file__).resolve().parents[1] / "bridge_benchmark" / "experiments" / "e2e" / "real_harness"
sys.path.insert(0, str(_H))
import a7_second_adapter as a7  # noqa: E402
import run_p3 as p3  # noqa: E402


def test_taxonomy_has_C_band():
    # a genuine Category-C band exists on the continuous cost channel
    cats = {a7.category(c) for c in [0.20, 0.45, 0.60, 0.90]}
    assert a7.category(0.45) == "C"          # in (theta_strict-eps, theta_strict) = (0.40, 0.50)
    assert a7.category(0.20) == "R" and a7.category(0.90) == "U"


def test_cwitness_is_a_joint_gap():
    # clean/swap/eps all admit, only the joint move denies
    c = 0.45
    assert a7.analytic_admit("loose", c) and a7.analytic_admit("strict", c)
    assert a7.analytic_admit("loose", c + a7.EPS)
    assert not a7.analytic_admit("strict", c + a7.EPS)


def _ready():
    if shutil.which("sg") is None:
        return False
    rc, _ = p3._sh("kubectl get clusterpolicy cost-cap-by-tier -o name", timeout=30)
    return rc == 0


@pytest.mark.skipif(not _ready(), reason="kind cluster + cost-cap-by-tier policy not up")
def test_real_kyverno_reproduces_noncomposition():
    res = a7.run(n_taxonomy=50, n_validate=5, n_cwit=4, seed=0)
    assert res["engine_vs_analytic_agreement"] >= 0.95     # adapter verdict matches real Kyverno
    assert res["real_kyverno_C_witnesses"] >= 1
    assert res["noncomposition"] is True                    # engine admits every marginal, denies the joint
