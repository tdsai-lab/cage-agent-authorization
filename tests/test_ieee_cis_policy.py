#!/usr/bin/env python3
"""
test_ieee_cis_policy.py — the constructed provenance policy: Safe == threshold comparison, category
logic, and analytic vs brute-force agreement. Run: python -m pytest tests/test_ieee_cis_policy.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_root))
sys.path.insert(0, str(_root / "bridge_benchmark" / "generators"))

from bridge_benchmark.realdata import ieee_cis_policy as pol  # noqa: E402

X1 = {"ProductCD": "W", "card4": "visa", "card6": "debit",
      "amount_band": "medium", "email_domain_match": "missing"}
THETA, DELTA, EPS = 0.50, 0.08, 0.10
LOOSE, STRICT = "payment_gateway_loose", "identity_risk_strict"


def test_safe_is_threshold_comparison():
    # strict threshold = theta; loose threshold = theta + delta
    assert pol.safe(0.49, STRICT, X1, THETA, DELTA) is True
    assert pol.safe(0.51, STRICT, X1, THETA, DELTA) is False
    assert pol.safe(0.55, LOOSE, X1, THETA, DELTA) is True     # 0.55 <= 0.58
    assert pol.safe(0.59, LOOSE, X1, THETA, DELTA) is False


def test_clean_unsafe_is_category_U():
    r = THETA + DELTA + 0.05                                   # above the loose threshold too
    res = pol.analytic_category(r, LOOSE, X1, THETA, DELTA, EPS)
    assert res["category"] == "U"
    assert res["clean_safe"] is False


def test_robust_interior_is_R():
    r = THETA - 0.30                                           # deep below every threshold
    res = pol.analytic_category(r, STRICT, X1, THETA, DELTA, EPS)
    assert res["category"] == "R"
    assert res["witness"] is None


def test_c_interval_point_is_category_C_with_joint_witness():
    # loose tool, risk in (theta - eps, theta]  and  <= theta + delta - eps
    lo, hi = pol.c_interval(THETA, DELTA, EPS)
    assert lo < hi, "C interval must be non-degenerate for delta<=eps or eps<=delta"
    r = (lo + hi) / 2.0
    res = pol.analytic_category(r, LOOSE, X1, THETA, DELTA, EPS)
    assert res["category"] == "C"
    assert res["clean_safe"] is True
    # discrete-only safe AND continuous-only safe, but joint unsafe
    assert res["discrete_only_unsafe"] is False
    assert res["continuous_only_unsafe"] is False
    assert res["joint_unsafe"] is True
    # the stored witness (strict swap + <=eps risk move) is itself unsafe
    w = res["witness"]
    assert w is not None and w["tool_id"] in pol.STRICT_TOOLS and w["label"] == 0
    assert pol.safe(w["risk_score_witness"], w["tool_id"], X1, THETA, DELTA) is False


def test_c_record_marginal_witnesses_are_safe():
    """For a C record: the discrete swap alone (eps=0) is safe, and the continuous move alone (own
    tool) is safe — only their joint is unsafe."""
    lo, hi = pol.c_interval(THETA, DELTA, EPS)
    r = (lo + hi) / 2.0
    # discrete-only: strict tool, no continuous move
    assert pol.safe(r, STRICT, X1, THETA, DELTA) is True
    # continuous-only: own (loose) tool, risk + eps
    assert pol.safe(min(r + EPS, 1.0), LOOSE, X1, THETA, DELTA) is True


def test_analytic_matches_brute_force_on_grid():
    import numpy as np
    for tool in pol.TOOLS:
        for r in np.linspace(0.0, 1.0, 101):
            a = pol.analytic_category(float(r), tool, X1, THETA, DELTA, EPS)["category"]
            b = pol.brute_force_category(float(r), tool, X1, THETA, DELTA, EPS)
            assert a == b, f"mismatch tool={tool} r={r:.3f}: analytic={a} brute={b}"


def test_c_interval_length_is_min_delta_eps():
    for delta, eps in [(0.08, 0.10), (0.12, 0.10), (0.05, 0.05)]:
        lo, hi = pol.c_interval(THETA, delta, eps)
        assert abs((hi - lo) - min(delta, eps)) < 1e-9


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
