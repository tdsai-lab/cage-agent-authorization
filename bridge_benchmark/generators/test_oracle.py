#!/usr/bin/env python3
"""
test_oracle.py — unit tests for the analytic action-indexed oracle (the paper's specification, PLAN2 step 10).

Run directly:  python test_oracle.py   (exit 0 = all pass, 1 = failure)
Also importable as pytest test functions.

Covers the PLAN2 step-10 checklist:
  * threshold finance C example / R example
  * affine monitoring C example / R example
  * action-indexed reversal: same z, different a -> different Safe(z, a)
  * valid_range does NOT clip adversarial epsilon
  * d = 1 enumeration size
  * witness margins: pre < 0, post >= 0
  * grid-search falsification cannot override the analytic oracle (R has no flip)
"""
from __future__ import annotations

import sys

from oracle import (
    load_rule_table, safe, category, continuous_reachable_unsafe, discrete_cardinality, _x1,
)
from verify_interaction_type import verify_interaction_type, falsification_cross_check

RT = load_rule_table()
EPS = 0.10
FIN = RT["domains"]["financial_compliance"]


def _fin(tool, risk, action="approve_transaction", country="US", channel="card", amount=0.2):
    return {"domain": "financial_compliance", "tool_id": tool, "candidate_action": action,
            "categorical_fields": {"counterparty_country": country, "channel": channel},
            "numeric_fields": {"risk_score": risk, "amount_norm": amount}}


def _mon(tool, er, lat, action="suppress_alert", severity="SEV3"):
    return {"domain": "system_monitoring", "tool_id": tool, "candidate_action": action,
            "categorical_fields": {"severity": severity},
            "numeric_fields": {"error_rate": er, "latency_norm": lat}}


# --------------------------------------------------------------------------- #
def test_threshold_finance_C():
    res = verify_interaction_type(_fin("credit_check", 0.45), RT, d=1, eps=EPS)
    assert res["category"] == "C_joint_gap", res
    assert res["joint_gap_witness"]["tool_id"] == "sanctions_screen"
    assert res["witness_audit_ok"] is True
    assert res["is_multivariate_joint"] is False


def test_threshold_finance_R():
    res = verify_interaction_type(_fin("credit_check", 0.20), RT, d=1, eps=EPS)
    assert res["category"] == "R_robust_interior", res


def test_affine_monitoring_C_and_D():
    res = verify_interaction_type(_mon("memory_monitor", 0.600, 0.635), RT, d=1, eps=EPS)
    assert res["category"] == "C_joint_gap", res
    assert res["is_multivariate_joint"] is True, "monitoring affine [1,1] must be category D"
    assert res["joint_gap_witness"]["tool_id"] == "incident_detector"
    assert "witness_weight_norm" in res["joint_gap_witness"]


def test_affine_monitoring_R():
    res = verify_interaction_type(_mon("memory_monitor", 0.40, 0.40), RT, d=1, eps=EPS)
    assert res["category"] == "R_robust_interior", res


def test_action_indexed_reversal():
    # Same z, two actions, opposite safety. risk 0.95: approving is unsafe, rejecting is safe.
    z = _fin("credit_check", 0.95)
    assert safe(z, "approve_transaction", RT) is False
    assert safe(z, "reject_transaction", RT) is True


def test_valid_range_does_not_clip_adversary():
    # Oracle must evaluate numeric values outside valid_range [0,1] without clipping/raising.
    z = _fin("credit_check", 1.5)  # 1.5 is outside the clean valid_range
    assert safe(z, "approve_transaction", RT) is False  # 1.5 >= 0.90 -> unsafe, computed, not clipped
    # A near-boundary point whose continuous flip needs x2 to move in the unsafe direction:
    z2 = _fin("market_data", 0.92)  # theta 0.95
    cru = continuous_reachable_unsafe(z2, "approve_transaction", RT, EPS)
    assert cru["reachable"] is True  # m + eps = -0.03 + 0.10 >= 0; uses unconstrained L2 ball


def test_d1_enumeration_size():
    # |D_1| = 1 (identity) + (4-1) tool swaps + (3-1) country + (3-1) channel = 8
    n = discrete_cardinality(FIN, "credit_check", {"counterparty_country": "US", "channel": "card"}, d=1)
    assert n == 8, n


def test_witness_margins_pre_neg_post_nonneg():
    for rec in (_fin("credit_check", 0.45), _mon("memory_monitor", 0.600, 0.635)):
        w = verify_interaction_type(rec, RT, d=1, eps=EPS)["joint_gap_witness"]
        assert w["pre_continuous_margin"] < 0.0, w
        assert w["post_continuous_margin"] >= 0.0, w


def test_falsification_cannot_override_R():
    # The analytic verdict is R; a falsification sweep must NOT find any flip (consistency).
    for rec in (_fin("credit_check", 0.20), _mon("memory_monitor", 0.40, 0.40)):
        assert verify_interaction_type(rec, RT, d=1, eps=EPS)["category"] == "R_robust_interior"
        fc = falsification_cross_check(rec, RT, d=1, eps=EPS)
        assert fc["flip_found"] is False, fc


def test_falsification_confirms_C_joint_flip_exists():
    # For a C point the analytic oracle is the labeler; falsification may *confirm* a joint flip
    # exists (it can find one), but it is never used to assign the category.
    rec = _fin("credit_check", 0.45)
    assert verify_interaction_type(rec, RT, d=1, eps=EPS)["category"] == "C_joint_gap"
    fc = falsification_cross_check(rec, RT, d=1, eps=EPS)
    assert fc["flip_found"] is True, "a joint flip should be findable for a C point"


def _run() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"[PASS] {t.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"[FAIL] {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"[ERROR] {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_run())
