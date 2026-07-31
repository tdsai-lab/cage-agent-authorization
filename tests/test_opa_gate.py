#!/usr/bin/env python3
"""
test_opa_gate.py — NEW_EXP_OPA_GATE. Verifies the OPA/Rego policy-as-code oracle: batched verdicts,
the A/B/C/R/U taxonomy computed through OPA, and that C-witnesses arise. Skips if the OPA binary is
absent (download: bin/opa from openpolicyagent.org), so the suite stays green without OPA installed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
_OPA = _BB / "experiments" / "opa_gate"
for p in (_OPA, _BB / "generators"):
    sys.path.insert(0, str(p))

opa_bridge = pytest.importorskip("opa_bridge")
try:
    opa_bridge.opa_path()
except FileNotFoundError:
    pytest.skip("OPA binary not available", allow_module_level=True)

from opa_oracle import OpaOracle  # noqa: E402
from schema import sample_records  # noqa: E402


def test_opa_bridge_known_verdicts():
    rego = _OPA / "policies" / "authored" / "finance.rego"
    cases = [
        {"tool": "t_credit", "action": "approve_transaction", "x1": {"jurisdiction": "domestic"},
         "x2": {"risk_score": 0.30}},                                  # < 0.62+0.04 -> safe
        {"tool": "t_credit", "action": "approve_transaction", "x1": {"jurisdiction": "sanctioned"},
         "x2": {"risk_score": 0.60}},                                  # >= 0.62-0.10=0.52 -> unsafe
        {"tool": "t_credit", "action": "manual_review", "x1": {"jurisdiction": "sanctioned"},
         "x2": {"risk_score": 0.99}},                                  # non-privileged -> safe
    ]
    assert opa_bridge.eval_batch(rego, "opa_gate.finance", cases) == [True, False, True]


def test_opa_category_taxonomy_and_c_witnesses():
    orc = OpaOracle("finance")
    recs = sample_records("finance", 300, seed=0)
    cats = orc.categorize(recs, eps=0.10)
    # OPA Safe(z,a) for the clean point must agree with the category's clean_safe flag
    clean = orc.safe_records(recs)
    assert clean == [c["clean_safe"] for c in cats]
    # C-witnesses arise at nontrivial prevalence
    n_c = sum(c["category"] == "C" for c in cats)
    assert n_c > 0 and n_c / len(cats) > 0.02
    for c in cats:
        cat = c["category"]
        if cat == "U":
            assert not c["clean_safe"]
        else:
            assert c["clean_safe"]
        if cat == "C":                      # joint-gap: flips jointly, neither margin alone
            assert c["joint_flip"] and not c["disc_flip"] and not c["cont_flip"]
        if cat == "R":                      # robust: nothing in B_{1,eps} flips
            assert not c["truly_unsafe_reachable"]
        if cat == "A":
            assert c["disc_flip"]
        if cat == "B":
            assert c["cont_flip"] and not c["disc_flip"]


if __name__ == "__main__":
    test_opa_bridge_known_verdicts()
    test_opa_category_taxonomy_and_c_witnesses()
    print("PASS test_opa_gate (2)")
