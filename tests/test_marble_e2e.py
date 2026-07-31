#!/usr/bin/env python3
"""
test_marble_e2e.py — B2-Marble e2e. On the REAL Marble AML engine, the deployed decision path commits
real (persisted) unsafe approve decisions on Category-C witnesses; the certified joint gate drives them
to 0 while staying non-vacuous on R. Pure gate logic runs always; the engine arms need Marble live.
"""
from __future__ import annotations

import sys
import os
from pathlib import Path

import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
sys.path.insert(0, str(_BB / "experiments"))
sys.path.insert(0, str(_BB / "realdata"))

import marble_e2e as e2e  # noqa: E402

_MARBLE_DIR = Path(os.environ.get("MARBLE_DIR", "external/marble_src"))


def test_gate_blocks_joint_gap_allows_robust():
    # pure gate logic (no engine): a C-witness (safe at loose, joint-unsafe at strict+ε) is blocked;
    # a robustly-safe low risk is allowed.
    c_risk = e2e.mc.THETA - 0.05          # ~0.439: risk+0.10 >= theta_strict(0.4888) -> strict branch fails
    assert e2e.certified_gate_allows("loose", c_risk)[0] is False
    assert e2e.certified_gate_allows("loose", 0.10)[0] is True    # robustly safe


def _marble_ready():
    try:
        import urllib.request
        urllib.request.urlopen(f"{e2e.API}/liveness", timeout=5).read()
    except Exception:
        return False
    return (_MARBLE_DIR / ".scenario_id").exists() and (_MARBLE_DIR / ".api_key").exists()


_engine = pytest.mark.skipif(not _marble_ready(),
                             reason="Marble engine not live / scenario+key missing (external infra)")


@pytest.fixture(scope="module")
def arms():
    sid = (_MARBLE_DIR / ".scenario_id").read_text().strip()
    key = (_MARBLE_DIR / ".api_key").read_text().strip()
    return e2e.run(sid, key, n_c=40, n_r=40)


@_engine
def test_engine_only_commits_persisted_unsafe_approvals(arms):
    eo = arms["engine_only"]
    assert eo["P_unsafe_side_effect"] >= 0.9        # deployed path approves the C-witnesses
    assert eo["marble_persists_decisions"] is True  # real, inspectable side effect on the engine


@_engine
def test_certified_gate_zero_and_oracle_reviews(arms):
    assert arms["certified_gate"]["committed_unsafe_approvals"] == 0     # sound
    orc = arms["oracle_true_worstcase"]
    assert orc["engine_reviews"] == orc["checked"]  # Marble itself reviews the worst case = ground truth


@_engine
def test_nonvacuous_on_R(arms):
    nv = arms["nonvacuity_R"]
    assert nv["gate_allowed"] > 0 and nv["engine_approved"] > 0          # safe txns still flow to Marble
