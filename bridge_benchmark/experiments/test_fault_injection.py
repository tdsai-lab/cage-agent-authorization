#!/usr/bin/env python3
"""
test_fault_injection.py — invariants for the PLAN.md #16 fault-injection budget measurement.

Asserts the load-bearing structural facts (not exact quantiles):
  * each atomic provenance/policy/TOCTOU fault changes EXACTLY one discrete atom (d=1, eps=0)
    -> d=1 is the empirically natural single-fault granularity;
  * NO single injected fault produces d>=2 (d>=2 only by compounding) -> the discrete budget is 1;
  * a faithful same-surface stale read drifts LESS than a wrong-entity key collision;
  * an in-budget continuous fault (jitter) lands inside B_{1,eps} for almost all samples, while the
    schema column-transpose is a measured OUT-of-budget tail (the documented scope cliff);
  * the measurement is deterministic under a fixed seed.
"""
import sys
from pathlib import Path

import pytest

_root = Path(__file__).resolve().parents[1]
for p in ("generators", "experiments", "realdata", "agents"):
    sys.path.insert(0, str(_root / p))

import fault_injection as fi  # noqa: E402


@pytest.fixture(scope="module")
def sub():
    return fi.load_realistic("financial_compliance", n_pool=4000, seed=0)


@pytest.fixture(scope="module")
def rows(sub):
    return {f: fi.run_fault(sub, f, 800, seed=0) for f in fi.INJECTORS}


def test_discrete_faults_are_exactly_d1_eps0(rows):
    for f in ("wrong_provenance_binding", "wrong_policy_pack", "toctou_env_label"):
        r = rows[f]
        assert r is not None and r["n"] > 0
        assert r["pr_d1"] == 1.0, f"{f} must change exactly one discrete atom"
        assert r["pr_d_ge2"] == 0.0 and r["max_d"] == 1
        assert r["eps_p99"] == 0.0, f"{f} must not move the numeric channel"


def test_no_single_fault_exceeds_d1(rows):
    for f, r in rows.items():
        if r is None:
            continue
        assert r["pr_d_ge2"] == 0.0, f"single fault {f} produced d>=2 (budget d=1 violated)"
        assert r["max_d"] <= 1


def test_continuous_faults_have_d0(rows):
    for f in ("stale_cache", "numeric_jitter", "normalization_skew", "schema_skew",
              "cache_key_collision"):
        r = rows[f]
        if r is None:
            continue
        assert r["pr_d0"] == 1.0, f"{f} should not touch the discrete channel"


def test_stale_read_drifts_less_than_key_collision(rows):
    stale, collision = rows["stale_cache"], rows["cache_key_collision"]
    assert stale is not None and collision is not None
    assert stale["eps_p50"] < collision["eps_p50"], \
        "a same-surface stale read must drift less than a wrong-entity collision"


def test_jitter_in_budget_schema_skew_is_scope_cliff(rows):
    assert rows["numeric_jitter"]["frac_in_B_1_budget"] > 0.9      # common fault sits inside budget
    assert rows["schema_skew"]["frac_in_B_1_budget"] < 0.5         # transposition is the measured tail


def test_deterministic(sub):
    a = fi.run_fault(sub, "numeric_jitter", 500, seed=1)
    b = fi.run_fault(sub, "numeric_jitter", 500, seed=1)
    assert a == b


@pytest.mark.skipif(not fi.IEEE_PATH.exists(), reason="IEEE-CIS data not present")
def test_ieee_real_data_discrete_budget():
    s = fi.load_ieee_cis(n=3000)
    r = fi.run_fault(s, "wrong_provenance_binding", 1000, seed=0)
    assert r["pr_d1"] == 1.0 and r["eps_p99"] == 0.0  # real provenance swap = d=1, eps=0
    pooled = fi.run_pooled(s, 1500, seed=0)
    assert pooled["pr_d_ge2"] == 0.0                  # pooled real faults: still no d>=2
