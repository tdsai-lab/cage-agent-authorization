#!/usr/bin/env python3
"""
test_fault_budget.py — EXP-FAULT invariants (bridge_benchmark/experiments/exp_fault_injection.py).

Fast: tiny n, one seed, a synthetic oracle-aware substrate (financial_compliance) so no /nas data is
needed. The IEEE-CIS-dependent path is skip-guarded.
"""
import sys
from pathlib import Path

import numpy as np
import pytest

_root = Path(__file__).resolve().parents[1] / "bridge_benchmark"
for p in ("generators", "experiments", "realdata", "agents"):
    sys.path.insert(0, str(_root / p))

import fault_injection as fi  # noqa: E402
import exp_fault_injection as ex  # noqa: E402


@pytest.fixture(scope="module")
def fin_sub():
    return fi.load_realistic("financial_compliance", n_pool=800, seed=0)


@pytest.fixture(scope="module")
def fin_adapter():
    return ex.build_adapter("financial_compliance")


EPS_BUDGET = 0.10
EPS_THRESH = [0.05, 0.10]


def _run(sub, fault, adapter, n=60):
    return ex.run_one(sub, fault, adapter, n=n, seed=0, eps_budget=EPS_BUDGET,
                      eps_thresholds=EPS_THRESH)


# (a) every single discrete fault yields d_obs==1 and epsilon_obs==0
def test_discrete_faults_d1_eps0(fin_sub, fin_adapter):
    for fault in ex.DISCRETE_FAULTS:
        recs, row = _run(fin_sub, fault, fin_adapter)
        assert recs, f"{fault}: no records"
        assert all(r["d_obs"] == 1 for r in recs), f"{fault}: some d_obs != 1"
        assert all(r["epsilon_obs"] == 0.0 for r in recs), f"{fault}: some eps != 0"
        assert all(r["in_budget"] for r in recs), f"{fault}: discrete fault not in budget"
        assert row["pr_d1"] == 1.0 and row["eps_max"] == 0.0


# (b) single continuous faults yield d_obs==0
def test_continuous_faults_d0(fin_sub, fin_adapter):
    for fault in ex.CONTINUOUS_FAULTS:
        recs, row = _run(fin_sub, fault, fin_adapter)
        assert recs, f"{fault}: no records"
        assert all(r["d_obs"] == 0 for r in recs), f"{fault}: some d_obs != 0"
        assert row["pr_d0"] == 1.0


# (c) Pr[d>=2]==0 for ALL single faults
def test_no_single_fault_reaches_d_ge2(fin_sub, fin_adapter):
    for fault in ex.DISCRETE_FAULTS + ex.CONTINUOUS_FAULTS:
        recs, row = _run(fin_sub, fault, fin_adapter)
        assert row["pr_d_ge2"] == 0.0, f"{fault}: Pr[d>=2] != 0"
        assert max(r["d_obs"] for r in recs) <= 1


# (d) per_fault records carry the required fields
REQUIRED = {"seed", "substrate", "fault_type", "s_before", "s_after", "x_before", "x_after",
            "d_obs", "epsilon_obs", "in_budget", "safe_before", "safe_after"}


def test_per_fault_record_schema(fin_sub, fin_adapter):
    recs, _ = _run(fin_sub, "numeric_jitter", fin_adapter)
    assert recs
    for r in recs:
        assert REQUIRED.issubset(r.keys())
        assert isinstance(r["x_before"], list) and isinstance(r["x_after"], list)
        assert len(r["x_before"]) == len(r["x_after"]) == len(fin_sub.x2_fields)
        assert isinstance(r["d_obs"], int) and isinstance(r["epsilon_obs"], float)
        assert isinstance(r["in_budget"], bool)
        # oracle-aware substrate -> safe labels are real booleans, not null
        assert isinstance(r["safe_before"], bool) and isinstance(r["safe_after"], bool)


def test_no_oracle_substrate_yields_null_labels(fin_sub):
    # exercise the adapter=None path: safe_before/after must be null
    recs, row = ex.run_one(fin_sub, "numeric_jitter", None, n=20, seed=0,
                           eps_budget=EPS_BUDGET, eps_thresholds=EPS_THRESH)
    assert recs
    assert all(r["safe_before"] is None and r["safe_after"] is None for r in recs)
    assert row["n_labelled"] == 0 and row["pr_safe_change"] is None


def test_in_budget_flag_matches_definition(fin_sub, fin_adapter):
    recs, _ = _run(fin_sub, "cache_key_collision", fin_adapter)
    for r in recs:
        assert r["in_budget"] == (r["d_obs"] <= 1 and r["epsilon_obs"] <= EPS_BUDGET)


@pytest.mark.skipif(not fi.IEEE_PATH.exists(), reason="IEEE-CIS balanced set not present")
def test_ieee_cis_discrete_d1():
    sub = fi.load_ieee_cis()
    adapter = ex.build_adapter("ieee_cis")
    assert adapter is not None
    recs, row = ex.run_one(sub, "wrong_provenance_binding", adapter, n=80, seed=0,
                           eps_budget=EPS_BUDGET, eps_thresholds=EPS_THRESH)
    assert recs and row["pr_d1"] == 1.0 and row["pr_d_ge2"] == 0.0
    # provenance swap (loose<->strict) flips the constructed authorization policy for some records
    assert isinstance(recs[0]["safe_before"], bool)


def test_aggregate_multiseed_shapes(fin_sub, fin_adapter):
    rows = []
    for seed in (0, 1):
        _, row = ex.run_one(fin_sub, "numeric_jitter", fin_adapter, n=40, seed=seed,
                            eps_budget=EPS_BUDGET, eps_thresholds=EPS_THRESH)
        rows.append(row)
    agg, metrics = ex.aggregate(rows, EPS_THRESH)
    assert len(agg) == 1
    a = agg[0]
    assert a["n_seeds"] == 2
    assert a["eps_p90_mean"] is not None and a["eps_p90_std"] is not None
    assert "frac_in_B1_0.1_mean" in a
