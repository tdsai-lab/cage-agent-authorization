"""Tests for NEW_EXPS Tier-1 #2: discrete escape rate (experiments/discrete_escape.py).

Skip-guarded (needs numpy/scipy + the synthetic realistic substrates from fault_injection). Fast:
uses small n and n_points, and only the synthetic financial_compliance substrate (no IEEE-CIS raw
dependency).
"""
import sys
from pathlib import Path

import pytest

_root = Path(__file__).resolve().parents[1] / "bridge_benchmark"
for p in ("generators", "experiments", "realdata", "agents", "cert"):
    sys.path.insert(0, str(_root / p))

pytest.importorskip("numpy")
pytest.importorskip("scipy")

try:
    import discrete_escape as de
    import fault_injection as fi
    _SUB = fi.load_realistic("financial_compliance", seed=0)
except Exception as e:  # pragma: no cover
    pytest.skip(f"discrete_escape substrate unavailable: {e}", allow_module_level=True)


def test_provenance_policy_toctou_escape_near_zero():
    """(a) Held-out provenance/policy/TOCTOU faults land back inside the shared frozen N_d -> escape 0
    (their edges are redundantly declared by the shared registered vocabulary)."""
    for mech in de.DISCRETE_MECHS:
        rows = [de.leave_one_out_escape(_SUB, mech, n=400, seed=s, eps=0.10) for s in (0, 1)]
        rates = [r["escape_rate"] for r in rows if r is not None]
        assert rates, f"{mech} produced no applicable faults"
        assert max(rates) <= 0.02, f"{mech} escaped N_d materially: {rates} (KILL threshold)"


def test_x2_tail_faults_escape_nonzero():
    """The out-of-budget x2 faults (schema transposition, wrong-entity collision) leave N_d x B_eps
    with clearly nonzero rate — the documented scope cliff the validation layer is meant to catch."""
    for mech in de.X2_MECHS:
        r = de.leave_one_out_escape(_SUB, mech, n=400, seed=0, eps=0.10)
        assert r is not None and r["escape_rate"] > 0.1, f"{mech} escape unexpectedly low: {r}"


def test_over_declaration_monotone_non_increasing():
    """(b) Adding inert branches to N_d never RAISES certified R_allow (larger |N_d| -> more min-over-
    states branches + smaller family-wise alpha_branch -> lower R_allow)."""
    rows = de.over_declaration_curve(seeds=[0, 1, 2], Ks=(0, 1, 2, 4, 8), n_mc=1500,
                                     sigma=0.10, eps=0.10, tau=0.90, n_points=300)
    means = [r["R_allow_mean"] for r in rows]
    stds = [r["R_allow_std"] for r in rows]
    branches = [r["num_branches"] for r in rows]
    assert branches == sorted(branches) and branches[0] == 3
    # monotone non-increasing in EXPECTATION; allow a small MC tolerance (2 x pooled std) between
    # adjacent points since R_allow is a Monte-Carlo estimate of the true (monotone) quantity.
    for i, (a, b) in enumerate(zip(means, means[1:])):
        tol = 2.0 * max(stds[i], stds[i + 1]) + 5e-3
        assert b <= a + tol, f"R_allow rose beyond MC noise with more inert branches: {means}"
    # and it must actually move a lot overall (not a flat degenerate curve)
    assert means[0] > means[-1] + 5e-2


def test_smoke_emits_files(tmp_path):
    """(c) A small end-to-end run emits the four expected output files with content."""
    seeds = [0]
    subs = [_SUB]
    esc_rows = []
    for sub in subs:
        esc_rows.extend(de.aggregate_escape(sub, n=200, seeds=seeds, eps=0.10))
    over_rows = de.over_declaration_curve(seeds=seeds, n_mc=1000, n_points=60)
    de.write_outputs(tmp_path, esc_rows, over_rows, notes=["test"],
                     params={"eps": 0.10, "n": 200, "seeds": seeds, "sigma": 0.10,
                             "tau": 0.90, "alpha_fwer": 1e-3})
    for name in ("escape_by_mechanism.csv", "over_declaration_curve.csv",
                 "summary.json", "summary.md"):
        f = tmp_path / name
        assert f.exists() and f.stat().st_size > 0, f"missing/empty {name}"
    assert "K,num_branches" in (tmp_path / "over_declaration_curve.csv").read_text()
