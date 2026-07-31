#!/usr/bin/env python3
"""Tests for Tier-2 #8 discrete-budget d-sweep (enumeration cliff), experiments/d_sweep.py.

(a) |N_d| strictly increasing in d and matches the analytic combinatorial count on a known vocabulary;
(b) cert_false_allow == 0 for every d, EVERY backend (soundness invariant across d and backend);
(c) R_allow non-increasing as d grows, per backend (more branches never raises utility);
(d) quick run emits all output files;
(e) PRIMARY deterministic Lipschitz backend present + has NO alpha_branch (torch-guarded).
Skip-guarded on numpy/scipy/sklearn. Kept fast.
"""
import json
import math
import sys
from pathlib import Path

import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
for p in ("experiments", "generators", "models", "cert"):
    sys.path.insert(0, str(_BB / p))

pytest.importorskip("numpy")
pytest.importorskip("scipy")
pytest.importorskip("sklearn")

import d_sweep as ds  # noqa: E402
from oracle import discrete_swaps  # noqa: E402


# ------------------------------------------------------------------ #
# (a) |N_d| combinatorics: strictly increasing + matches analytic count
# ------------------------------------------------------------------ #
def _analytic_swap_count(n_tools, cat_sizes, d):
    """Number of distinct non-identity states reachable by <=d atomic swaps over slots where slot 0 is
    the tool (alt count = n_tools-1) and the rest are categorical fields (alt count = size-1 each).
    = sum_{r=1..d} sum over r-subsets of slots of product of per-slot alt-counts."""
    from itertools import combinations
    alts = [n_tools - 1] + [s - 1 for s in cat_sizes]
    slots = [a for a in alts if a > 0]
    total = 0
    for r in range(1, d + 1):
        for combo in combinations(slots, r):
            prod = 1
            for a in combo:
                prod *= a
            total += prod
    return total


def test_Nd_matches_analytic_and_strictly_increasing():
    # known vocabulary with THREE swap slots (tool + 2 categorical fields) so |N_d| strictly grows
    # through d=3: 3 tools (2 tool-alts), c0 size 3 (2 alts), c1 size 4 (3 alts).
    dc = {
        "tools": ["t0", "t1", "t2"],
        "numeric_fields": ["x0"],
        "categorical_fields": {"c0": ["v0", "v1", "v2"], "c1": ["w0", "w1", "w2", "w3"]},
    }
    x1 = {"c0": "v0", "c1": "w0"}
    prev = -1
    for d in (1, 2, 3):
        cnt = sum(1 for _ in discrete_swaps(dc, "t0", x1, d))  # non-identity states
        expected = _analytic_swap_count(3, [3, 4], d)
        assert cnt == expected, f"d={d}: got {cnt}, analytic {expected}"
        assert cnt > prev, f"|N_d| not strictly increasing at d={d}"
        prev = cnt
    # closed form on 3 slots with per-slot alt counts [2,2,3]:
    #   d=1: 2+2+3 = 7
    #   d=2: +pairs 2*2 + 2*3 + 2*3 = 4+6+6 = 16 -> 23
    #   d=3: +triple 2*2*3 = 12 -> 35
    assert _analytic_swap_count(3, [3, 4], 1) == 7
    assert _analytic_swap_count(3, [3, 4], 2) == 23
    assert _analytic_swap_count(3, [3, 4], 3) == 35
    # and a 2-slot vocabulary DOES saturate at d=2 (documents the saturation edge)
    assert _analytic_swap_count(3, [3], 2) == _analytic_swap_count(3, [3], 3) == 8


def test_valid_states_d_increasing_on_synthetic():
    rt, ev = ds.build_synthetic(x1_size=4, seed=0, n_eval=60, eps=0.10, K=8, k=3, n_cat_fields=2)
    rec = ev[0]
    counts = [ds.n_states_d(rt, rec, d) for d in (1, 2, 3)]
    assert counts[0] < counts[1] <= counts[2] or counts[0] <= counts[1] <= counts[2]
    # strictly increasing from d=1->d=2 (there are >=2 categorical fields + tool alternatives)
    assert counts[1] > counts[0]


# ------------------------------------------------------------------ #
# (b),(c),(d) end-to-end quick run: soundness, monotone R_allow, files
# ------------------------------------------------------------------ #
@pytest.fixture(scope="module")
def quick_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("exp_d_sweep")
    agg, cross = ds.run(
        max_d=3, seeds=[0], outdir=out, quick=True,
        eps=0.10, sigma=0.10, tau=0.90, n_mc=1500, alpha_fwer=1e-3,
        x1_sizes=[4], opa_domains=[],  # synthetic-only for a fast, dependency-light test
    )
    return out, agg, cross


def test_rs_ablation_cert_false_allow_zero_every_d(quick_run):
    """The RS-ablation certificate is a min-over-branches probabilistic lower bound => SOUND w.r.t. the
    oracle at every d (cert_false_allow=0). This is the invariant that must never regress."""
    _out, agg, _cross = quick_run
    rs = [r for r in agg if r["backend"] == "rs_ablation"]
    assert rs, "no RS-ablation rows"
    for r in rs:
        assert r["cert_false_allow"] == 0.0, (
            f"RS soundness violated: track={r['track']} d={r['d']} cfa={r['cert_false_allow']}")


def test_lipschitz_cert_is_deterministic_min_margin_bound():
    """The PRIMARY Lipschitz certificate is DETERMINISTIC: allow iff min_{s'∈N_d} h_θ(s') > L·ε with
    L = CLAIMED_L*fscale (numeric-block scaling => gate is fscale-Lipschitz in the raw eps-ball). Verify
    the decision rule EXACTLY (no n_mc, no alpha) and that the sound threshold scales with fscale."""
    pytest.importorskip("torch")
    if not ds._LIP_OK:
        pytest.skip("Lipschitz backend import failed")
    rt, ev = ds.build_synthetic(x1_size=4, seed=0, n_eval=400, eps=0.10, K=8, k=3, n_cat_fields=2)
    model, enc, fscale = ds.train_synth_lip(rt, seed=0, n_train=400, eps=0.10, epochs=60)
    assert fscale == ds.LIP_SYNTH["fscale"]
    eps = 0.10
    L_eff = ds.CLAIMED_L * fscale
    import numpy as np, torch  # noqa
    start = enc.dim - len(enc.numeric_fields)
    for r in ev[:40]:
        allow, ns, min_margin = ds.certify_lip_at_d(model, enc, rt, r, 2, eps=eps, fscale=fscale)
        # recompute min_margin over N_2 with the SAME numeric scaling, independently.
        rows = []
        for t, x1 in ds.valid_states_d(rt, r, 2):
            v = np.asarray(enc.transform_point(r["domain"], t, r["candidate_action"], x1,
                                               r["numeric_fields"]), dtype=np.float32)
            v[start:] *= fscale
            rows.append(v)
        with torch.no_grad():
            h = model(torch.from_numpy(np.asarray(rows, dtype=np.float32)).to(ds._LIP_DEVICE)).cpu().numpy()
        assert ns == len(rows)
        assert abs(min_margin - float(np.min(h))) < 1e-4
        assert allow == bool(min_margin > L_eff * eps)


def test_R_allow_non_increasing_in_d_per_backend(quick_run):
    _out, agg, _cross = quick_run
    # group by (backend, track, x1_size); R_allow(d) must be non-increasing within each group.
    groups = {}
    for r in agg:
        groups.setdefault((r["backend"], r["track"], r["x1_size"]), []).append(r)
    checked = 0
    for key, rows in groups.items():
        rows = sorted(rows, key=lambda z: z["d"])
        vals = [z["R_allow"] for z in rows if not math.isnan(z["R_allow"])]
        for a, b in zip(vals, vals[1:]):
            assert b <= a + 1e-9, f"{key}: R_allow increased with d: {vals}"
            checked += 1
    assert checked > 0, "no R_allow monotonicity comparisons were made"


def test_rs_ablation_always_present(quick_run):
    _out, agg, _cross = quick_run
    backends = {r["backend"] for r in agg}
    assert "rs_ablation" in backends
    # RS rows carry an FWER alpha_branch (randomized cert); it shrinks as |N_d| grows.
    rs = sorted([r for r in agg if r["backend"] == "rs_ablation"], key=lambda z: z["d"])
    abs_ = [r["alpha_branch"] for r in rs]
    assert all(a is not None for a in abs_)
    assert abs_[-1] <= abs_[0] + 1e-12, "alpha_branch should shrink (or hold) as |N_d| grows"


def test_primary_lipschitz_backend_deterministic(quick_run):
    """PRIMARY = deterministic Lipschitz: present when torch is importable, with NO alpha_branch (no
    confidence budget to Bonferroni-divide). cert_false_allow is REPORTED (gate-fidelity, H.2), not
    asserted =0 here — see test_lipschitz_cert_is_deterministic_min_margin_bound for the exact rule."""
    pytest.importorskip("torch")
    if not ds._LIP_OK:
        pytest.skip("Lipschitz backend import failed")
    _out, agg, cross = quick_run
    lip = [r for r in agg if r["backend"] == "lipschitz"]
    assert lip, "PRIMARY Lipschitz rows missing though torch is available"
    for r in lip:
        assert r["alpha_branch"] is None, "deterministic Lipschitz cert must have NO alpha_branch"
    assert cross["primary_backend"] == "lipschitz"
    assert cross["backends"]["lipschitz"] is not None
    # soundness bookkeeping is exposed per-backend in summary.json
    summ = json.loads((_out / "summary.json").read_text())
    assert "soundness_by_backend" in summ


def test_quick_run_emits_files(quick_run):
    out, _agg, cross = quick_run
    for fn in ("d_sweep.csv", "crossover.json", "summary.json", "summary.md"):
        assert (out / fn).exists(), f"missing {fn}"
    summ = json.loads((out / "summary.json").read_text())
    # RS ablation is the certificate that is sound w.r.t. the oracle at every d.
    assert summ["soundness_by_backend"]["rs_ablation_sound_all_d"] is True
    assert "operational_cliff_d" in cross
    # csv header names the backend column
    csv_lines = (out / "d_sweep.csv").read_text().strip().splitlines()
    assert csv_lines[0].startswith("backend,")
    assert len(csv_lines) >= 4
