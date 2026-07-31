#!/usr/bin/env python3
"""
test_fragment_differential.py — frozen-seed pytest for EXP-CX3 (CAGE-Exact fragment). Asserts the
`cert/fragment.py` implementation of Definition 1 / Proposition 7 agrees with the independent oracles on a
small frozen subset (0 mismatches) and refuses every out-of-fragment policy (`unsupported`). The OPA-engine
leg is skipped if the `opa` binary is unavailable; the numpy/grid/closed-form legs always run.
"""
import random
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent / "cert"))
sys.path.insert(0, str(_HERE / "opa_gate"))

import cx3_differential as C   # noqa: E402
import fragment as F           # noqa: E402

EPS = 0.10


def test_parse_and_robust_basic():
    spec = {"numeric_fields": ["x0", "x1"], "cat_field": "s", "cat_values": ["trusted", "loose"],
            "action": "approve",
            "branches": {"trusted": [{"w": [1.0, 0.0], "b": 0.5}],
                         "loose": [{"w": [1.0, 0.0], "b": 0.2}]}}
    pol = F.parse_policy(spec)
    assert F.point_safe(pol, "trusted", {"x0": 0.3, "x1": 0.0}) is True
    # d=1 swaps to loose (b=0.2): 0.3 > 0.2 -> not robust even at eps=0
    assert F.robust_eval(pol, "trusted", {"x0": 0.3, "x1": 0.0}, "approve", eps=0.0, d=1)["allow"] is False
    # a comfortably-interior point is robust
    assert F.robust_eval(pol, "trusted", {"x0": 0.0, "x1": 0.0}, "approve", eps=0.05, d=1)["allow"] is True


def test_support_function_tie_is_safe():
    # exact equality w.x + eps||w|| == b must be SAFE (<= convention, Prop 7)
    spec = {"numeric_fields": ["x0"], "cat_field": "s", "cat_values": ["s0"], "action": "a",
            "branches": {"s0": [{"w": [1.0], "b": 0.1 + EPS}]}}   # w.x=0.1, +eps*1=+0.1 -> ==b
    pol = F.parse_policy(spec)
    r = F.robust_eval(pol, "s0", {"x0": 0.1}, "a", eps=EPS, d=1)
    assert r["allow"] is True and abs(r["worst_slack"]) < 1e-9


def test_out_of_fragment_all_refused():
    rng = random.Random(0)
    kinds = set()
    for pid in range(20):
        spec = C.gen_out_of_fragment(pid, rng)
        assert F.in_fragment(spec) is False, f"accepted out-of-fragment {spec['_kind']}"
        kinds.add(spec["_kind"])
    assert kinds == set(C.OUT_OF_FRAGMENT_KINDS)   # every disqualifying construct exercised


def test_differential_zero_mismatch_frozen_subset():
    """5 frozen-seed fragment policies × 120 returns: CAGE-Exact must agree with the independent oracles
    (vectorized ball-sampling all-k + exhaustive dense-grid k<=2) and the closed-form consistency check."""
    import numpy as np
    rng = random.Random(1234)
    npr = np.random.default_rng(1234)
    total_mism = total_hard = 0
    for pid in range(5):
        spec = C.gen_fragment_policy(pid, rng)
        pol = F.parse_policy(spec)
        warr = C._branch_arrays(pol)
        recs = C.gen_returns(spec, 120, EPS, rng)
        cage = [C.cage_allow(pol, r, EPS, 1) for r in recs]
        solver = [C.solver_oracle_robust(pol, r, EPS, 1) for r in recs]
        sampling = [C.sampling_oracle_robust(pol, r, EPS, 1, 200, warr, npr) for r in recs]
        grid = [C.grid_oracle_robust(pol, r, EPS, 1, 21) for r in recs] if pol.k <= 2 else None
        # solver = same closed-form -> full consistency; sampling & grid are soundness-only (finite points
        # under-approximate unsafety), so only HARD failures (cage-ALLOW with an unsafe probe) gate.
        total_mism += sum(1 for a, b in zip(cage, solver) if a != b)
        total_hard += sum(1 for a, b in zip(cage, sampling) if a and not b)
        if grid is not None:
            total_hard += sum(1 for a, b in zip(cage, grid) if a and not b)
    assert total_hard == 0, f"{total_hard} hard failures (CAGE allowed an unsafe point)"
    assert total_mism == 0, f"{total_mism} solver-consistency mismatches on the frozen subset"


def test_opa_engine_agrees_if_available():
    """OPA-engine leg (skipped without the binary): compiled Rego point-safety must match Python."""
    try:
        import opa_bridge as OB
        OB.opa_version()
    except Exception as e:
        pytest.skip(f"opa binary unavailable: {e}")
    import tempfile, os
    rng = random.Random(7)
    spec = C.gen_fragment_policy(0, rng)
    pol = F.parse_policy(spec)
    fp = tempfile.NamedTemporaryFile("w", suffix=".rego", delete=False)
    fp.write(F.compile_to_rego(pol)); fp.close()
    recs = C.gen_returns(spec, 60, EPS, rng)
    opa = C.opa_oracle_robust(pol, recs, fp.name, "cage.fragment", EPS, 1, 8, 4, rng)
    cage = [C.cage_allow(pol, r, EPS, 1) for r in recs]
    os.unlink(fp.name)
    assert sum(1 for a, b in zip(cage, opa) if a and not b) == 0   # no OPA-found unsafe under CAGE-allow


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
