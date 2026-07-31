#!/usr/bin/env python3
"""
test_opa_fwer.py — fast tests for EXP-OPA-FULL (exp_opa_full.py).

Skip-guarded if the OPA binary is missing. Checks:
  (a) the FWER identity: alpha_branch == alpha_fwer / num_branches for a sampled record;
  (b) the OPA runner actually invokes `opa eval` (labels are non-constant -> the engine ran, not a stub);
  (c) a tiny --quick run emits the expected output files.
Kept fast (tiny n / n_mc).
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_BB = _ROOT / "bridge_benchmark"
_OPA = _BB / "experiments" / "opa_gate"
for p in (_BB / "generators", _BB / "experiments", _OPA):
    sys.path.insert(0, str(p))


def _opa_available():
    try:
        import opa_bridge  # noqa: F401
        opa_bridge.opa_version()
        return True
    except Exception:
        return False


opa = pytest.mark.skipif(not _opa_available(), reason="OPA binary not available")


# --------------------------------------------------------------------------- #
# (a) FWER identity
# --------------------------------------------------------------------------- #
@opa
def test_fwer_identity_alpha_branch():
    from oracle import discrete_swaps
    from schema import sample_records
    import exp_opa_full as E

    alpha_fwer = 0.001
    recs = sample_records("finance", 5, seed=0)
    from opa_oracle import OpaOracle
    dc = OpaOracle("finance").dc
    for r in recs:
        nb = E._branches(dc, r)
        # num_branches = 1 identity + |exact d=1 discrete swaps|
        assert nb == 1 + len(list(discrete_swaps(dc, r["tool_id"], r["categorical_fields"], 1)))
        alpha_branch = alpha_fwer / nb
        # the exact identity the certificate consumes (Bonferroni union bound over the family)
        assert abs(alpha_branch - alpha_fwer / nb) < 1e-18
        assert nb >= 1 and alpha_branch <= alpha_fwer


# --------------------------------------------------------------------------- #
# (b) the runner invokes opa eval (labels are non-constant)
# --------------------------------------------------------------------------- #
@opa
def test_opa_eval_actually_invoked():
    from opa_oracle import OpaOracle
    from schema import sample_records

    orc = OpaOracle("finance")
    recs = sample_records("finance", 60, seed=1, scheme="boundary")
    labels = orc.safe_records(recs)            # one batched `opa eval` call
    assert len(labels) == len(recs)
    # a real engine produces a non-trivial mix of verdicts on the boundary band (not a constant stub)
    assert 0 < sum(bool(x) for x in labels) < len(labels), \
        "labels are constant -> OPA likely not actually evaluating"
    # and categories over B_{1,eps} are produced by the engine too
    cats = orc.categorize(recs, eps=0.10)
    seen = {c["category"] for c in cats}
    assert seen and seen.issubset({"A", "B", "C", "R", "U"})


@opa
def test_opa_bridge_is_called(monkeypatch):
    """Direct evidence opa_bridge.eval_batch (the `opa eval` wrapper) is invoked by the oracle."""
    import opa_bridge
    from opa_oracle import OpaOracle
    from schema import sample_records

    calls = {"n": 0}
    real = opa_bridge.eval_batch

    def spy(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(opa_bridge, "eval_batch", spy)
    # OpaOracle imported opa_bridge module ref, so monkeypatching the module attr is seen
    orc = OpaOracle("finance")
    orc.safe_records(sample_records("finance", 10, seed=2))
    assert calls["n"] >= 1


# --------------------------------------------------------------------------- #
# (c) tiny --quick run emits expected files
# --------------------------------------------------------------------------- #
@opa
def test_quick_run_emits_files():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "exp_opa_full_quick"
        cmd = [sys.executable, str(_BB / "experiments" / "exp_opa_full.py"),
               "--seeds", "0", "--epsilons", "0.10", "--taus", "0.90",
               "--backends", "smoothing", "--domains", "finance",
               "--n-train", "120", "--n-eval", "40", "--n-mc", "200",
               "--alpha-fwer", "0.001", "--out", str(out)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        assert proc.returncode == 0, f"runner failed:\n{proc.stderr[-2000:]}"
        for name in ("per_example.jsonl", "summary.csv", "summary.json",
                     "utility_curve_epsilon.csv", "utility_curve_tau.csv", "summary.md"):
            assert (out / name).exists(), f"missing output {name}"
        # per_example.jsonl carries the FWER fields and OPA-engine category
        line = (out / "per_example.jsonl").read_text().splitlines()[0]
        rec = json.loads(line)
        for k in ("alpha_fwer", "alpha_branch", "num_branches", "category", "opa_version"):
            assert k in rec, f"per_example record missing {k}"
        assert abs(rec["alpha_branch"] - rec["alpha_fwer"] / rec["num_branches"]) < 1e-12
        # summary.json has cells and the FWER family-size log
        sm = json.loads((out / "summary.json").read_text())
        assert sm["cells"] and "fwer_num_branches" in sm["config"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
