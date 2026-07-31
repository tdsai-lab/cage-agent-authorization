#!/usr/bin/env python3
"""
test_complete_verification.py — T1-1 complete-verification (MILP) backend (Tier-1 item 1).

Skip-guarded on scipy.optimize.milp and (for the OPA-track quick-run test) the OPA binary. Fast:
  (a) the sklearn ReLU-MLP -> PortedMLP forward-pass port matches predict_proba to <= 1e-6;
  (b) on the analytic halfspace domain the MILP verdict == the analytic robust oracle for a batch;
  (c) a --quick run emits the output files and cert_false_allow == 0 for every backend.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_BB = _ROOT / "bridge_benchmark"
for p in ("generators", "models", "cert"):
    sys.path.insert(0, str(_BB / p))
sys.path.insert(0, str(_BB / "experiments"))
sys.path.insert(0, str(_BB / "experiments" / "opa_gate"))

try:
    from scipy.optimize import milp  # noqa: F401
    _MILP = True
except Exception:
    _MILP = False

skip_milp = pytest.mark.skipif(not _MILP, reason="scipy.optimize.milp not available")


def _opa_ok():
    try:
        import opa_bridge
        opa_bridge.opa_version()
        return True
    except Exception:
        return False


@skip_milp
def test_forward_pass_port_matches_sklearn():
    """(a) PortedMLP forward pass matches sklearn MLPClassifier predict_proba to 1e-6."""
    import numpy as np
    from sklearn.neural_network import MLPClassifier
    import complete_verification as CV

    rng = np.random.default_rng(0)
    X = rng.standard_normal((300, 26))
    y = (X[:, 0] - 0.5 * X[:, 3] + 0.2 * X[:, 10] > 0).astype(int)
    est = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=0).fit(X, y)

    class _G:  # minimal gate stub exposing .est
        pass
    g = _G(); g.est = est
    ported, max_diff = CV.port_and_check(g, X[:64], tol=1e-6)
    assert max_diff <= 1e-6
    # spot-check p_safe path too
    p_port = ported.p_safe(X[:64])
    p_ref = est.predict_proba(X[:64])[:, 1]
    assert float(np.max(np.abs(p_port - p_ref))) <= 1e-6


@skip_milp
def test_milp_matches_analytic_robust_oracle():
    """(b) On the analytic halfspace domain, the MILP verdict == analytic robust oracle for a batch."""
    import complete_verification as CV
    agree, n = CV.validate_on_analytic(eps=0.10, n=48, per_dim=6, verbose=False)
    assert n == 48
    assert agree == 1.0, f"MILP != analytic robust oracle (agreement {agree})"


@skip_milp
def test_outer_polytope_is_sound_and_tight():
    """The circumscribing polytope contains the unit ball (sound) and its slack is small for small k."""
    import numpy as np
    import complete_verification as CV
    U = CV.outer_polytope_dirs(3, per_dim=8, seed=0)
    # every unit-ball point satisfies u^T delta <= 1 for all facets (soundness of the outer approx)
    rng = np.random.default_rng(1)
    D = rng.standard_normal((2000, 3)); D /= np.linalg.norm(D, axis=1, keepdims=True)
    assert np.all(D @ U.T <= 1.0 + 1e-9)
    slack = CV.polytope_slack(U)
    assert slack >= 1.0 and slack < 1.6            # tight for k=3


@pytest.mark.skipif(not (_MILP and _opa_ok()), reason="scipy.milp or OPA binary unavailable")
def test_quick_run_emits_outputs_and_sound(tmp_path):
    """(c) A --quick run writes the output files and cert_false_allow == 0 for every backend."""
    out = tmp_path / "cv_out"
    r = subprocess.run(
        [sys.executable, str(_BB / "experiments" / "complete_verification.py"),
         "--quick", "--no-lip", "--domains", "finance", "--n-eval", "40", "--cv-cap", "40",
         "--rs-mc", "1500", "--out", str(out)],
        capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, f"run failed:\nSTDOUT{r.stdout[-2000:]}\nSTDERR{r.stderr[-2000:]}"
    for fn in ("summary.csv", "summary.json", "summary.md", "per_record.jsonl"):
        assert (out / fn).exists(), f"missing {fn}"
    summary = json.loads((out / "summary.json").read_text())
    assert summary["meta"]["validation_agreement"] == 1.0
    assert summary["meta"]["max_port_diff"] <= 1e-6
    backends = {row["backend"]: row for row in summary["summary"]}
    assert "complete_verif" in backends and "randomized_smoothing" in backends
    for row in summary["summary"]:
        assert row["cert_false_allow"] == 0.0, f"{row['backend']} cert_false_allow != 0"
    # CV must be at least as permissive as RS on the robust set (no smoothing/MC tax)
    cv = backends["complete_verif"]["R_allow_mean"]
    rs = backends["randomized_smoothing"]["R_allow_mean"]
    assert cv >= rs - 1e-9, f"R_allow CV ({cv}) < RS ({rs})"
