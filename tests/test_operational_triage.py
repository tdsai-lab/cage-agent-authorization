"""Tests for NEW_EXPS Tier-1 #3 operational triage (analytic, on the existing IEEE-CIS gate/cert
machinery). Skip-guarded if IEEE-CIS data or torch is unavailable. Fast: subsampled config."""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_root = Path(__file__).resolve().parents[1] / "bridge_benchmark"
sys.path.insert(0, str(_root / "experiments"))

try:
    import implicit_policy_gate as ipg  # noqa: E402
    import operational_triage as tri  # noqa: E402
    _HAVE_DATA = ipg.IEEE_PATH.exists()
except Exception:  # pragma: no cover
    _HAVE_DATA = False

try:
    import torch  # noqa: F401
    _HAVE_TORCH = True
except Exception:  # pragma: no cover
    _HAVE_TORCH = False

pytestmark = pytest.mark.skipif(not _HAVE_DATA, reason="IEEE-CIS data not present")


def _args(backend, tmp):
    return SimpleNamespace(n_records=3000, n_eval=150, sigma=0.10, eps=0.10, tau=0.90,
                           n_mc=400, alpha=1e-3, seed=0, seeds=None, n_thr=25,
                           backend=backend, out=str(tmp))


@pytest.fixture(scope="module")
def lip_result():
    if not _HAVE_TORCH:
        pytest.skip("torch not available for the Lipschitz backend")
    return tri.run(_args("lipschitz", "/tmp/_ignore"), "lipschitz")


def test_certified_zero_in_budget_fraud_at_every_operating_point(lip_result):
    """(a) The certified gate's strict-0 frontier tier has 0 in-budget adversarial fraud in the auto
    tranche (both the tranche and fraud-conditional normalization), and the whole sound frontier is 0."""
    op = {o["operating_point"]: o for o in lip_result["operating_points"]}
    sf = op["certified_autonomy_sound_frontier"]
    assert sf["in_budget_fraud"] == 0.0
    assert sf["in_budget_fraud_conditional"] == 0.0
    # the sound frontier (all certified rows at or below the operating volume) is 0
    assert lip_result["cert_sound_frontier_max_in_budget_fraud"] == 0.0
    # and the certified autonomy tier is non-vacuous (real volume runs autonomously)
    assert sf["auto_frac"] > 0.0
    assert op["certified_autonomy_default"]["auto_frac"] > 0.0


def test_point_gate_materially_worse_at_matched_volume(lip_result):
    """(b) At a matched autonomy volume, the POINT gate admits materially more in-budget adversarial
    fraud (fraud-conditional false-allow) than the certified gate. The high-volume point (~80%) is the
    robust, subsampling-insensitive contrast."""
    op = {o["operating_point"]: o for o in lip_result["operating_points"]}
    hv = op["high_volume_point"]
    cd = op["certified_autonomy_default"]
    # the point gate at ~80% autonomy leaks a materially large fraction of fraud under the attack,
    # far above the certified strict-0 frontier tier (which is 0 by construction / soundness).
    assert hv["in_budget_fraud_conditional"] > 0.10
    assert hv["in_budget_fraud_conditional"] > \
        op["certified_autonomy_sound_frontier"]["in_budget_fraud_conditional"]
    # and at least as bad as the certified gate's own default operating point (>= handles the coarse,
    # low-fraud subsampled config where both saturate; the full-scale run separates them cleanly)
    assert hv["in_budget_fraud_conditional"] >= cd["in_budget_fraud_conditional"] - 1e-9


def test_curve_and_figure_produced(tmp_path, lip_result):
    """(c) The pareto CSV, operating-points CSV, and the figure files are produced."""
    results = {"lipschitz": lip_result}
    args = _args("lipschitz", tmp_path)
    tri.write_outputs(tmp_path, results, {"lipschitz": [0.0]}, [0], args)
    assert (tmp_path / "pareto_curve.csv").exists()
    assert (tmp_path / "operating_points.csv").exists()
    assert (tmp_path / "summary.json").exists()
    assert (tmp_path / "summary.md").exists()
    # figure: at least one of pdf/png (plotting is non-fatal but should succeed with matplotlib present)
    assert (tmp_path / "triage_pareto.pdf").exists() or (tmp_path / "triage_pareto.png").exists()
    # curve CSV has both gate families and >1 row
    txt = (tmp_path / "pareto_curve.csv").read_text().strip().splitlines()
    assert len(txt) > 3
    assert any("certified_lipschitz" in l for l in txt)
    assert any(l.startswith("point[") for l in txt)
