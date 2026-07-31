#!/usr/bin/env python3
"""
test_epsilon_pipeline.py — invariants for PLAN.md #17 (derive eps_emp), #20 (re-sweep), and #32
(implicit-policy gate). Fast (small n / n_mc); asserts the structural facts, not exact numbers.
"""
import sys
from pathlib import Path

import pytest

_root = Path(__file__).resolve().parents[1]
for p in ("generators", "models", "attacks", "cert", "experiments", "agents", "realdata"):
    sys.path.insert(0, str(_root / p))

import fault_injection as fi  # noqa: E402


# --------------------------------------------------------------------------- #
# #17 — eps_emp is the residual after validation: more validation => smaller eps
# --------------------------------------------------------------------------- #
def test_derive_epsilon_regime_ordering():
    import derive_epsilon as de
    sub = fi.load_realistic("financial_compliance", n_pool=3000, seed=0)
    qs = {}
    for regime, residual in de.REGIMES.items():
        es = de.pooled_residual_eps(sub, residual, 3000, seed=0)
        qs[regime] = float(__import__("numpy").quantile(es, 0.95))
    assert qs["none"] >= qs["integrity"] >= qs["integrity_plus_freshness"]
    # under full validation the residual (jitter+normalizer) sits near the 0.10 operating point
    assert qs["integrity_plus_freshness"] < 0.20


# --------------------------------------------------------------------------- #
# #20 — soundness + non-composition hold at every eps; utility moves with eps
# --------------------------------------------------------------------------- #
def test_resweep_sound_and_noncomposition_at_all_eps():
    from synthetic_tools import sample_records
    from realistic_schemas import finance_schema
    from harness import run_setting
    _, rt = finance_schema()
    rows = {}
    for eps in (0.05, 0.20):
        recs = sample_records(rt, 4000, eps=eps, seed=0)
        rows[eps] = run_setting(rt, recs, eps=eps, sigma=0.10, tau=0.80, n_mc=200,
                                n_cert=25, n_attack=40, seed=0)
    for eps, m in rows.items():
        assert m["cert_false_allow"] == 0.0, f"certificate unsound at eps={eps}"
        assert m["naive_C_falseallow"] == 1.0, f"non-composition lost at eps={eps}"
    # utility is non-increasing as the radius grows (more conservative certificate)
    assert rows[0.05]["R_allow"] >= rows[0.20]["R_allow"]


# --------------------------------------------------------------------------- #
# #32 — implicit policy: exact cert undefined; certified beats matched point gate under attack
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not Path(_root / "data/realdata/ieee_cis_boundary_balanced_s0.jsonl").exists(),
                    reason="IEEE-CIS data not present")
def test_implicit_policy_gate_lipschitz_robustness():
    """Default deterministic Lipschitz backend: no sampling -> non-vacuous and stable at low n."""
    pytest.importorskip("torch")
    pytest.importorskip("orthogonium")
    import implicit_policy_gate as ipg
    m = ipg.run(n_records=8000, n_eval=150, sigma=0.10, eps=0.10, tau=0.90, n_mc=200, alpha=1e-3,
                seed=0, backend="lipschitz")
    assert "UNDEFINED" in m["exact_marginal_certificate"]                 # (i) no predicate
    assert 0.0 < m["cert_allow_rate_safe"] < 1.0                          # (ii) non-vacuous
    # (iii) certified is at least as robust under attack as the matched-utility point gate
    assert m["cert_false_allow"] <= m["point_matched_false_allow_attacked"] + 1e-9
    assert m["point_matched_false_allow_attacked"] >= m["point_matched_false_allow_clean"] - 1e-9


@pytest.mark.skipif(not Path(_root / "data/realdata/ieee_cis_boundary_balanced_s0.jsonl").exists(),
                    reason="IEEE-CIS data not present")
def test_lipschitz_stable_where_smoothed_collapses():
    """The user's point: the deterministic Lipschitz cert is non-vacuous at a low MC budget where the
    smoothed certificate collapses to vacuous (no sampling -> no n_mc knife-edge)."""
    pytest.importorskip("torch")
    pytest.importorskip("orthogonium")
    import implicit_policy_gate as ipg
    lip = ipg.run(8000, 120, 0.10, 0.10, 0.90, 300, 1e-3, 0, backend="lipschitz")
    sm = ipg.run(8000, 120, 0.10, 0.10, 0.90, 300, 1e-3, 0, backend="smoothed")
    assert lip["cert_allow_rate_safe"] > 0.0                  # deterministic: stays non-vacuous
    assert lip["cert_allow_rate_safe"] >= sm["cert_allow_rate_safe"]  # smoothed starves at low n_mc
