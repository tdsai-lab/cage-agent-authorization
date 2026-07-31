#!/usr/bin/env python3
"""
test_additional_exps.py — follow-up experiments EXP-A1/A3/A4. A2 lives in
test_mcp_substrate.py. Heavy (real-data / torch) paths are skip-guarded; the pure logic is unit-tested
on tiny in-memory fixtures so the suite stays fast and offline.
"""
from __future__ import annotations

import sys
import os
from pathlib import Path

import numpy as np
import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
sys.path.insert(0, str(_BB / "experiments"))
sys.path.insert(0, str(_BB / "generators"))
sys.path.insert(0, str(_BB / "realdata"))

RAW = Path(os.environ.get("IEEE_CIS_DIR", "bridge_benchmark/data/raw/ieee_cis"))


# ── EXP-A1: compound / correlated fault injection ─────────────────────────────────────────────────────
def _tiny_substrate():
    import fault_injection as FI
    # two provenance tools, one categorical env field, two numeric fields; a small record pool
    recs = []
    for i in range(60):
        recs.append({"tool_id": "toolA" if i % 2 else "toolB",
                     "x1": {"env": "prod" if i % 3 else "staging", "pack": "p1" if i % 2 else "p2"},
                     "x2": {"a": float(i % 5), "b": float((i * 7) % 11)}})
    sub = FI.Substrate("tiny", recs, ["a", "b"],
                       provenance_swaps={"toolA": ["toolB"], "toolB": ["toolA"]},
                       x1_values={"env": ["prod", "staging", "canary"], "pack": ["p1", "p2", "p3"]},
                       env_field="env")
    return sub


def test_a1_two_discrete_pair_reaches_d2():
    import compound_fault_injection as C
    sub = _tiny_substrate()
    # provenance swap + policy-pack rebind = two DISTINCT discrete atoms -> d>=2 when both fire
    row = C.measure_combo(sub, ("wrong_provenance_binding", "wrong_policy_pack"), 40, 0, "adversarial")
    assert row is not None
    assert row["pr_d_ge2_when_all_fired"] >= 0.99      # both distinct atoms change -> d=2
    assert row["pr_d_ge3"] == 0.0 and row["frac_d_le2"] == 1.0


def test_a1_discrete_plus_continuous_pair_stays_d1():
    import compound_fault_injection as C
    sub = _tiny_substrate()
    row = C.measure_combo(sub, ("toctou_env_label", "numeric_jitter"), 40, 0, "adversarial")
    assert row is not None
    assert row["pr_d_ge2"] == 0.0 and row["max_d"] <= 1     # one discrete + one continuous -> d<=1


def test_a1_independent_regime_is_lower_than_adversarial():
    import compound_fault_injection as C
    sub = _tiny_substrate()
    adv = C.measure_combo(sub, ("wrong_provenance_binding", "wrong_policy_pack"), 200, 0, "adversarial")
    ind = C.measure_combo(sub, ("wrong_provenance_binding", "wrong_policy_pack"), 200, 0, "independent")
    # independent co-occurrence (product of fire rates) yields far less d>=2 mass than forced co-occurrence
    assert ind["pr_d_ge2"] <= adv["pr_d_ge2"]


def test_a1_combos_defined():
    import compound_fault_injection as C
    assert ("wrong_provenance_binding", "wrong_policy_pack") in C.PAIRS
    assert any(len(t) == 3 for t in C.TRIPLES)


@pytest.mark.skipif(not RAW.exists(), reason="raw IEEE-CIS not present")
def test_a1_d2_lipschitz_soundness_quick():
    import compound_fault_injection as C
    r = C.d2_lipschitz_soundness(seeds=(0,), quick=True)
    if not r.get("available"):
        pytest.skip(f"lipschitz backend unavailable: {r.get('reason')}")
    assert r["d2_cert_false_allow_zero"] is True        # d=2 gate sound (cert_false_allow=0)


# ── EXP-A3: sub-minute freshness SLA sweep ────────────────────────────────────────────────────────────
@pytest.mark.skipif(not RAW.exists(), reason="raw IEEE-CIS not present")
def test_a3_submin_runs_and_cert_sound():
    import freshness_sla_submin as F3
    p = F3.run([0], n_eval=1500, max_rows=120000, grid=[15, 30, 60, 120])
    assert p["cert_false_allow_invariant_holds"] is True    # certificate stays sound at every Δt
    # coverage grows monotonically-ish with Δt (more same-entity priors admitted)
    covs = [r["coverage_hit_rate"] for r in p["table"]]
    assert covs[-1] >= covs[0]
    assert "verdict" in p


# ── EXP-A4: operational fidelity monitor ──────────────────────────────────────────────────────────────
def test_a4_monitor_alarms_on_high_rate():
    import fidelity_monitor as F4
    # a synthetic decision log where every certified-allow after idx 50 is a fraud -> must alarm
    log = []
    for i in range(200):
        fraud = 1 if i >= 100 else 0
        log.append({"dt": float(i), "cert_allow": True, "fraud": fraud, "regressed": i >= 100})
    res = F4.run_monitor(log, n_window=20, theta_alarm=0.5, delta_audit=0.0)
    assert res is not None and res["alarm_decision_idx"] >= 100


def test_a4_monitor_silent_when_clean():
    import fidelity_monitor as F4
    log = [{"dt": float(i), "cert_allow": True, "fraud": 0, "regressed": False} for i in range(300)]
    assert F4.run_monitor(log, n_window=50, theta_alarm=0.01, delta_audit=0.0) is None


def test_a4_delayed_audit_shifts_detection_later():
    import fidelity_monitor as F4
    log = [{"dt": float(i), "cert_allow": True, "fraud": 1 if i >= 50 else 0, "regressed": i >= 50}
           for i in range(400)]
    fast = F4.run_monitor(log, n_window=10, theta_alarm=0.5, delta_audit=0.0)
    slow = F4.run_monitor(log, n_window=10, theta_alarm=0.5, delta_audit=30.0)
    assert fast is not None and slow is not None
    assert slow["alarm_decision_idx"] >= fast["alarm_decision_idx"]   # later label -> later detection


def test_a4_two_window_ignores_slow_drift():
    import fidelity_monitor as F4
    # a SLOW linear drift in the fraud rate (benign non-stationarity) must NOT trip the two-window monitor
    log = []
    for i in range(4000):
        p = 0.1 + 0.3 * (i / 4000)            # base rate drifts 0.1 -> 0.4 gradually
        fraud = 1 if ((i * 2654435761) % 1000) / 1000.0 < p else 0
        log.append({"dt": float(i), "cert_allow": True, "fraud": fraud, "regressed": False})
    # trailing reference tracks the slow drift; a modest theta should not alarm on it
    assert F4.run_monitor(log, n_window=500, theta_alarm=0.1, delta_audit=0.0) is None


def test_a4_corrupt_labels_flips_only_frauds():
    import fidelity_monitor as F4
    train = [{"tool_id": "t", "x1": {}, "x2": {}, "fraud": 1, "dt": 0.0} for _ in range(100)]
    train += [{"tool_id": "t", "x1": {}, "x2": {}, "fraud": 0, "dt": 0.0} for _ in range(100)]
    out = F4._corrupt_labels(train, 1.0, 0)
    assert all(r["fraud"] == 0 for r in out)                       # all frauds flipped at frac=1.0
    out2 = F4._corrupt_labels(train, 0.0, 0)
    assert sum(r["fraud"] for r in out2) == 100                    # none flipped at frac=0.0


# ── EXP-B1: δ-sensitivity of C prevalence (min(δ,ε) law) ──────────────────────────────────────────────
def test_b1_law_check_monotone_saturating():
    import delta_sensitivity_c as B1
    # a synthetic Pr(C) that tracks min(δ,ε): rises to δ=ε then flat
    eps = 0.10
    agg = [{"delta": d, "min_delta_eps": min(d, eps), "pr_C_mean": min(d, eps) * 0.5}
           for d in [0.02, 0.05, 0.08, 0.15, 0.30]]
    lc = B1.law_check(agg, eps)
    assert lc["monotone_up_to_eps"] and lc["tracks_law"]
    assert lc["saturation_rel_span_above_eps"] < 0.01


def test_b1_sweep_c_grows_with_delta_and_cert_sound():
    import ieee_cis_policy as pol
    import delta_sensitivity_c as B1
    # a boundary-clustered record set: risk just below θ so larger δ opens more C mass
    recs = [(0.49, "payment_gateway_loose", {}) for _ in range(200)]
    rows = B1.sweep(recs, 0.488808, pol, [0.02, 0.08, 0.30], 0.10)
    prc = [r["pr_C"] for r in rows]
    assert prc[0] <= prc[1] + 1e-9                      # C mass non-decreasing in δ up to ε
    assert all(r["exact_cert_false_allow"] == 0.0 for r in rows)   # exact cert sound at every δ


# ── EXP-B2: raw-unit ε audit ──────────────────────────────────────────────────────────────────────────
def test_b2_log_inverse_roundtrip():
    from ieee_cis_adapter import _norm_log
    import raw_unit_epsilon_audit as B2
    cap = 1000.0
    for x in (10.0, 100.0, 500.0):
        v = _norm_log(x, cap)
        assert abs(B2._inv_log(v, cap) - x) < 1e-6      # inverse of the log normalization is exact


def test_b2_log_field_eps_move_grows_with_anchor():
    import raw_unit_epsilon_audit as B2
    # a heavy-tailed raw field; ε-move magnitude must grow from the median to the upper anchor (log compress)
    vals = list(range(1, 2001))
    rows = B2.audit_log_field("amt", vals, cap=2000.0, eps=0.10, unit="USD")
    mag = {r["anchor_quantile"]: max(r["raw_move_up_for_eps"], r["raw_move_down_for_eps"]) for r in rows}
    assert mag[0.95] > mag[0.50]                        # ε=0.10 is a larger raw move higher up the tail


def test_b2_linear_field_constant_move():
    import raw_unit_epsilon_audit as B2
    rows = B2.audit_linear_field("cpu", list(range(0, 101)), cap=100.0, eps=0.10, unit="CPU %")
    moves = {r["raw_move_up_for_eps"] for r in rows}
    assert moves == {10.0}                              # linear: constant ε·cap move regardless of anchor


# ── EXP-C4: fscale held-out selection ─────────────────────────────────────────────────────────────────
def test_c4_cert_subset_balanced():
    import fscale_heldout_selection as C4
    ev = ([{"category": "R", "i": i} for i in range(50)]
          + [{"category": "C", "i": i} for i in range(20)]
          + [{"category": "U", "i": i} for i in range(20)])
    sub = C4._cert_subset(ev, n_cert=10)
    cats = {r["category"] for r in sub}
    assert "R" in cats and (("C" in cats) or ("U" in cats))   # R + a stress mix


@pytest.mark.skipif(not RAW.exists(), reason="raw IEEE-CIS not present (proxy for full deps)")
def test_c4_heldout_selection_synthetic_eval_sound():
    import d_sweep as DS
    if not DS._LIP_OK:
        pytest.skip(f"lipschitz backend unavailable: {DS._LIP_IMPORT_ERR}")
    import fscale_heldout_selection as C4
    p = C4.run([0], [3.0, 4.0], eps=0.10, quick=True, out_prefix="_c4_test", tracks=("synthetic",))
    assert p is not None and p["all_eval_sound"] is True     # held-out-selected fscale sound on EVAL
