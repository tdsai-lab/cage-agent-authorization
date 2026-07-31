#!/usr/bin/env python3
"""
test_revision_exps.py — revision runs M1–M5.

Pure-logic unit tests on the statistical helpers + smoke tests that each script's
public entry point runs on whatever artifacts are present (skip-guarded when the
gitignored cert/out inputs are absent, e.g. a fresh clone).
"""
from __future__ import annotations

import sys
import os
from pathlib import Path

import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
sys.path.insert(0, str(_BB / "experiments"))

import numpy as np  # noqa: E402

import wilson_zero_cells as WZ  # noqa: E402
import prop3_boundary_mass as BM  # noqa: E402
import natural_traffic_autonomy as NTA  # noqa: E402
import fidelity_audit_stopping as FAS  # noqa: E402


# ── M1 (R4): Wilson / Clopper-Pearson helpers ─────────────────────────────────
def test_wilson_zero_count_known_values():
    # Wilson-95% upper for 0 successes: closed comparisons to published values.
    assert WZ.wilson_upper(0, 40) == pytest.approx(0.0876, abs=1e-3)
    assert WZ.wilson_upper(0, 300) == pytest.approx(0.0126, abs=1e-3)
    # monotone: more trials -> tighter (smaller) upper bound
    assert WZ.wilson_upper(0, 1000) < WZ.wilson_upper(0, 100) < WZ.wilson_upper(0, 10)


def test_wilson_bounds_in_unit_interval():
    for n in (1, 8, 24, 300, 6032):
        u = WZ.wilson_upper(0, n)
        assert 0.0 < u <= 1.0


def test_cp_zero_count_closed_form():
    # k=0 Clopper-Pearson two-sided upper = 1-(alpha/2)**(1/n)
    for n in (24, 40, 300):
        expected = 1.0 - (0.05 / 2.0) ** (1.0 / n)
        assert WZ.cp_upper(0, n) == pytest.approx(expected, rel=1e-9)


def test_cp_and_wilson_agree_at_zero():
    # at k=0 the two intervals are close (cross-check); neither uniformly dominates.
    for n in (24, 40, 300, 6032):
        w, c = WZ.wilson_upper(0, n), WZ.cp_upper(0, n)
        assert abs(w - c) <= 0.02 or abs(w - c) / max(w, c) <= 0.10


def test_wilson_degenerate_n_zero():
    import math
    assert math.isnan(WZ.wilson_upper(0, 0))


# ── M5 (R6): Prop.3 boundary-mass helpers ─────────────────────────────────────
def test_mass_counts_within_tolerance():
    vals = [0.0, 1e-7, -1e-7, 0.5, 1.0, 1.0 - 1e-8]
    k, n = BM._mass(vals, 0.0)
    assert (k, n) == (3, 6)          # 0, +1e-7, -1e-7 within 1e-6
    k, n = BM._mass(vals, 1.0)
    assert (k, n) == (2, 6)          # 1.0 and 1.0-1e-8


def test_mass_ignores_nan():
    k, n = BM._mass([np.nan, 0.0, np.nan], 0.0)
    assert (k, n) == (1, 1)          # NaNs dropped from both count and denominator


def test_mass_empty():
    assert BM._mass([], 0.0) == (0, 0)
    assert BM._mass([np.nan, np.nan], 0.0) == (0, 0)


@pytest.mark.skipif(not Path(os.environ.get("IEEE_CIS_DIR", "bridge_benchmark/data/raw/ieee_cis")).exists(),
                    reason="real IEEE-CIS data not mounted")
def test_m5_ieee_clean_boundary_soundness():
    # the EXACT clean safety boundary (g_self=0) must carry no mass that could be a
    # false-allow — and regardless, boundary records are blocked (closed inequality).
    import delta_sensitivity_c as DS
    rows, n = BM.audit_dataset("ieee_cis", DS.ieee_records, max_rows=4000)
    assert n > 0
    for r in rows:
        assert r["on_boundary_k"] >= 0
        assert "blocked" in r["soundness_side"]


# ── M2 (R3): natural-traffic autonomy accounting ─────────────────────────────
def test_autonomy_identity():
    # unconditional allow = Pr[R]*R_allow ; human review = 1 - that.
    r = NTA._acc("s", "exact (rung 1)", 0.5684, 0.0334, 1.0, 1000, "src")
    assert r["unconditional_certified_allow"] == pytest.approx(0.5684, abs=1e-4)
    assert r["human_review_volume"] == pytest.approx(0.4316, abs=1e-4)
    r2 = NTA._acc("s", "rung 2", 0.30, 0.10, 0.40, 1000, "src")
    assert r2["unconditional_certified_allow"] == pytest.approx(0.12, abs=1e-4)
    assert r2["human_review_volume"] == pytest.approx(0.88, abs=1e-4)


def test_autonomy_bounds():
    # unconditional allow never exceeds Pr[R]; volumes sum to 1.
    for prR, ra in ((0.9, 1.0), (0.1, 0.5), (0.46, 1.0)):
        r = NTA._acc("s", "b", prR, 0.05, ra, 100, "src")
        assert r["unconditional_certified_allow"] <= prR + 1e-9
        assert r["unconditional_certified_allow"] + r["human_review_volume"] == pytest.approx(1.0)


# ── M4 (R7): anytime-valid Clopper-Pearson confidence sequence ────────────────
def test_cp_upper_known_value():
    # exact one-sided CP upper for 5/100 at alpha=0.05 ≈ 0.1023
    assert FAS._cp_upper(5, 100, 0.05) == pytest.approx(0.1023, abs=1e-3)
    assert FAS._cp_upper(0, 100, 0.05) == pytest.approx(1 - 0.05 ** (1 / 100), abs=1e-6)
    assert FAS._cp_upper(10, 10, 0.05) == 1.0
    assert FAS._cp_upper(0, 0, 0.05) == 1.0


def test_av_alpha_budget_bounded():
    # α-spending weights must sum to ≤ alpha (anytime validity via union bound)
    seq = FAS.av_cp_sequence([0] * 5000, alpha=0.05)
    assert sum(s["alpha_j"] for s in seq) <= 0.05 + 1e-9


def test_av_upper_tightens_on_clean_stream():
    # NOTE: the α-spending bound is NOT monotone step-to-step (later checkpoints spend less α), but it
    # tightens overall on a clean stream and is non-vacuous at large N.
    seq = FAS.av_cp_sequence([0] * 4000, alpha=0.05)
    pb = [s["p_bar"] for s in seq]
    assert pb[-1] < pb[0]
    assert pb[-1] < 0.01


def test_av_upper_covers_true_rate():
    # upper bound must sit above the true mean for a high-rate stream
    seq = FAS.av_cp_sequence([1 if i % 4 == 0 else 0 for i in range(2000)], alpha=0.05)
    assert seq[-1]["p_bar"] > 0.25


def test_matured_stream_respects_audit_delay():
    log = [{"dt": 0, "cert_allow": True, "fraud": 1, "regressed": False},
           {"dt": 5, "cert_allow": True, "fraud": 0, "regressed": True}]
    # with a large delay nothing matures during the stream; both drain at the end, order preserved
    out = FAS.matured_stream(log, delta_audit=100)
    assert [fr for fr, _ in out] == [1, 0]
    assert [rg for _, rg in out] == [False, True]


def test_analyse_regime_halts_on_rate_jump():
    # clean prefix all-safe, then a burst of false-allows → p_bar must cross p* and halt
    matured = [(0, False)] * 300 + [(1, True)] * 300
    res = FAS.analyse_regime(matured, alpha=0.05, tol_margin=0.03, p_floor=0.05, n0=50, ratio=1.4)
    assert res["halted"] is True
    assert res["reg_maturation_index"] == 300
    assert res["clean_guarantee_p_bar"] < 0.05      # clean prefix certifies low fidelity gap


def test_analyse_regime_no_halt_on_clean():
    matured = [(0, False)] * 4000
    res = FAS.analyse_regime(matured, alpha=0.05, tol_margin=0.03, p_floor=0.05, n0=50, ratio=1.4)
    assert res["halted"] is False
    assert res["guarantee_established"] is True     # clean stream certifies fidelity


def test_synthetic_halt_demo_fires():
    # deterministic (fixed rng seed) demonstration that establish-then-halt fires on a true rate jump
    d = FAS.synthetic_halt_demo(alpha=0.05, p_floor=0.05, n0=50, ratio=1.4)
    assert d["halted"] is True
    assert d["guarantee_established_N"] is not None          # guarantee established on the clean segment
    assert d["halt_N"] > d["n_clean"]                        # halt occurs after the regression starts
    assert d["halt_latency_audits"] > 0


# ── M3 (R2): NAB fscale held-out selection (pure split logic) ─────────────────
def test_m3_split_balances_both_halves():
    import nab_fscale_heldout as NF
    test = [{"category": c, "id": i} for c in "ABCRU" for i in range(8)]
    sel, ev = NF._split_cert(test, n_cert=4)
    # both halves contain every category (in particular R, which a naive slice can starve)
    for half in (sel, ev):
        cats = {r["category"] for r in half}
        assert cats == set("ABCRU")
    assert not [r for r in sel if r in ev]          # disjoint


@pytest.mark.skipif(not (WZ.OUT and (Path(WZ.OUT) / "certificates.jsonl").exists()),
                    reason="cert/out/certificates.jsonl not present (fresh clone)")
def test_m1_audit_runs_and_all_zero_cells():
    rows = []
    WZ.rows_certificates(rows)
    assert rows, "expected synthetic-canonical zero cells"
    # every audited cell is a genuine zero (k=0) with a positive denominator
    for r in rows:
        assert r["k"] == 0
        assert r["N"] > 0
        assert 0.0 < r["wilson95_upper"] <= 1.0
