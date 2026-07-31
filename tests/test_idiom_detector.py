#!/usr/bin/env python3
"""
test_idiom_detector.py — PLAN_2 P1 Task A. The frozen idiom detector must FIRE on the authored
provenance-conditioned Rego (#9b ground truth) and be SILENT on a constant-threshold control, at
precision >= 0.90; cross-language matchers (Kyverno) fire on a map-indexed threshold and not on a
constant. Skips the Rego AST path if the OPA binary is absent.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
_DET = _BB / "experiments" / "detector"
_OPA = _BB / "experiments" / "opa_gate"
sys.path.insert(0, str(_DET))

import idiom_detector as idet  # noqa: E402

_POL = _OPA / "policies" / "authored"
_FIX = _DET / "fixtures"
_have_opa = (_OPA / "bin" / "opa").exists()


@pytest.mark.skipif(not _have_opa, reason="OPA binary not available")
def test_fires_on_authored_idiom_silent_on_constant():
    pos = idet.detect_file(_POL / "ieee_fraud.rego", "rego")
    neg = idet.detect_file(_POL / "constant_threshold_control.rego", "rego")
    assert pos.idiom_present is True and pos.confidence == 1.0
    assert pos.f_num == "risk_score" and pos.op == "<" and pos.s_field == "tool"
    assert neg.idiom_present is False


@pytest.mark.skipif(not _have_opa, reason="OPA binary not available")
def test_calibration_precision_bar():
    pos, neg = idet._authored()
    cal = idet.calibrate(pos, neg, "rego")
    assert cal["precision"] >= 0.90, f"precision {cal['precision']} below 0.90 bar"
    assert cal["fp"] == 0                       # the constant control must not be flagged


def test_frozen_spec_is_hashed():
    spec = idet.frozen_spec()
    assert len(spec["detector_sha256"]) == 64
    assert "theta(s)" in spec["idiom_predicate"]
    assert set(spec["compare_ops"]) == {"<", "<=", ">", ">="}


def test_kyverno_map_indexed_threshold():
    pytest.importorskip("yaml")
    on = idet.detect_file(_FIX / "kyverno_idiom.yaml", "kyverno")
    off = idet.detect_file(_FIX / "kyverno_constant.yaml", "kyverno")
    assert on.idiom_present is True and off.idiom_present is False
