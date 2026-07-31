#!/usr/bin/env python3
"""
test_scan_corpus.py — PLAN_2 P1 Task B. The pre-registered scan must reproduce the gatekeeper-library
NULL (positive null control), expose the numeric-θ vs keyed-θ funnel, decide HIT on a corpus that
contains the authored idiom, and carry a pre-registration hash. Uses the VENDORED gatekeeper library
and the authored Rego (no dependency on externally-cloned corpora). Skips if OPA is absent.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
_DET = _BB / "experiments" / "detector"
_OPA = _BB / "experiments" / "opa_gate"
sys.path.insert(0, str(_DET))

import scan_corpus as sc  # noqa: E402

_have_opa = (_OPA / "bin" / "opa").exists()
pytestmark = pytest.mark.skipif(not _have_opa, reason="OPA binary not available")

_GK = _OPA / "policies" / "third_party" / "gatekeeper_library"
_AUTHORED = _OPA / "policies" / "authored"


def test_gatekeeper_null_control_reproduced():
    corpus = [{"name": "gatekeeper_library_NULLCTRL", "language": "rego", "root": _GK,
               "glob": "*.rego", "source": "vendored"}]
    results, _ = sc.scan(corpus)
    r = results[0]
    assert r["files_scanned"] >= 5
    assert r["files_with_idiom"] == 0 and r["idiom_rate"] == 0.0   # the null control


def test_funnel_numeric_ge_keyed():
    corpus = [{"name": "authored", "language": "rego", "root": _AUTHORED, "glob": "*.rego",
               "source": "authored"}]
    results, _ = sc.scan(corpus)
    r = results[0]
    # the authored dir contains the idiom (ieee_fraud/finance/sre/ops) + the constant control
    assert r["files_with_idiom"] >= 4
    assert r["files_with_numeric_threshold"] >= r["files_with_idiom"]   # funnel ordering


def test_decision_hit_on_authored_idiom():
    corpus = [{"name": "authored_HIT", "language": "rego", "root": _AUTHORED, "glob": "*.rego",
               "source": "authored"}]
    results, counts = sc.scan(corpus)
    reg = sc.prereg(corpus, counts)
    assert len(reg["detector_sha256"]) == 64
    any_hit = any(r["files_with_idiom"] > 0 for r in results)
    assert any_hit is True
