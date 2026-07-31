#!/usr/bin/env python3
"""
test_cx6_marble.py — CX6. Calibrating ε on one half and evaluating on a disjoint holdout, with the REAL
Marble engine deciding: the certified budget covers the integrity+freshness faults (near-zero escape)
while the schema/identity tail escapes (reproduces #16 on a real engine). Skips unless Marble is live.
"""
from __future__ import annotations

import sys
import os
import urllib.request
from pathlib import Path

import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
for p in ("experiments", "generators", "realdata"):
    sys.path.insert(0, str(_BB / p))

pytest.importorskip("numpy")
import cx6_marble as cx6  # noqa: E402

_MARBLE_DIR = Path(os.environ.get("MARBLE_DIR", "external/marble_src"))


def _ready():
    try:
        urllib.request.urlopen(f"{cx6.API}/liveness", timeout=5).read()
    except Exception:
        return False
    return (_MARBLE_DIR / ".scenario_id").exists() and (_MARBLE_DIR / ".api_key").exists() \
        and cx6.fi.IEEE_PATH.exists()


pytestmark = pytest.mark.skipif(not _ready(), reason="Marble live / IEEE data / key required")


@pytest.fixture(scope="module")
def res():
    sid = (_MARBLE_DIR / ".scenario_id").read_text().strip()
    key = (_MARBLE_DIR / ".api_key").read_text().strip()
    return cx6.run(sid, key, n=400, seed=0)


def test_eps_calibrated_positive(res):
    assert 0.0 < res["eps_cal_p95"] < 0.2                # a sane freshness-scale budget


def test_integrity_freshness_covered_on_holdout(res):
    # the calibrated budget covers integrity+freshness faults on held-out data (low escape)
    assert res["integrity_freshness_escape_mean"] < 0.05
    assert res["per_mechanism"]["wrong_provenance_binding"]["budget_escape_rate"] == 0.0


def test_out_of_budget_tail_escapes(res):
    # the schema/identity tail escapes the calibrated ball (the honest, measured precondition)
    assert res["out_of_budget_tail_escape_mean"] > res["integrity_freshness_escape_mean"]
    assert res["per_mechanism"]["cache_key_collision"]["budget_escape_rate"] > 0.05
