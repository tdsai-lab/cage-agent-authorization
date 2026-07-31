#!/usr/bin/env python3
"""
test_opa_track_a.py — NEW_EXP_OPA_GATE_2 Track A (third-party Gatekeeper prevalence). Verifies the
vendored-policy adapter (Safe = zero violations over the SET) and the documented informative null
(C ~ 0 under unmodified Gatekeeper policies). Skips if OPA or the vendored policies are absent.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

import pytest

_OPA = Path(__file__).resolve().parents[1] / "bridge_benchmark" / "experiments" / "opa_gate"
sys.path.insert(0, str(_OPA))
sys.path.insert(0, str(_OPA / "scripts"))

opa_bridge = pytest.importorskip("opa_bridge")
try:
    opa_bridge.opa_path()
except FileNotFoundError:
    pytest.skip("OPA binary not available", allow_module_level=True)
if not (_OPA / "policies" / "third_party" / "gatekeeper_library" / "PROVENANCE.json").exists():
    pytest.skip("vendored Gatekeeper policies absent (run scripts/vendor_gatekeeper.py)",
                allow_module_level=True)

from eval_gatekeeper import safe_batch  # noqa: E402
import run_track_a as ta  # noqa: E402


def test_gatekeeper_set_verdicts():
    mp = ta.MERGED_PARAMS
    bad = {"review": ta.review_from_z({"s": {"registry": "docker.io/", "owner": "__none__",
                                             "env": "prod", "privileged": True, "hostport": 8080},
                                       "x": {"cpu_limit_m": 900, "memory_limit_mib": 1024,
                                             "replicas": 1, "container_count": 1}}), "parameters": mp}
    ok = {"review": ta.review_from_z({"s": {"registry": "registry.company.com/", "owner": "team-a",
                                            "env": "prod", "privileged": False, "hostport": 0},
                                      "x": {"cpu_limit_m": 500, "memory_limit_mib": 512,
                                            "replicas": 1, "container_count": 1}}), "parameters": mp}
    assert safe_batch([bad, ok, bad]) == [False, True, False]


def test_third_party_informative_null_C_absent():
    import random
    rng = random.Random(0)
    zs = [ta._sample_z(rng, boundary=False) for _ in range(200)]
    cats = categorize_safely(zs)
    c = Counter(cats)
    assert set(c).issubset(set("RCUAB"))
    assert sum(c.values()) == len(zs)
    # documented null: joint-gap C does not arise under unmodified Gatekeeper policies
    assert c.get("C", 0) / len(zs) <= 0.02
    # the discrete-only category A is reachable (these policies are discrete-dominated)
    assert c.get("A", 0) > 0


def categorize_safely(zs):
    return ta.categorize(zs, eps=0.10)


if __name__ == "__main__":
    test_gatekeeper_set_verdicts()
    test_third_party_informative_null_C_absent()
    print("PASS test_opa_track_a (2)")
