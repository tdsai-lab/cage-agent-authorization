#!/usr/bin/env python3
"""Pytest for EXP-CX5 (OpenFisca BRS zone-ceiling case study). Skips if the OpenFisca corpus is absent."""
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import cx5_openfisca as X   # noqa: E402


@pytest.mark.skipif(not X.BRS.exists(), reason="OpenFisca corpus not cloned")
def test_real_ceilings_load_and_boundary_exists():
    theta = X.load_ceilings()
    # real 2025 BRS values (frozen): 1-person zone A = 38508, zone C = 33479
    assert theta["zone_A"][1] == 38508.0 and theta["zone_C"][1] == 33479.0
    # a provenance-conditioned boundary exists: ceiling varies by zone at every household size >= 1
    assert any(len({theta[z][n] for z in X.ZONES}) > 1 for n in X.SIZES)


@pytest.mark.skipif(not X.BRS.exists(), reason="OpenFisca corpus not cloned")
def test_category_c_exists_and_neighborhood_blocks_point_exploit():
    p = X.run(n=4000, seed=0, eps_list=[0.10], cap_mode="max_ceiling", out_prefix="_cx5_test")
    r = p["results"]["0.1"]
    assert r["pr_C"] > 0                                   # natural Category-C witnesses on the real rule
    pv = r["point_vs_neighborhood"]
    assert pv["n_c_witnesses"] > 0
    assert pv["neighborhood_grants"] == 0                  # exact neighborhood cert blocks every C witness
    assert pv["point_grants"] == pv["n_c_witnesses"]       # naive point gate grants them all (the exploit)
    assert pv["point_unsafe_under_swap"] == pv["n_c_witnesses"]   # all realize the zone-swap over-ceiling


@pytest.mark.skipif(not X.BRS.exists(), reason="OpenFisca corpus not cloned")
def test_taxonomy_partitions():
    theta = X.load_ceilings()
    cap = max(theta[z][n] for z in X.ZONES for n in X.SIZES)
    tn = {z: {n: theta[z][n] / cap for n in X.SIZES} for z in X.ZONES}
    # an over-ceiling income in every zone -> U
    assert X.categorize("zone_A", 1, 2.0, tn, 0.10)[0] == "U"
    # a deep-interior low income -> R (robust safe under any zone swap + eps)
    assert X.categorize("zone_C", 1, 0.01, tn, 0.10)[0] == "R"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
