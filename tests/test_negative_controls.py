#!/usr/bin/env python3
"""NEW_EXPS_7 Part D — negative control: arbitrary endpoint lies are outside the certified budget.

Checks: the L2 distance helper; and that a large fabrication (gap ≫ ε) is marked OUTSIDE the certified
budget with certified_claim_applicable → 0, while a small fabrication (gap ≤ ε) is inside the budget.
"""
import csv
import sys
from pathlib import Path

_repo = Path(__file__).resolve().parents[1]
_root = _repo / "bridge_benchmark"
for p in ("generators", "models", "cert", "experiments", "realdata", "agents"):
    sys.path.insert(0, str(_root / p))
sys.path.insert(0, str(_repo))

import pytest  # noqa: E402
import negative_controls as nc  # noqa: E402

DATA = _root / "data" / "realdata" / "ieee_cis_boundary_balanced_s0.jsonl"


def test_l2_only_counts_changed_fields():
    a = {"r": 0.9, "x": 0.5}
    b = {"r": 0.1, "x": 0.5}
    assert abs(nc.l2(a, b, ["r", "x"]) - 0.8) < 1e-9


@pytest.mark.skipif(not DATA.exists(), reason="IEEE-CIS balanced dataset not generated")
def test_endpoint_lie_outside_budget(tmp_path):
    nc.main(["--records", str(DATA), "--n-examples", "20", "--n-mc", "200",
             "--out-dir", str(tmp_path)])
    with open(tmp_path / "endpoint_lie.csv") as f:
        rows = {float(r["fabrication_gap"]): r for r in csv.DictReader(f)}
    # small fabrication (== ε) is inside the certified budget
    small = rows[0.10]
    assert small["inside_certified_budget"] == "True"
    assert float(small["certified_claim_applicable"]) == 1.0
    # large fabrication (0.80 ≫ ε) is OUTSIDE the budget: certificate makes no claim
    big = rows[0.80]
    assert big["inside_certified_budget"] == "False"
    assert float(big["certified_claim_applicable"]) == 0.0
    # and the distance to the true state exceeds ε for the big lie
    assert float(big["mean_distance_to_true_state"]) > 0.10


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
