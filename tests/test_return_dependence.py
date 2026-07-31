#!/usr/bin/env python3
"""
test_return_dependence.py — TM1 return-dependence test (NEW_EXPS_4 Part D). Small run, no network.
Run: `python -m pytest tests/test_return_dependence.py -q` or run the file directly.
"""
from __future__ import annotations

import csv
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
_root = Path(__file__).resolve().parents[1]
_bb = _root / "bridge_benchmark"
for p in ("generators", "experiments"):
    sys.path.insert(0, str(_bb / p))

import return_dependence as rd  # noqa: E402


# 6. return_dependence writes CSV and MD on a small run, with sensible columns/values.
def test_return_dependence_writes_outputs(tmp_path=None):
    out_dir = Path(tmp_path) if tmp_path else _root / "bridge_benchmark" / "cert" / "out" / "_test_rd"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_csv = out_dir / "return_dependence.csv"
    out_md = out_dir / "return_dependence.md"
    rows = rd.run(domains=["finance_compliance"], n=400, n_pairs=200, eps=0.10, seed=0,
                  out_csv=out_csv, out_md=out_md)
    assert out_csv.exists() and out_md.exists()

    with open(out_csv) as f:
        recs = list(csv.DictReader(f))
    assert len(recs) == 1
    for col in rd.ROWS_COLS:
        assert col in recs[0]
    r = rows[0]
    # rates are valid probabilities; matched return-dependence is nonzero (the whole point)
    for k in ("rho_matched", "rho_same_tool", "rho_tool_swap_same_x1",
              "rho_same_categorical_context", "safe_rate", "pre_return_majority_error"):
        assert 0.0 <= r[k] <= 1.0, (k, r[k])
    assert r["rho_matched"] > 0.0
    # pre-return majority error equals min(safe_rate, 1-safe_rate)
    assert abs(r["pre_return_majority_error"] - min(r["safe_rate"], 1 - r["safe_rate"])) < 1e-6
    md = out_md.read_text()
    assert "return-dependence" in md.lower()


if __name__ == "__main__":
    test_return_dependence_writes_outputs()
    print("PASS test_return_dependence_writes_outputs")
    print("\n1/1 passed")
