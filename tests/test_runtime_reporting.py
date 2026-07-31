#!/usr/bin/env python3
"""NEW_EXPS_7 Part E — runtime & cost reporting.

Checks: the runtime summary files are written with the expected columns, and the certified gate's
per-decision latency is materially higher than the pointwise gates (it runs Monte-Carlo over the
enumerated discrete branches). No LLM backend is used here (offline).
"""
import csv
import sys
from pathlib import Path

_root = Path(__file__).resolve().parents[1] / "bridge_benchmark"
for p in ("generators", "models", "cert", "experiments", "agents"):
    sys.path.insert(0, str(_root / p))

import pytest  # noqa: E402
import runtime_report as rr  # noqa: E402

COLS = {"domain", "gate", "n_mc", "discrete_branches", "sigma", "epsilon", "tau",
        "mean_latency_ms", "p50_latency_ms", "p95_latency_ms", "decisions_per_second",
        "R_allow", "cert_false_allow"}


def test_runtime_summary_written(tmp_path):
    rr.main(["--n-records", "30", "--n-mc", "150", "--out-dir", str(tmp_path)])
    assert (tmp_path / "runtime_summary.csv").exists()
    assert (tmp_path / "runtime_summary.md").exists()
    with open(tmp_path / "runtime_summary.csv") as f:
        rows = list(csv.DictReader(f))
    assert rows and COLS.issubset(rows[0].keys())
    by = {(r["domain"], r["gate"]): r for r in rows}
    for dom in ("finance", "sre"):
        cert = float(by[(dom, "certified")]["mean_latency_ms"])
        none = float(by[(dom, "none")]["mean_latency_ms"])
        assert cert > none, "certified gate should be slower than the no-op gate"
        # certified gate reports its MC budget and >=1 discrete branch
        assert int(by[(dom, "certified")]["n_mc"]) == 150
        assert int(by[(dom, "certified")]["discrete_branches"]) >= 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
