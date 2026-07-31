#!/usr/bin/env python3
"""
test_ieee_cis_categories.py — end-to-end generation + certification on the fixture, and agreement
between the policy's analytic category and the shared oracle over the generated rule_table.
Run: python -m pytest tests/test_ieee_cis_categories.py -q
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_root))
sys.path.insert(0, str(_root / "bridge_benchmark" / "generators"))

from oracle import category as oracle_category  # noqa: E402
from bridge_benchmark.realdata import ieee_cis_policy as pol  # noqa: E402

FIXTURE = _root / "bridge_benchmark" / "data" / "fixtures" / "ieee_cis_tiny"
REQUIRED = ("uid", "source", "domain", "tool_id", "candidate_action", "x1", "x2", "label",
            "category", "oracle", "meta")


def test_analytic_category_matches_shared_oracle():
    """The independent policy analytic category must agree with oracle.py over the rule_table."""
    import numpy as np
    theta, delta, eps = 0.50, 0.08, 0.10
    rt = pol.build_rule_table(theta, delta)
    x1 = {"ProductCD": "W", "card4": "visa", "card6": "debit",
          "amount_band": "medium", "email_domain_match": "missing"}
    for tool in pol.TOOLS:
        for r in np.linspace(0.001, 0.999, 80):
            z = {"domain": pol.DOMAIN, "tool_id": tool, "candidate_action": pol.ACTION,
                 "categorical_fields": x1,
                 "numeric_fields": {f: (float(r) if f == "risk_score" else 0.3)
                                    for f in pol.NUMERIC_FIELDS}}
            oc = oracle_category(z, pol.ACTION, rt, d=1, eps=eps)["category"][0]
            ac = pol.analytic_category(float(r), tool, x1, theta, delta, eps)["category"]
            assert oc == ac, f"oracle={oc} analytic={ac} tool={tool} r={r:.3f}"


def _gen(tmp_path, sampling):
    from bridge_benchmark.experiments import realdata_ieee_cis as gen
    out = tmp_path / f"recs_{sampling}.jsonl"
    rc = gen.main(["--input-dir", str(FIXTURE), "--out", str(out), "--sampling", sampling,
                   "--n-records", "200", "--theta-quantile", "0.70", "--delta", "0.08",
                   "--epsilon", "0.10", "--seed", "0", "--min-c-records", "5"])
    assert rc == 0
    return out


def test_generation_writes_jsonl_config_report(tmp_path):
    out = _gen(tmp_path, "boundary_balanced")
    assert out.exists()
    assert (tmp_path / "ieee_cis_generation_config.json").exists()
    assert (tmp_path / "ieee_cis_generation_report.md").exists()
    recs = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    assert recs
    for r in recs:
        for k in REQUIRED:
            assert k in r, f"missing {k}"
        assert set(r["x2"]) == set(pol.NUMERIC_FIELDS)
        for v in r["x2"].values():
            assert 0.0 <= v <= 1.0
        assert r["category"] in ("R", "A", "B", "C", "U")


def test_c_targeted_produces_joint_witnesses(tmp_path):
    out = _gen(tmp_path, "c_targeted")
    recs = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    c_recs = [r for r in recs if r["category"] == "C"]
    assert c_recs, "c_targeted produced no C records on the fixture"
    for r in c_recs:
        w = r["witness"]
        assert w is not None and w["type"] == "joint" and w["label"] == 0
        # the witness is jointly unsafe under the strict provenance
        assert pol.safe(w["risk_score_witness"], w["tool_id"], r["x1"], 0.0 + r["oracle"]["theta_base"],
                        r["oracle"]["delta"]) is False


def test_certification_runs_and_writes_metrics(tmp_path):
    from bridge_benchmark.experiments import run_realdata_ieee_cis_cert as runner
    recs = _gen(tmp_path, "boundary_balanced")
    out = tmp_path / "cert_out"
    rc = runner.main(["--records", str(recs), "--epsilon", "0.10", "--d", "1", "--sigma", "0.10",
                      "--tau", "0.90", "--n-mc", "300", "--n-cert", "12", "--n-attack", "20",
                      "--pred-cap", "60", "--seed", "0", "--out", str(out)])
    assert rc == 0
    for f in ("metrics.json", "report.md", "config.json", "records_with_predictions.jsonl"):
        assert (out / f).exists(), f"missing {f}"
    m = json.loads((out / "metrics.json").read_text())
    assert m["cert_false_allow"] == 0.0                         # soundness
    assert "fraud_diagnostics" in m and "category_counts" in m


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
