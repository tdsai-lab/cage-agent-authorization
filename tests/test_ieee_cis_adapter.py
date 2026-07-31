#!/usr/bin/env python3
"""
test_ieee_cis_adapter.py — IEEE-CIS adapter loads the fixture CSVs and builds valid typed channels.
Run: python -m pytest tests/test_ieee_cis_adapter.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_root))
sys.path.insert(0, str(_root / "bridge_benchmark" / "realdata"))

from bridge_benchmark.realdata import ieee_cis_adapter as adp  # noqa: E402
from bridge_benchmark.realdata import ieee_cis_policy as pol  # noqa: E402

FIXTURE = _root / "bridge_benchmark" / "data" / "fixtures" / "ieee_cis_tiny"


def test_fixture_csv_loads():
    df = adp.load_raw(FIXTURE)
    assert len(df) > 0
    for c in ("TransactionID", "isFraud", "TransactionAmt", "ProductCD"):
        assert c in df.columns
    # identity merged (fixture has train_identity.csv)
    assert "DeviceType" in df.columns


def test_missing_dir_raises():
    import pytest
    with pytest.raises(FileNotFoundError):
        adp.load_raw("/nonexistent/ieee_cis/path")


def test_runs_without_identity(tmp_path):
    df = adp.load_raw(FIXTURE)
    tx = pd.read_csv(FIXTURE / "train_transaction.csv")
    tx.to_csv(tmp_path / "train_transaction.csv", index=False)        # no identity file
    df2 = adp.load_raw(tmp_path)
    assert len(df2) == len(tx)


def test_split_is_deterministic_and_balanced():
    df = adp.load_raw(FIXTURE)
    s1 = adp.assign_split(df, seed=0)
    s2 = adp.assign_split(df, seed=0)
    assert (s1 == s2).all()
    frac_train = (s1 == "risk_model_train").mean()
    assert 0.3 < frac_train < 0.7                                     # ~50/50


def test_x2_features_in_unit_interval():
    df = adp.load_raw(FIXTURE)
    edges = adp._amount_band_edges(pd.to_numeric(df["TransactionAmt"], errors="coerce"))
    caps = adp._caps(df)
    risk = adp.fixture_deterministic_risk(df)
    for (_, row), r in zip(df.iterrows(), risk):
        x2 = adp.build_x2(row, float(r), caps)
        assert set(x2) == set(pol.NUMERIC_FIELDS)
        for f, v in x2.items():
            assert 0.0 <= v <= 1.0, f"{f}={v} out of [0,1]"


def test_x1_values_are_schema_valid():
    df = adp.load_raw(FIXTURE)
    edges = adp._amount_band_edges(pd.to_numeric(df["TransactionAmt"], errors="coerce"))
    for _, row in df.iterrows():
        x1 = adp.build_x1(row, edges)
        assert set(x1) == set(pol.CATEGORICAL_FIELDS)
        for f, v in x1.items():
            assert v in pol.CATEGORICAL_FIELDS[f], f"{f}={v} not schema-valid"


def test_risk_model_trains_and_scores_in_unit_interval():
    df = adp.load_raw(FIXTURE)
    edges = adp._amount_band_edges(pd.to_numeric(df["TransactionAmt"], errors="coerce"))
    split = adp.assign_split(df, seed=0)
    pipe, _ = adp.train_risk_model(df[split == "risk_model_train"], edges, seed=0)
    risk = adp.predict_risk(pipe, df[split == "gate_pool"], edges)
    assert ((risk >= 0.0) & (risk <= 1.0)).all()


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
