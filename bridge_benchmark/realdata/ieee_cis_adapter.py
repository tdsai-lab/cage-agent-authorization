#!/usr/bin/env python3
"""
ieee_cis_adapter.py — load IEEE-CIS transaction features, build the typed (x1, x2) channels, train a
held-out risk model, and deterministically split rows into risk_model_train / gate_pool.

REAL vs CONSTRUCTED: the transaction feature marginals (amount, dist, C/D/V aggregates) and the
isFraud labels are real (or, in fixture mode, synthetic rows with the same columns). The risk model
is trained on isFraud ONLY to produce a continuous risk_score that grounds the continuous channel.
The authorization label is NOT isFraud — it is the constructed threshold policy in ieee_cis_policy.py.
isFraud is kept only for external plausibility diagnostics.

No internet. If the real CSVs are absent the caller gets a clear message pointing at the expected
path; a tiny bundled fixture under data/fixtures/ieee_cis_tiny lets tests run.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[1] / "realdata"))
from ieee_cis_policy import CATEGORICAL_FIELDS  # noqa: E402

SOURCE = "ieee_cis"

C_COLS = [f"C{i}" for i in range(1, 15)]
D_COLS = [f"D{i}" for i in range(1, 16)]
V_COLS = [f"V{i}" for i in range(1, 21)]
_BASE_TX_COLS = ["TransactionID", "isFraud", "TransactionDT", "TransactionAmt", "ProductCD",
                 "card4", "card6", "P_emaildomain", "R_emaildomain", "dist1", "dist2"]
TX_USECOLS = _BASE_TX_COLS + C_COLS + D_COLS + V_COLS
ID_USECOLS = ["TransactionID", "DeviceType"] + [f"id_{j:02d}" for j in range(1, 11)]

_RISK_NUM_FEATURES = ["amt_log", "dist1", "dist2", "c_mean", "d_mean", "v_mean"]
_RISK_CAT_FEATURES = ["ProductCD", "card4", "card6", "amount_band", "email_domain_match"]


# --------------------------------------------------------------------------- #
# load
# --------------------------------------------------------------------------- #
def load_raw(input_dir: str | Path, max_rows: int | None = None) -> pd.DataFrame:
    d = Path(input_dir)
    tx_path = d / "train_transaction.csv"
    if not tx_path.exists():
        raise FileNotFoundError(
            f"expected {tx_path} not found. Place IEEE-CIS Fraud Detection CSVs at "
            f"{d}/train_transaction.csv (+ optional train_identity.csv). No automatic download is "
            f"performed; for tests use --input-dir bridge_benchmark/data/fixtures/ieee_cis_tiny.")
    header = pd.read_csv(tx_path, nrows=0).columns.tolist()
    usecols = [c for c in TX_USECOLS if c in header]
    df = pd.read_csv(tx_path, usecols=usecols, nrows=max_rows)
    for c in TX_USECOLS:                       # fill any missing optional columns with NaN
        if c not in df.columns:
            df[c] = np.nan

    id_path = d / "train_identity.csv"
    if id_path.exists():
        id_header = pd.read_csv(id_path, nrows=0).columns.tolist()
        id_use = [c for c in ID_USECOLS if c in id_header]
        if "TransactionID" in id_use:
            df_id = pd.read_csv(id_path, usecols=id_use)
            df = df.merge(df_id, on="TransactionID", how="left")
    return df


# --------------------------------------------------------------------------- #
# deterministic split (stable hash of TransactionID + seed)
# --------------------------------------------------------------------------- #
def _stable_unit(transaction_id: int, seed: int) -> float:
    h = (np.uint64(int(transaction_id)) * np.uint64(2654435761) + np.uint64(seed * 2246822519 + 1))
    return float(int(h) % 1_000_003) / 1_000_003.0


def assign_split(df: pd.DataFrame, seed: int) -> np.ndarray:
    u = df["TransactionID"].map(lambda t: _stable_unit(t, seed)).to_numpy()
    return np.where(u < 0.5, "risk_model_train", "gate_pool")


# --------------------------------------------------------------------------- #
# feature engineering -> x1 (categorical) and x2 (continuous, all in [0,1])
# --------------------------------------------------------------------------- #
def _amount_band_edges(amt: pd.Series) -> tuple[float, float, float]:
    q = amt.quantile([0.25, 0.50, 0.75])
    return float(q.loc[0.25]), float(q.loc[0.50]), float(q.loc[0.75])


def _caps(df: pd.DataFrame) -> dict:
    def cap(series):
        s = pd.to_numeric(series, errors="coerce").dropna()
        return float(s.quantile(0.99)) if len(s) else 1.0
    return {
        "amount_cap": max(cap(df["TransactionAmt"]), 1.0),
        "dist_cap": max(cap(pd.concat([df["dist1"], df["dist2"]])), 1.0),
        "c_cap": max(cap(df[C_COLS].mean(axis=1)), 1e-6),
        "d_cap": max(cap(df[D_COLS].mean(axis=1)), 1e-6),
        "v_cap": max(cap(df[V_COLS].mean(axis=1)), 1e-6),
    }


def _band(amt: float, edges) -> str:
    q25, q50, q75 = edges
    if not np.isfinite(amt):
        return "low"
    if amt < q25:
        return "low"
    if amt < q50:
        return "medium"
    if amt < q75:
        return "high"
    return "very_high"


def _email_match(p, r) -> str:
    p_ok = isinstance(p, str) and p != "" and p == p     # not NaN
    r_ok = isinstance(r, str) and r != "" and r == r
    if not p_ok or not r_ok:
        return "missing"
    return "same" if p == r else "different"


def _norm_log(x, cap) -> float:
    x = float(x) if (x is not None and np.isfinite(x)) else 0.0
    x = max(x, 0.0)
    return min(math.log1p(x) / math.log1p(cap), 1.0)


def _norm_clip(x, cap) -> float:
    x = float(x) if (x is not None and np.isfinite(x)) else 0.0
    return float(min(max(x / cap, 0.0), 1.0))


def build_x1(row, edges) -> dict:
    band = _band(float(row["TransactionAmt"]) if np.isfinite(row["TransactionAmt"]) else float("nan"),
                 edges)
    def cat(v, allowed, default):
        v = v if (isinstance(v, str) and v in allowed) else default
        return v
    return {
        "ProductCD": cat(row.get("ProductCD"), CATEGORICAL_FIELDS["ProductCD"], "W"),
        "card4": cat(row.get("card4"), CATEGORICAL_FIELDS["card4"], "visa"),
        "card6": cat(row.get("card6"), CATEGORICAL_FIELDS["card6"], "debit"),
        "amount_band": band,
        "email_domain_match": _email_match(row.get("P_emaildomain"), row.get("R_emaildomain")),
    }


def build_x2(row, risk: float, caps: dict) -> dict:
    return {
        "risk_score": round(float(min(max(risk, 0.0), 1.0)), 6),
        "amount_norm": round(_norm_log(row["TransactionAmt"], caps["amount_cap"]), 6),
        "dist1_norm": round(_norm_log(row["dist1"], caps["dist_cap"]), 6),
        "dist2_norm": round(_norm_log(row["dist2"], caps["dist_cap"]), 6),
        "c_mean_norm": round(_norm_clip(np.nanmean(_vals(row, C_COLS)), caps["c_cap"]), 6),
        "d_mean_norm": round(_norm_clip(np.nanmean(_vals(row, D_COLS)), caps["d_cap"]), 6),
        "v_mean_norm": round(_norm_clip(np.nanmean(_vals(row, V_COLS)), caps["v_cap"]), 6),
    }


def _vals(row, cols):
    out = [pd.to_numeric(row.get(c), errors="coerce") for c in cols]
    arr = np.array([x if x is not None else np.nan for x in out], dtype=float)
    return arr if np.isfinite(arr).any() else np.array([0.0])


# --------------------------------------------------------------------------- #
# risk model: held-out logistic risk score grounded in real marginals
# --------------------------------------------------------------------------- #
def _risk_frame(df: pd.DataFrame, edges) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    out["amt_log"] = np.log1p(pd.to_numeric(df["TransactionAmt"], errors="coerce").clip(lower=0))
    out["dist1"] = pd.to_numeric(df["dist1"], errors="coerce")
    out["dist2"] = pd.to_numeric(df["dist2"], errors="coerce")
    out["c_mean"] = df[C_COLS].apply(pd.to_numeric, errors="coerce").mean(axis=1)
    out["d_mean"] = df[D_COLS].apply(pd.to_numeric, errors="coerce").mean(axis=1)
    out["v_mean"] = df[V_COLS].apply(pd.to_numeric, errors="coerce").mean(axis=1)
    out["ProductCD"] = df["ProductCD"].astype("object")
    out["card4"] = df["card4"].astype("object")
    out["card6"] = df["card6"].astype("object")
    out["amount_band"] = [(_band(a, edges)) for a in pd.to_numeric(df["TransactionAmt"], errors="coerce")]
    out["email_domain_match"] = [_email_match(p, r)
                                 for p, r in zip(df["P_emaildomain"], df["R_emaildomain"])]
    return out


def train_risk_model(df_train: pd.DataFrame, edges, seed: int = 0,
                     max_rows: int | None = None):
    """sklearn logistic pipeline trained on isFraud. Returns (pipeline, auc_or_None)."""
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder, StandardScaler

    df = df_train
    if max_rows is not None and len(df) > max_rows:
        df = df.sample(n=max_rows, random_state=seed)
    X = _risk_frame(df, edges)
    y = pd.to_numeric(df["isFraud"], errors="coerce").fillna(0).astype(int).to_numpy()

    num = Pipeline([("imp", SimpleImputer(strategy="median")), ("sc", StandardScaler())])
    cat = Pipeline([("imp", SimpleImputer(strategy="most_frequent")),
                    ("oh", OneHotEncoder(handle_unknown="ignore"))])
    pre = ColumnTransformer([("num", num, _RISK_NUM_FEATURES), ("cat", cat, _RISK_CAT_FEATURES)])
    pipe = Pipeline([("pre", pre),
                     ("clf", LogisticRegression(max_iter=1000, class_weight="balanced"))])
    auc = None
    if len(np.unique(y)) == 2:
        pipe.fit(X, y)
    else:                                       # degenerate label column -> uniform-ish risk
        pipe = None
    return pipe, auc


def predict_risk(pipe, df: pd.DataFrame, edges) -> np.ndarray:
    if pipe is None:
        return fixture_deterministic_risk(df)
    X = _risk_frame(df, edges)
    return pipe.predict_proba(X)[:, 1]


def heldout_auc(pipe, df_gate: pd.DataFrame, edges) -> float | None:
    if pipe is None:
        return None
    y = pd.to_numeric(df_gate["isFraud"], errors="coerce").fillna(0).astype(int).to_numpy()
    if len(np.unique(y)) < 2:
        return None
    from sklearn.metrics import roc_auc_score
    p = predict_risk(pipe, df_gate, edges)
    try:
        return float(roc_auc_score(y, p))
    except Exception:
        return None


def fixture_deterministic_risk(df: pd.DataFrame) -> np.ndarray:
    """Deterministic pseudo-risk in [0,1] from normalized marginals (no isFraud, no RNG)."""
    caps = _caps(df)
    edges = _amount_band_edges(pd.to_numeric(df["TransactionAmt"], errors="coerce"))
    out = []
    for _, row in df.iterrows():
        v = _norm_clip(np.nanmean(_vals(row, V_COLS)), caps["v_cap"])
        c = _norm_clip(np.nanmean(_vals(row, C_COLS)), caps["c_cap"])
        a = _norm_log(row["TransactionAmt"], caps["amount_cap"])
        out.append(min(max(0.5 * v + 0.3 * c + 0.2 * a, 0.0), 1.0))
    return np.asarray(out)
