#!/usr/bin/env python3
"""
nab_adapter.py — load the Numenta Anomaly Benchmark (NAB) real cloud-CPU telemetry, build the typed
(x1, x2) channels for the monitoring/SRE domain, and deterministically split rows into
metric_model_train / gate_pool.

REAL vs CONSTRUCTED: the CPU-utilization values (real EC2/RDS % load) and the NAB anomaly windows are
real. The authorization label is NOT the anomaly label; it is the constructed provenance/env-dependent
threshold policy in nab_policy.py. The anomaly label (`is_anomaly`, from labels/combined_windows.json)
is kept ONLY as an external plausibility diagnostic (the monitoring analogue of IEEE-CIS `isFraud`).

Download: the NAB files are fetched from the public GitHub raw endpoint if absent under
data/realdata/nab/ (cached; sha256-logged). No fabrication: if download fails the caller gets a clear
message. Continuous fields are normalized to [0,1] (cpu% / 100 for the policy-binding channel, real
rolling-window aggregates for the gate-feature channels), matching the IEEE-CIS adapter convention.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[1] / "realdata"))
from nab_policy import CATEGORICAL_FIELDS, LOOSE_TOOLS, STRICT_TOOLS, TOOLS  # noqa: E402

SOURCE = "nab"
DATA_ROOT = _HERE.parents[1] / "data" / "realdata" / "nab"
_GH_BASE = "https://raw.githubusercontent.com/numenta/NAB/master"

# real CPU-utilization time series (per-machine provenance). realAWSCloudwatch = 10 EC2/RDS machines;
# realKnownCause = a real ASG-misconfiguration CPU trace.
_AWS_FILES = [
    "ec2_cpu_utilization_24ae8d", "ec2_cpu_utilization_53ea38", "ec2_cpu_utilization_5f5533",
    "ec2_cpu_utilization_77c1ca", "ec2_cpu_utilization_825cc2", "ec2_cpu_utilization_ac20cd",
    "ec2_cpu_utilization_c6585a", "ec2_cpu_utilization_fe7f93",
    "rds_cpu_utilization_cc0c53", "rds_cpu_utilization_e47b3b",
]
_KNOWN_FILES = ["cpu_utilization_asg_misconfiguration"]
_ROLL_WINDOW = 12          # 12 points x 5-min cadence = 1h rolling context


def _rel_paths() -> list[tuple[str, str]]:
    out = [(f"data/realAWSCloudwatch/{f}.csv", f) for f in _AWS_FILES]
    out += [(f"data/realKnownCause/{f}.csv", f) for f in _KNOWN_FILES]
    return out


# --------------------------------------------------------------------------- #
# download-if-absent (cached)
# --------------------------------------------------------------------------- #
def download_if_absent(data_root: str | Path = DATA_ROOT, verbose: bool = True) -> Path:
    root = Path(data_root)
    files = list(_rel_paths()) + [("labels/combined_windows.json", None),
                                  ("LICENSE.txt", None)]
    for rel, _ in files:
        dest = root / rel
        if dest.exists() and dest.stat().st_size > 0:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        url = f"{_GH_BASE}/{rel}"
        if verbose:
            print(f"[nab_adapter] downloading {url}")
        try:
            urllib.request.urlretrieve(url, dest)
        except Exception as e:  # pragma: no cover - network dependent
            raise RuntimeError(
                f"failed to download {url}: {e}. NAB is a public GitHub repo (numenta/NAB, MIT). "
                f"If offline, pre-place the CSVs under {root}/data/.")
    return root


def is_downloaded(data_root: str | Path = DATA_ROOT) -> bool:
    root = Path(data_root)
    need = [root / rel for rel, _ in _rel_paths()]
    need.append(root / "labels" / "combined_windows.json")
    return all(p.exists() and p.stat().st_size > 0 for p in need)


# --------------------------------------------------------------------------- #
# load real telemetry -> long frame with per-machine provenance + anomaly label
# --------------------------------------------------------------------------- #
def _load_labels(root: Path) -> dict:
    p = root / "labels" / "combined_windows.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def _machine_id(fname: str) -> str:
    return fname


def _machine_class(fname: str) -> str:
    return "rds" if fname.startswith("rds") else "ec2"


def load_raw(data_root: str | Path = DATA_ROOT, max_rows: int | None = None) -> pd.DataFrame:
    """Return a long frame: one row per (machine, timestamp) with real CPU value + anomaly flag."""
    root = Path(data_root)
    labels = _load_labels(root)
    frames = []
    for rel, fname in _rel_paths():
        path = root / rel
        if not path.exists():
            raise FileNotFoundError(
                f"expected {path} not found. Run download_if_absent() or the --download step "
                f"(source: {_GH_BASE}/{rel}).")
        df = pd.read_csv(path)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp").reset_index(drop=True)
        df["machine_id"] = _machine_id(fname)
        df["machine_class"] = _machine_class(fname)
        # anomaly windows key uses the source-relative path
        key = rel[len("data/"):] if rel.startswith("data/") else rel
        windows = labels.get(key, [])
        anom = np.zeros(len(df), dtype=int)
        for w in windows:
            lo, hi = pd.to_datetime(w[0]), pd.to_datetime(w[1])
            anom |= ((df["timestamp"] >= lo) & (df["timestamp"] <= hi)).to_numpy().astype(int)
        df["is_anomaly"] = anom
        # rolling context (trailing window) computed on the real series, per machine
        v = df["value"].astype(float)
        df["roll_mean"] = v.rolling(_ROLL_WINDOW, min_periods=1).mean()
        df["roll_std"] = v.rolling(_ROLL_WINDOW, min_periods=1).std().fillna(0.0)
        df["delta"] = v.diff().fillna(0.0)
        df["max_recent"] = v.rolling(_ROLL_WINDOW, min_periods=1).max()
        df["min_recent"] = v.rolling(_ROLL_WINDOW, min_periods=1).min()
        df["row_in_machine"] = np.arange(len(df))
        frames.append(df)
    out = pd.concat(frames, ignore_index=True)
    # a stable global integer id per row (for deterministic split / sampling)
    out["obs_id"] = np.arange(len(out))
    if max_rows is not None and len(out) > max_rows:
        out = out.iloc[:max_rows].reset_index(drop=True)
    return out


# --------------------------------------------------------------------------- #
# deterministic split (stable hash of obs_id + seed)
# --------------------------------------------------------------------------- #
def _stable_unit(obs_id: int, seed: int) -> float:
    h = (np.uint64(int(obs_id)) * np.uint64(2654435761) + np.uint64(seed * 2246822519 + 1))
    return float(int(h) % 1_000_003) / 1_000_003.0


def assign_split(df: pd.DataFrame, seed: int) -> np.ndarray:
    u = df["obs_id"].map(lambda t: _stable_unit(t, seed)).to_numpy()
    return np.where(u < 0.5, "metric_model_train", "gate_pool")


# --------------------------------------------------------------------------- #
# provenance/env assignment: each telemetry OBSERVATION is deterministically routed through one of the
# monitoring endpoints (loose vs strict). This is the constructed provenance context s: the SAME
# machine's readings can be scraped via a staging or a prod collector, so provenance is per-return.
# The related-pair swap (d=1) mislabels which environment produced the reading. (Per-observation, not
# per-machine, avoids the coarse 11-machine coin-flip artifact and gives a dataset-grounded, seed-
# stable prevalence.)
# --------------------------------------------------------------------------- #
def obs_base_tool(obs_id: int, seed: int) -> str:
    u = _stable_unit(int(obs_id), seed * 7 + 3)
    return TOOLS[int(u * len(TOOLS)) % len(TOOLS)]


def machine_base_tool(machine_id: str, seed: int) -> str:  # kept for compatibility (unused)
    u = _stable_unit(abs(hash(("m", machine_id))) % 1_000_003, seed * 7 + 3)
    return TOOLS[int(u * len(TOOLS)) % len(TOOLS)]


# --------------------------------------------------------------------------- #
# feature engineering -> x1 (categorical) and x2 (continuous, all in [0,1])
# --------------------------------------------------------------------------- #
def _cpu_band(cpu_pct: float) -> str:
    if not np.isfinite(cpu_pct):
        return "low"
    if cpu_pct < 25.0:
        return "low"
    if cpu_pct < 50.0:
        return "medium"
    if cpu_pct < 75.0:
        return "high"
    return "very_high"


def _norm_pct(x) -> float:
    x = float(x) if (x is not None and np.isfinite(x)) else 0.0
    return float(min(max(x / 100.0, 0.0), 1.0))


def build_x1(row) -> dict:
    def cat(v, allowed, default):
        return v if (isinstance(v, str) and v in allowed) else default
    return {
        "machine_class": cat(row.get("machine_class"), CATEGORICAL_FIELDS["machine_class"], "ec2"),
        "load_band": _cpu_band(float(row["value"]) if np.isfinite(row["value"]) else float("nan")),
        "metric_kind": "cpu_utilization",
    }


def build_x2(row) -> dict:
    return {
        "cpu_util_norm": round(_norm_pct(row["value"]), 6),
        "roll_mean_norm": round(_norm_pct(row.get("roll_mean")), 6),
        "roll_std_norm": round(_norm_pct(row.get("roll_std")), 6),
        # delta normalized to [0,1] by (delta+100)/200 so a real rate-of-change is a signed feature
        "delta_norm": round(float(min(max((float(row.get("delta", 0.0)) + 100.0) / 200.0, 0.0), 1.0)), 6),
        "max_recent_norm": round(_norm_pct(row.get("max_recent")), 6),
        "min_recent_norm": round(_norm_pct(row.get("min_recent")), 6),
    }
