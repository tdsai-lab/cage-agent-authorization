#!/usr/bin/env python3
"""
opa_bridge.py — thin batched bridge to the Open Policy Agent (OPA) binary.

`eval_batch(rego_path, package, cases)` sends ALL cases in ONE `opa eval` call (stdin JSON
{"cases":[...]}) and reads back `data.<package>.decisions` — a per-index boolean object — so labelling
thousands of probe points costs one subprocess, not one per point. The verdict is OPA's; Python only
assembles inputs and reads outputs (policy-as-code oracle).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_BIN = _HERE / "bin" / "opa"


def opa_path() -> str:
    """Locate the OPA binary: vendored bin/opa, then $OPA_BIN, then PATH."""
    if _BIN.exists():
        return str(_BIN)
    env = os.environ.get("OPA_BIN")
    if env and Path(env).exists():
        return env
    found = shutil.which("opa")
    if found:
        return found
    raise FileNotFoundError("OPA binary not found (looked at bin/opa, $OPA_BIN, PATH). "
                            "Download: curl -L -o bin/opa "
                            "https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static")


def opa_version() -> str:
    out = subprocess.run([opa_path(), "version"], capture_output=True, text=True, timeout=30)
    for line in out.stdout.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return "unknown"


def policy_hash(rego_path) -> str:
    return hashlib.sha256(Path(rego_path).read_bytes()).hexdigest()[:16]


def eval_batch(rego_path, package: str, cases: list[dict]) -> list[bool]:
    """Return [safe(case) for case in cases] as decided by OPA. One subprocess for the whole batch."""
    if not cases:
        return []
    query = f"data.{package}.decisions"
    proc = subprocess.run(
        [opa_path(), "eval", "--format", "json", "--stdin-input", "--data", str(rego_path), query],
        input=json.dumps({"cases": cases}), capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        raise RuntimeError(f"opa eval failed (rc={proc.returncode}):\n{proc.stderr[:2000]}")
    doc = json.loads(proc.stdout)
    try:
        decisions = doc["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError):
        # query produced no result -> undefined for all (treat as a hard error, not silent False)
        raise RuntimeError(f"opa eval returned no decisions; raw head: {proc.stdout[:500]}")
    # decisions is an object {"0": bool, "1": bool, ...}; order by integer key
    out = [None] * len(cases)
    for k, v in decisions.items():
        out[int(k)] = bool(v)
    if any(o is None for o in out):
        missing = [i for i, o in enumerate(out) if o is None]
        raise RuntimeError(f"OPA returned undefined decisions for case indices {missing[:10]} "
                           f"(check the policy `safe` is total over inputs)")
    return out


if __name__ == "__main__":
    rego = _HERE / "policies" / "authored" / "finance.rego"
    cases = [
        {"tool": "t_credit", "action": "approve_transaction", "x1": {"jurisdiction": "domestic"},
         "x2": {"risk_score": 0.40}},   # 0.40 < 0.55+0.06=0.61 -> safe
        {"tool": "t_credit", "action": "approve_transaction", "x1": {"jurisdiction": "sanctioned"},
         "x2": {"risk_score": 0.40}},   # 0.40 < 0.55-0.16=0.39 -> FALSE (unsafe)
        {"tool": "t_credit", "action": "manual_review", "x1": {"jurisdiction": "sanctioned"},
         "x2": {"risk_score": 0.99}},   # non-privileged -> safe
    ]
    print("opa version:", opa_version())
    print("decisions:", eval_batch(rego, "opa_gate.finance", cases), "(expected [True, False, True])")
