#!/usr/bin/env python3
"""
eval_gatekeeper.py — adapter to the UNMODIFIED vendored Gatekeeper-library policies (Track A,
NEW_EXP_OPA_GATE_2). We do NOT edit the third-party policy logic; we only build the Gatekeeper
admission-review input and read back `data.<package>.violation`.

Gatekeeper Rego is v0 and each `violation` rule reads a single global `input`, so we run ONE OPA
server (`opa run -s --v0-compatible`) loaded with every vendored policy + lib, and POST inputs to
`/v1/data/<package>/violation` (localhost, ~ms/request). Safe under a policy iff it returns zero
violations; Safe under the SET iff no policy reports a violation.
"""
from __future__ import annotations

import http.client
import json
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

import sys
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
from opa_bridge import opa_path  # noqa: E402

GL = _HERE.parent / "policies" / "third_party" / "gatekeeper_library"


def load_provenance():
    return json.loads((GL / "PROVENANCE.json").read_text())


def _all_rego_files():
    prov = load_provenance()
    files = [str(_HERE / "track_a_batch.rego")]
    for p in prov["policies"]:
        d = GL / p["name"]
        files.append(str(d / "policy.rego"))
        files += [str(d / lf) for lf in p.get("libs", [])]
    return files, prov


def safe_batch(cases):
    """Safe(z) for a whole batch in ONE stateless `opa eval` (no server). cases[i] = {"review":...,
    "parameters": merged}. Returns [bool] aligned to cases (True = zero violations under the SET)."""
    if not cases:
        return []
    files, _ = _all_rego_files()
    data_args = []
    for f in files:
        data_args += ["--data", f]
    proc = subprocess.run(
        [opa_path(), "eval", "--v0-compatible", "--format", "json", "--stdin-input", *data_args,
         "data.track_a_batch.results"],
        input=json.dumps({"cases": cases}), capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        raise RuntimeError(f"opa eval failed (rc={proc.returncode}):\n{proc.stderr[:2000]}")
    doc = json.loads(proc.stdout)
    try:
        res = doc["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError):
        raise RuntimeError(f"opa eval returned no results; head: {proc.stdout[:400]}")
    out = [None] * len(cases)
    for k, v in res.items():
        out[int(k)] = bool(v)
    if any(o is None for o in out):
        raise RuntimeError("OPA returned undefined safety for some cases (check track_a_batch query)")
    return out


class GatekeeperEngine:
    """OPA server loaded with the vendored Gatekeeper policies. Use as a context manager."""

    def __init__(self, port=None):
        self.port = port or _free_port()
        self.proc = None
        self.prov = load_provenance()
        self.packages = {p["name"]: p["package"] for p in self.prov["policies"]}

    def __enter__(self):
        rego_files = [str(_HERE / "track_a_aggregate.rego")]      # authored aggregation glue
        for p in self.prov["policies"]:
            d = GL / p["name"]
            rego_files.append(str(d / "policy.rego"))
            rego_files += [str(d / lf) for lf in p.get("libs", [])]
        self.proc = subprocess.Popen(
            [opa_path(), "run", "-s", "--v0-compatible", "-a", f"127.0.0.1:{self.port}", *rego_files],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        for _ in range(100):                              # wait for health (<=10s)
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=1).read()
                self.conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
                return self
            except (urllib.error.URLError, ConnectionError):
                if self.proc.poll() is not None:
                    raise RuntimeError(f"opa server died:\n{self.proc.stderr.read()[:1500]}")
                time.sleep(0.1)
        raise RuntimeError("opa server did not become healthy in 10s")

    def __exit__(self, *exc):
        try:
            self.conn.close()
        except Exception:
            pass
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def _post(self, path, payload):
        body = json.dumps(payload)
        for attempt in (1, 2):                            # one reconnect on a dropped keep-alive
            try:
                self.conn.request("POST", path, body=body, headers={"Content-Type": "application/json"})
                return json.loads(self.conn.getresponse().read())
            except (http.client.HTTPException, ConnectionError, OSError):
                if attempt == 2:
                    raise
                self.conn.close()
                self.conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)

    def report(self, review, merged_params):
        """ONE request: per-policy violation counts + set-safe via the authored aggregate package.
        merged_params is the union of every policy's parameters (each rule reads only its own keys)."""
        res = self._post("/v1/data/track_a",
                         {"input": {"review": review, "parameters": merged_params}}).get("result", {})
        return bool(res.get("safe", False)), res

    def _violations(self, package, review, parameters):
        body = json.dumps({"input": {"review": review, "parameters": parameters}}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/data/{package}/violation",
                                     data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            res = json.loads(r.read()).get("result", [])
        return res or []

    def violations_for_policy(self, name, review, parameters):
        return self._violations(self.packages[name], review, parameters)

    def set_safe(self, policy_params, review):
        """Safe under the SET iff NO vendored policy reports a violation for this review object.
        policy_params: {policy_name: parameters_dict}. Returns (safe_bool, per_policy_violation_counts)."""
        counts = {}
        for name, params in policy_params.items():
            counts[name] = len(self.violations_for_policy(name, review, params))
        return (sum(counts.values()) == 0), counts


if __name__ == "__main__":
    review_bad = {"object": {"metadata": {"name": "d", "labels": {"env": "prod"}},
                             "spec": {"containers": [{"name": "c", "image": "docker.io/evil/x:1",
                                                      "resources": {"limits": {"cpu": "900m", "memory": "1024Mi"}}}]}}}
    review_ok = {"object": {"metadata": {"name": "d", "labels": {"owner": "team-a", "env": "prod"}},
                            "spec": {"containers": [{"name": "c", "image": "registry.company.com/api:v1",
                                                     "resources": {"limits": {"cpu": "900m", "memory": "1024Mi"}}}]}}}
    merged = {"repos": ["registry.company.com/"],
              "labels": [{"key": "owner", "allowedRegex": "team-a|platform"}],
              "cpu": "1", "memory": "2Gi", "hostNetwork": False, "min": 0, "max": 0}
    with GatekeeperEngine() as eng:
        print("loaded packages:", eng.packages)
        print("bad  ->", eng.report(review_bad, merged))
        print("ok   ->", eng.report(review_ok, merged))
