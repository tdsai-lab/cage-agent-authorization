#!/usr/bin/env python3
"""
vendor_gatekeeper.py — vendor UNMODIFIED ConstraintTemplate Rego from open-policy-agent/gatekeeper-library
at a pinned commit, for the Track-A third-party prevalence test (NEW_EXP_OPA_GATE_2). Records full
provenance (source_url, commit, license, package, sha256). We do NOT edit the policy logic.
"""
from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path

import yaml

COMMIT = "6364bd191edb"           # gatekeeper-library master @ 2026-06-08 (pinned for reproducibility)
LICENSE = "Apache-2.0"
RAW = "https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/{commit}/{path}"
OUT = Path(__file__).resolve().parents[1] / "policies" / "third_party" / "gatekeeper_library"

# (short name, repo path to template.yaml, kind of constraint)
TEMPLATES = [
    ("allowedrepos", "library/general/allowedrepos/template.yaml", "discrete (image prefix)"),
    ("requiredlabels", "library/general/requiredlabels/template.yaml", "discrete (labels/regex)"),
    ("containerlimits", "library/general/containerlimits/template.yaml", "numeric (cpu/memory)"),
    ("hostnetworkports", "library/pod-security-policy/host-network-ports/template.yaml",
     "numeric/discrete (hostPort)"),
    ("privileged", "library/pod-security-policy/privileged-containers/template.yaml",
     "discrete (privileged)"),
]


def fetch(path):
    url = RAW.format(commit=COMMIT, path=path)
    with urllib.request.urlopen(url, timeout=30) as r:
        return url, r.read().decode()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    prov = {"source_repo": "open-policy-agent/gatekeeper-library", "commit": COMMIT,
            "license": LICENSE, "fetched_via": "raw.githubusercontent.com", "policies": []}
    for name, path, kind in TEMPLATES:
        url, text = fetch(path)
        doc = yaml.safe_load(text)
        target = doc["spec"]["targets"][0]
        if "rego" in target:                                   # legacy format
            rego, libs = target["rego"], target.get("libs", [])
        else:                                                  # newer `code:` format -> Rego engine
            src = next(c["source"] for c in target["code"] if c.get("engine") == "Rego")
            rego, libs = src["rego"], src.get("libs", [])
        pkg = next((ln.split("package", 1)[1].strip() for ln in rego.splitlines()
                    if ln.strip().startswith("package ")), None)
        d = OUT / name
        d.mkdir(exist_ok=True)
        (d / "policy.rego").write_text(rego)
        (d / "template.yaml").write_text(text)        # keep the unmodified source too
        lib_files = []
        for i, lib in enumerate(libs):
            (d / f"lib_{i}.rego").write_text(lib)
            lib_files.append(f"lib_{i}.rego")
        sha = hashlib.sha256(rego.encode()).hexdigest()[:16]
        prov["policies"].append({"name": name, "package": pkg, "kind": kind, "source_url": url,
                                 "rego_sha256_16": sha, "libs": lib_files,
                                 "constraint_kind": doc["spec"]["crd"]["spec"]["names"]["kind"]})
        print(f"vendored {name:16s} pkg={pkg:28s} sha={sha} libs={len(lib_files)} ({kind})")
    (OUT / "PROVENANCE.json").write_text(json.dumps(prov, indent=2) + "\n")
    print(f"\nwrote {OUT/'PROVENANCE.json'}")


if __name__ == "__main__":
    main()
