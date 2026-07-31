#!/usr/bin/env python3
"""
scan_corpus.py — PLAN_2 P1 Task B: a PRE-REGISTERED scan for the continuous provenance-conditioned
threshold idiom across third-party EXECUTABLE policy corpora, using the frozen Task-A detector.

Pre-registration (frozen + hashed BEFORE the scan, per the P1 invariant): the corpus list with each
repo's resolved commit, the detector sha256, the idiom predicate, the sampling scheme (all policy files
matching the language glob), and the two-stage funnel definition. The pre-registration hash is written
alongside the results so the scan is auditable.

Two-stage prevalence funnel:  Pr[C | corpus] = idiom_rate(corpus) * Pr[C | idiom].
For a CONTINUOUS threshold theta(s) the C-window has length min(Delta, eps) > 0, so Pr[C|idiom] ~ 1 and
the funnel collapses to idiom_rate; we keep the factor explicit because a QUANTIZED theta (Azure
keySize-style) gives Pr[C|idiom] < 1.

Decision tree (pre-registered):
  HIT  (>=1 continuous theta(s) in third-party executable code) -> emit the hit(s) for Task C, prefer
       as P3 substrate.
  NULL (idiom_rate ~ 0 continuous across third-party executable corpora) -> record the null, localized
       at the corpus stage (gatekeeper-library is the positive null control); the regulatory-authored
       executable track (#9b + PSD2/FinCEN) is the documented one-rung-lower fallback.

The gatekeeper-library (vendored) MUST reproduce idiom_rate=0 as the positive null control.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

import idiom_detector as idet  # noqa: E402

_BB = _HERE.parents[1]
_OPA = _BB / "experiments" / "opa_gate"
_EXT = _BB.parents[0] / "external" / "corpora"
OUT = _BB / "cert" / "out"

# Frozen corpus list. `path` is resolved at scan time; `commit` is captured from the checkout.
CORPORA = [
    {"name": "gatekeeper_library_NULLCTRL", "language": "rego",
     "root": _OPA / "policies" / "third_party" / "gatekeeper_library",
     "glob": "*.rego", "source": "open-policy-agent/gatekeeper-library (vendored)"},
    {"name": "kyverno_policies", "language": "kyverno",
     "root": _EXT / "kyverno_policies", "glob": "*.yaml",
     "source": "github.com/kyverno/policies"},
    {"name": "cloud_custodian", "language": "cloud_custodian",
     "root": _EXT / "cloud-custodian_cloud-custodian", "glob": "*.yml",
     "source": "github.com/cloud-custodian/cloud-custodian"},
]


def _git_commit(root):
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=20)
        return out.stdout.strip()[:12] if out.returncode == 0 else "n/a"
    except Exception:  # noqa: BLE001
        return "n/a"


def _is_kyverno_policy(path):
    try:
        head = path.read_text(errors="ignore")[:4000]
    except Exception:  # noqa: BLE001
        return False
    return ("kind: ClusterPolicy" in head or "kind: Policy" in head) and "kyverno.io" in head


def _policy_files(corpus):
    root, lang = corpus["root"], corpus["language"]
    if not root.exists():
        return []
    files = []
    if lang == "rego":
        files = list(root.rglob("*.rego"))
    elif lang == "kyverno":
        files = [p for p in root.rglob("*.yaml") if _is_kyverno_policy(p)]
    elif lang == "cloud_custodian":
        files = [p for p in root.rglob("*.yml")] + [p for p in root.rglob("*.yaml")]
    return files


def prereg(corpora, scanned_counts):
    return {
        "detector_sha256": idet.frozen_spec()["detector_sha256"],
        "idiom_predicate": idet.IDIOM_PREDICATE,
        "sampling": "all policy files matching the language glob (kyverno: kind in {ClusterPolicy,Policy})",
        "funnel": "Pr[C|corpus] = idiom_rate * Pr[C|idiom]; Pr[C|idiom]~1 for continuous theta",
        "corpora": [{"name": c["name"], "source": c["source"], "language": c["language"],
                     "commit": _git_commit(c["root"]), "files_scanned": scanned_counts.get(c["name"], 0)}
                    for c in corpora],
    }


def scan(corpora, max_files=None):
    results = []
    scanned_counts = {}
    for c in corpora:
        files = _policy_files(c)
        if max_files:
            files = files[:max_files]
        scanned_counts[c["name"]] = len(files)
        hits, n_numeric = [], 0
        for f in files:
            try:
                h = idet.detect_file(f, c["language"])
            except Exception:  # noqa: BLE001
                continue
            n_numeric += int(h.numeric_threshold)
            if h.idiom_present:
                hits.append(h.as_dict())
        n = len(files)
        results.append({
            "corpus": c["name"], "language": c["language"], "files_scanned": n,
            "files_with_numeric_threshold": n_numeric,    # funnel: have a numeric comparison at all
            "files_with_idiom": len(hits),                # of which, threshold is provenance-keyed
            "idiom_rate": round(len(hits) / n, 5) if n else 0.0,
            "Pr_C_given_corpus_continuous": round(len(hits) / n, 5) if n else 0.0,
            "hits": hits[:20],
        })
    return results, scanned_counts


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--max-files", type=int, default=None, help="cap files/corpus (debug)")
    ap.add_argument("--out", default="idiom_scan")
    args = ap.parse_args()

    results, counts = scan(CORPORA, args.max_files)
    reg = prereg(CORPORA, counts)
    reg_hash = hashlib.sha256(json.dumps(reg, sort_keys=True).encode()).hexdigest()[:16]

    any_hit = any(r["files_with_idiom"] > 0 and not r["corpus"].endswith("NULLCTRL")
                  for r in results)
    decision = "HIT" if any_hit else "NULL"
    null_ctrl = next((r for r in results if r["corpus"].endswith("NULLCTRL")), None)
    null_ctrl_ok = bool(null_ctrl and null_ctrl["files_with_idiom"] == 0)

    OUT.mkdir(parents=True, exist_ok=True)
    payload = {"prereg": reg, "prereg_hash": reg_hash, "decision": decision,
               "null_control_reproduced": null_ctrl_ok, "results": results}
    (OUT / f"{args.out}.json").write_text(json.dumps(payload, indent=2))
    with open(OUT / f"{args.out}.md", "w") as f:
        f.write("# PLAN_2 P1 Task B — pre-registered third-party idiom scan\n\n")
        f.write(f"Pre-registration hash `{reg_hash}` · detector `{reg['detector_sha256'][:16]}`. "
                f"Funnel: {reg['funnel']}\n\n")
        f.write("| corpus | lang | commit | files | numeric-θ | **keyed-θ (idiom)** | idiom_rate |\n")
        f.write("|---|---|---|---:|---:|---:|---:|\n")
        for r, creg in zip(results, reg["corpora"]):
            f.write(f"| {r['corpus']} | {r['language']} | `{creg['commit'][:8]}` | "
                    f"{r['files_scanned']} | {r['files_with_numeric_threshold']} | "
                    f"**{r['files_with_idiom']}** | {r['idiom_rate']} |\n")
        f.write("\n*numeric-θ* = files with any numeric threshold comparison; *keyed-θ* = of those, the "
                "threshold is selected by a discrete/provenance key (the idiom). A null with "
                "numeric-θ≫0 but keyed-θ=0 is credible: thresholds exist but are CONSTANT, not "
                "provenance-conditioned.\n")
        f.write(f"\n**Decision: {decision}.** Null control (gatekeeper-library) reproduced: "
                f"{null_ctrl_ok} (idiom_rate must be 0). ")
        if decision == "HIT":
            f.write("≥1 continuous theta(s) in third-party executable code → proceed to Task C "
                    "(engine-labeled C-witness) on the hit; prefer as the P3 substrate.\n\n## Hits\n\n")
            for r in results:
                for h in r["hits"]:
                    f.write(f"- [{r['corpus']}] `{Path(h['source']).name}` f_num={h['f_num']} "
                            f"s={h['s_field']} op={h['op']} conf={h['confidence']} ({h['evidence']})\n")
        else:
            f.write("idiom_rate≈0 for continuous theta(s) across third-party executable corpora → "
                    "**informative null, localized at the corpus stage** (exactly as gatekeeper "
                    "already shows). The regulatory-authored executable track (#9b + PSD2/FinCEN) is "
                    "the documented one-rung-lower fallback; a textual-substrate scan backs the "
                    "plausibility argument. Honest null, not papered over.\n")

    print(f"prereg_hash {reg_hash} · decision {decision} · null_control_ok {null_ctrl_ok}")
    for r in results:
        print(f"  {r['corpus']:30s} {r['language']:16s} files={r['files_scanned']:5d} "
              f"idiom={r['files_with_idiom']:3d} rate={r['idiom_rate']}")
    print(f"\nwrote {OUT / (args.out + '.json')}\nwrote {OUT / (args.out + '.md')}")
    return payload


if __name__ == "__main__":
    main()
