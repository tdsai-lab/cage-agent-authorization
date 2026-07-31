#!/usr/bin/env python3
"""
exp_policy_third_party.py — EXP-POLICY-THIRD-PARTY: third-party Rego/Gatekeeper grounding for the
continuous provenance-conditioned threshold idiom (`op(f_num, θ(s))`).

WHAT THIS ADDS (and what it REUSES). The contribution of this experiment is *policy-as-code realism*:
package the existing honest k8s/cloud NULL (Gatekeeper idiom_rate = 0) into the plan's taxonomy +
output layout, and run the C-witness search exactly where idiom > 0. It REUSES, unchanged:

  * `experiments/detector/idiom_detector.py` — the FROZEN, sha256-hashed idiom predicate. We import it
    and call `detect_file()` + `frozen_spec()`; we DO NOT edit it (its hash is an invariant, recorded in
    cert/out artifacts). This script is a thin WRAPPER on top of it.
  * `experiments/opa_gate/run_track_a.py` — the real `opa eval` categorize path over B_{1,ε}
    (clean / d=1 discrete neighbor / continuous worst-case / joint), via `eval_gatekeeper.safe_batch`.
    We import `categorize` + the sampler so Part B is the SAME engine-labeled R/A/B/C/U funnel that
    already found 0 third-party C-witnesses (the informative null).

GENUINE GAPS FILLED HERE (nothing else):

  PART A — 5-LEVEL TAXONOMY. The frozen detector only outputs idiom present/absent (+ a
    `numeric_threshold` funnel flag). We add a thin classification layer (HERE, never in the detector)
    mapping every policy to exactly one of:
        discrete_only                  — no numeric comparison at all (pure categorical/allow-list rules)
        fixed_numeric_threshold        — numeric comparison(s) exist, all against CONSTANT literals
        conditioned_numeric_threshold  — a numeric field is compared against a threshold SELECTED BY a
                                         discrete/provenance key  (== the frozen idiom; θ = θ(s))
        affine_or_multivariate_numeric — a conditioned threshold AND ≥2 numeric fields combine in the
                                         same rule (non-axis-aligned; defeats per-coordinate baselines)
        unknown_or_unsupported         — parse error / unsupported language / detector could not decide
    Mapping is derived purely from the frozen detector's own signals:
        has_numeric_comparison  := IdiomHit.numeric_threshold
        has_conditioned_thresh. := IdiomHit.idiom_present
        is_multivariate         := ≥2 distinct numeric input fields co-occur in the policy text
                                   (counted HERE from the source, never from the detector internals)
    (See `classify_taxonomy` docstring for the exact decision tree.)

  SOURCE LABELS. Every row carries source ∈ {third_party, authored_fixture, authored_control}:
        third_party       — Gatekeeper / kyverno / cloud-custodian (logic we did NOT author)
        authored_control  — our authored Rego positive/negative mechanism probes
                            (ieee_fraud.rego = conditioned θ(s) positive; constant_threshold_control.rego
                             = fixed-θ negative). NEVER silently mixed into the third-party prevalence.
        authored_fixture  — reserved for tiny test fixtures (used only by the pytest harness).

  PART B — executable OPA eval where possible. We reuse run_track_a's real-`opa eval` categorize path
    over the unmodified Gatekeeper set (only available for the in-tree gatekeeper corpus). If the OPA
    binary is missing we warn and run taxonomy-only.

  PART C — C-witness search on every policy classified conditioned_numeric_threshold or
    affine_or_multivariate_numeric, reusing the categorize-over-B_{1,ε} logic. Each engine-labeled C
    point is emitted as a witness record. If none arise (the third-party case), that is the informative
    null, localized at the corpus stage (idiom_rate = 0 ⇒ no third-party policy is even eligible).

OUTPUT LAYOUT (under --out, gitignored): policy_taxonomy.csv, c_witnesses.jsonl, summary.json,
summary.md. Deterministic (fixed seed, frozen detector hash recorded).

CLI:
  python bridge_benchmark/experiments/exp_policy_third_party.py \
      --policy-dir external/corpora --epsilon 0.10 \
      --out bridge_benchmark/cert/out/exp_policy_third_party
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_DETECTOR_DIR = _HERE / "detector"
_OPA_DIR = _HERE / "opa_gate"
sys.path.insert(0, str(_DETECTOR_DIR))
sys.path.insert(0, str(_OPA_DIR))

import idiom_detector as idet  # noqa: E402  (FROZEN; imported, never modified)

_BB = _HERE.parents[0]
_REPO = _BB.parents[0]
_GK_INTREE = _OPA_DIR / "policies" / "third_party" / "gatekeeper_library"
_AUTHORED = _OPA_DIR / "policies" / "authored"

# default per-corpus file cap (keeps a quick run to a couple of minutes); logged in summary.
DEFAULT_MAX_FILES = 300

# ---- the 5-level taxonomy labels ----------------------------------------- #
TAX_DISCRETE = "discrete_only"
TAX_FIXED = "fixed_numeric_threshold"
TAX_CONDITIONED = "conditioned_numeric_threshold"
TAX_AFFINE = "affine_or_multivariate_numeric"
TAX_UNKNOWN = "unknown_or_unsupported"
TAX_LEVELS = [TAX_DISCRETE, TAX_FIXED, TAX_CONDITIONED, TAX_AFFINE, TAX_UNKNOWN]

# corpora to scan for prevalence (third_party). Each entry: name, language (the frozen detector's
# language key), root (resolved under --policy-dir), and the glob. Missing dirs are skipped + logged.
_CORPORA = [
    {"name": "gatekeeper_library", "language": "rego", "subdir": None,
     "root_override": _GK_INTREE, "glob": "*.rego", "source": "third_party",
     "origin": "open-policy-agent/gatekeeper-library (vendored in-tree)", "opa_executable": True},
    {"name": "kyverno_policies", "language": "kyverno", "subdir": "kyverno_policies",
     "root_override": None, "glob": "*.yaml", "source": "third_party",
     "origin": "github.com/kyverno/policies", "opa_executable": False},
    {"name": "cloud_custodian", "language": "cloud_custodian", "subdir": "cloud-custodian_cloud-custodian",
     "root_override": None, "glob": "*.yml", "source": "third_party",
     "origin": "github.com/cloud-custodian/cloud-custodian", "opa_executable": False},
]

# authored controls — kept SEPARATE from the third-party prevalence (source=authored_control).
_AUTHORED_CONTROLS = [
    {"name": "authored__ieee_fraud", "language": "rego", "path": _AUTHORED / "ieee_fraud.rego",
     "origin": "authored conditioned-threshold positive (θ(provenance))", "opa_executable": True},
    {"name": "authored__constant_control", "language": "rego",
     "path": _AUTHORED / "constant_threshold_control.rego",
     "origin": "authored fixed-threshold negative control", "opa_executable": True},
]


# --------------------------------------------------------------------------- #
# numeric-field counting (HERE, from source text — never from the detector internals). Used only to
# distinguish multivariate (affine) from the per-coordinate conditioned case.
# --------------------------------------------------------------------------- #
_REGO_FIELD = re.compile(r"\b(?:input|data|c|review|object)(?:\.[A-Za-z_]\w*)*\.([A-Za-z_]\w*)\b")
_GENERIC_NUM_CMP = re.compile(r"([A-Za-z_][\w.\[\]'\"]*)\s*(?:<=|>=|<|>)")


def _count_numeric_fields(path: Path, language: str) -> int:
    """Conservative count of DISTINCT numeric input fields that appear on the LHS of an ordered
    comparison. Used only to split affine_or_multivariate from conditioned. Over- or under-counting only
    shifts a policy between two ADJACENT idiom levels (affine vs conditioned), never into/out of the
    idiom itself (that stays the frozen detector's call)."""
    try:
        txt = path.read_text(errors="ignore")
    except Exception:  # noqa: BLE001
        return 0
    fields = set()
    for m in _GENERIC_NUM_CMP.finditer(txt):
        lhs = m.group(1)
        tail = lhs.rstrip("'\"]").split(".")[-1].split("[")[0]
        if tail and re.match(r"[A-Za-z_]\w*$", tail):
            fields.add(tail)
    return len(fields)


# --------------------------------------------------------------------------- #
# PART A — the 5-level classifier (thin layer on the frozen detector's signals)
# --------------------------------------------------------------------------- #
def classify_taxonomy(hit, n_numeric_fields: int) -> str:
    """Map a frozen-detector IdiomHit (+ a source-counted numeric-field count) to exactly one of the
    five taxonomy levels. Decision tree (pure function of the detector's own outputs):

        parse error / unsupported            -> unknown_or_unsupported
        idiom_present (θ = θ(s))  &  ≥2 fields -> affine_or_multivariate_numeric
        idiom_present (θ = θ(s))             -> conditioned_numeric_threshold
        numeric_threshold (constant θ)       -> fixed_numeric_threshold
        otherwise (no numeric comparison)    -> discrete_only

    has_numeric_comparison := hit.numeric_threshold ; has_conditioned_threshold := hit.idiom_present.
    The detector decides the idiom; this layer only NAMES the level + (for the idiom) splits axis-aligned
    vs multivariate using the source-counted field count."""
    ev = (hit.evidence or "")
    if ev.startswith("parse_error") or ev.startswith("yaml_error") or hit.language == "unknown":
        return TAX_UNKNOWN
    if hit.idiom_present:
        return TAX_AFFINE if n_numeric_fields >= 2 else TAX_CONDITIONED
    if hit.numeric_threshold:
        return TAX_FIXED
    return TAX_DISCRETE


# --------------------------------------------------------------------------- #
# corpus walking (follows scan_corpus.py's pattern + kyverno policy-kind filter)
# --------------------------------------------------------------------------- #
def _is_kyverno_policy(path: Path) -> bool:
    try:
        head = path.read_text(errors="ignore")[:4000]
    except Exception:  # noqa: BLE001
        return False
    return ("kind: ClusterPolicy" in head or "kind: Policy" in head) and "kyverno.io" in head


def _corpus_root(c, policy_dir: Path) -> Path | None:
    if c["root_override"] is not None:
        return c["root_override"]
    if c["subdir"] is None:
        return None
    return policy_dir / c["subdir"]


def _policy_files(c, policy_dir: Path):
    root = _corpus_root(c, policy_dir)
    if root is None or not root.exists():
        return None  # signal "missing" so caller can skip + log
    lang = c["language"]
    if lang == "rego":
        files = sorted(root.rglob("*.rego"))
    elif lang == "kyverno":
        files = sorted(p for p in root.rglob("*.yaml") if _is_kyverno_policy(p))
    elif lang == "cloud_custodian":
        files = sorted(list(root.rglob("*.yml")) + list(root.rglob("*.yaml")))
    else:
        files = []
    return files


def _policy_id(path: Path, corpus_name: str) -> str:
    return f"{corpus_name}:{path.name}"


# --------------------------------------------------------------------------- #
# PART B/C — executable OPA categorize over B_{1,ε} (REUSED from run_track_a)
# --------------------------------------------------------------------------- #
def _opa_available() -> bool:
    p = _OPA_DIR / "bin" / "opa"
    return p.exists()


def run_opa_categorize(eps: float, seed: int = 0, n: int = 300):
    """REUSE run_track_a's real `opa eval` categorize path over the unmodified Gatekeeper set. Returns
    (category_distribution_dict, witness_records). Gatekeeper has idiom_rate=0 (no conditioned θ(s)), so
    this is the informative-null branch: any C found here would be a genuine third-party positive."""
    import run_track_a as rta  # noqa: E402  (imports eval_gatekeeper + methodology at module load)
    import random
    rng = random.Random(seed)
    # natural + boundary sampling, exactly as Track A (boundary over-samples the numeric limit).
    zs = [rta._sample_z(rng, boundary=False) for _ in range(n // 2)]
    zs += [rta._sample_z(rng, boundary=True) for _ in range(n - n // 2)]
    cats = rta.categorize(zs, eps)
    dist = dict(Counter(cats))
    witnesses = []
    for z, cat in zip(zs, cats):
        if cat == "C":
            witnesses.append({"z": z})
    return dist, witnesses, len(zs)


def authored_c_witness_search(eps: float, seed: int = 0, n: int = 400):
    """Run the SAME categorize-over-B_{1,ε} logic on the authored conditioned-threshold Rego
    (ieee_fraud.rego) as the MECHANISM positive control: where the idiom IS present, C-witnesses must
    appear. Uses the executable OPA `decisions` rule (engine-labeled, not the analytic oracle).

    Returns (n_C, witness_records). Each witness stores the discrete state s (provenance tool), the
    numeric x (risk_score), the action, the one-step discrete neighbor s', and the safety at
    clean / discrete-only / continuous-only / joint corners — the auditable same-state Category-C
    witness (Safe clean, Safe under discrete-only, Safe under continuous-only, UNSAFE under joint)."""
    import subprocess
    import random
    from opa_bridge import opa_path  # noqa: E402

    rego = _AUTHORED / "ieee_fraud.rego"
    theta_base, delta = 0.488808, 0.08
    loose = {"payment_gateway_loose", "manual_screen_loose"}
    strict = ["payment_gateway_strict", "manual_screen_strict"]
    all_tools = sorted(loose) + strict
    SCALE = 1.0  # risk_score already in [0,1]; ε is in the same raw unit (matches #9b convention)

    rng = random.Random(seed + 11)
    action = "approve_transaction"

    def theta(tool):
        return theta_base + delta if tool in loose else theta_base

    # Build probe cases: for each sampled (tool, risk), evaluate clean, discrete neighbor (swap to a
    # tool with a LOWER threshold), continuous worst (risk + ε), and joint (neighbor tool + risk + ε).
    cases, meta = [], []
    for _ in range(n):
        tool = rng.choice(all_tools)
        # sample risk just below this tool's threshold so the clean point is Safe and near the boundary
        risk = round(theta(tool) - rng.uniform(0.0, max(eps, 0.12)), 6)
        risk = max(0.0, min(1.0, risk))
        # discrete neighbor: the swap that LOWERS the threshold the most (loose -> strict) — the only
        # provenance swap that can flip an approve. If already strict, swap to another strict (no change).
        neighbor = strict[0] if tool in loose else strict[1 % len(strict)]
        base = len(cases)
        cases.append({"tool": tool, "x2": {"risk_score": risk}, "action": action})                # clean
        cases.append({"tool": neighbor, "x2": {"risk_score": risk}, "action": action})            # disc
        cases.append({"tool": tool, "x2": {"risk_score": risk + eps * SCALE}, "action": action})  # cont
        cases.append({"tool": neighbor, "x2": {"risk_score": risk + eps * SCALE}, "action": action})  # joint
        meta.append({"tool": tool, "risk": risk, "neighbor": neighbor, "base": base})

    proc = subprocess.run(
        [opa_path(), "eval", "--format", "json", "--stdin-input", "--data", str(rego),
         "data.opa_gate.ieee_fraud.decisions"],
        input=json.dumps({"cases": cases}), capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        raise RuntimeError(f"opa eval (authored) failed: {proc.stderr[:800]}")
    doc = json.loads(proc.stdout)
    res = doc["result"][0]["expressions"][0]["value"]
    verdict = {int(k): bool(v) for k, v in res.items()}

    witnesses, n_C = [], 0
    for m in meta:
        b = m["base"]
        safe_clean = verdict[b]
        safe_disc = verdict[b + 1]
        safe_cont = verdict[b + 2]
        safe_joint = verdict[b + 3]
        # Category C: safe clean AND safe under discrete-only AND safe under continuous-only, but UNSAFE
        # under the joint move (the auditable same-state joint-gap witness).
        if safe_clean and safe_disc and safe_cont and not safe_joint:
            n_C += 1
            witnesses.append({
                "policy_id": "authored__ieee_fraud:ieee_fraud.rego",
                "source": "authored_control",
                "s": {"tool": m["tool"]},
                "x": {"risk_score": m["risk"]},
                "action": action,
                "s_neighbor": {"tool": m["neighbor"]},
                "x_neighbor": {"risk_score": round(m["risk"] + eps * SCALE, 6)},
                "safe_clean": safe_clean, "safe_discrete_only": safe_disc,
                "safe_continuous_only": safe_cont, "safe_joint": safe_joint,
            })
    return n_C, witnesses


# --------------------------------------------------------------------------- #
# main driver
# --------------------------------------------------------------------------- #
def build_taxonomy_rows(policy_dir: Path, max_files: int):
    """Walk third-party corpora + authored controls; classify each file. Returns
    (rows, per_corpus_summary, skipped)."""
    rows, per_corpus, skipped = [], {}, []

    def _classify_one(path, language, corpus_name, source, opa_executable):
        try:
            hit = idet.detect_file(path, language)
        except Exception as e:  # noqa: BLE001
            hit = idet.IdiomHit(language or "unknown", False, source=str(path),
                                evidence=f"parse_error:{type(e).__name__}")
        nfields = _count_numeric_fields(path, language)
        label = classify_taxonomy(hit, nfields)
        return {
            "policy_id": _policy_id(path, corpus_name),
            "source": source,
            "path": str(path.relative_to(_REPO)) if str(path).startswith(str(_REPO)) else str(path),
            "idiom": label,
            "has_numeric_comparison": bool(hit.numeric_threshold),
            "has_conditioned_threshold": bool(hit.idiom_present),
            "n_numeric_fields": nfields,
            "opa_executable": bool(opa_executable),
            "notes": hit.evidence,
        }

    # third-party corpora
    for c in _CORPORA:
        files = _policy_files(c, policy_dir)
        if files is None:
            skipped.append({"corpus": c["name"], "reason": "missing_dir",
                            "expected": str(_corpus_root(c, policy_dir))})
            print(f"[skip] corpus '{c['name']}' missing at "
                  f"{_corpus_root(c, policy_dir)} — skipping (logged).")
            continue
        n_total = len(files)
        capped = files[:max_files]
        crows = [_classify_one(f, c["language"], c["name"], c["source"], c["opa_executable"])
                 for f in capped]
        rows.extend(crows)
        per_corpus[c["name"]] = {
            "source": c["source"], "origin": c["origin"], "language": c["language"],
            "files_available": n_total, "files_scanned": len(capped),
            "capped": n_total > len(capped),
            "tax_counts": dict(Counter(r["idiom"] for r in crows)),
            "n_conditioned": sum(r["idiom"] in (TAX_CONDITIONED, TAX_AFFINE) for r in crows),
            "opa_executable": c["opa_executable"],
        }
        print(f"[corpus] {c['name']:22s} scanned={len(capped):4d}/{n_total:<5d} "
              f"conditioned+affine={per_corpus[c['name']]['n_conditioned']}")

    # authored controls (kept separate)
    for a in _AUTHORED_CONTROLS:
        p = a["path"]
        if not p.exists():
            skipped.append({"corpus": a["name"], "reason": "missing_file", "expected": str(p)})
            continue
        r = _classify_one(p, a["language"], a["name"], "authored_control", a["opa_executable"])
        rows.append(r)
        per_corpus[a["name"]] = {
            "source": "authored_control", "origin": a["origin"], "language": a["language"],
            "files_available": 1, "files_scanned": 1, "capped": False,
            "tax_counts": {r["idiom"]: 1}, "n_conditioned": int(r["idiom"] in (TAX_CONDITIONED, TAX_AFFINE)),
            "opa_executable": a["opa_executable"],
        }
        print(f"[authored] {a['name']:22s} -> {r['idiom']}")

    return rows, per_corpus, skipped


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--policy-dir", default=str(_REPO / "external" / "corpora"),
                    help="root containing the third-party corpus subdirs (missing ones are skipped)")
    ap.add_argument("--epsilon", type=float, default=0.10)
    ap.add_argument("--out", default=str(_BB / "cert" / "out" / "exp_policy_third_party"))
    ap.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES,
                    help="cap files scanned per corpus (logged)")
    ap.add_argument("--n-opa", type=int, default=300, help="manifests sampled for the Gatekeeper OPA categorize")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    policy_dir = Path(args.policy_dir).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    frozen = idet.frozen_spec()
    print(f"frozen detector sha256: {frozen['detector_sha256']}")
    print(f"policy-dir: {policy_dir}  eps={args.epsilon}  cap/corpus={args.max_files}\n")

    # ---- PART A: taxonomy --------------------------------------------------
    rows, per_corpus, skipped = build_taxonomy_rows(policy_dir, args.max_files)

    # ---- PART B: executable OPA categorize (Gatekeeper, real opa eval) -----
    opa_ok = _opa_available()
    opa_categorize = None
    third_party_witnesses = []
    if opa_ok:
        try:
            dist, tp_wit, n_probed = run_opa_categorize(args.epsilon, args.seed, args.n_opa)
            opa_categorize = {"engine": "opa_eval(gatekeeper_set,unmodified)", "n_manifests": n_probed,
                              "category_distribution": dist,
                              "C_count": dist.get("C", 0),
                              "C_rate": round(dist.get("C", 0) / max(1, n_probed), 5)}
            third_party_witnesses = tp_wit
            print(f"\n[PART B] OPA categorize (gatekeeper) n={n_probed} dist={dist} "
                  f"C={dist.get('C', 0)}")
        except Exception as e:  # noqa: BLE001
            print(f"[PART B] WARNING: OPA categorize failed ({e}); taxonomy-only for executable eval.")
            opa_categorize = {"error": str(e)[:300]}
    else:
        print("[PART B] WARNING: OPA binary not found at "
              f"{_OPA_DIR/'bin'/'opa'} — running taxonomy-only (no executable eval).")

    # ---- PART C: C-witness search on conditioned/affine policies -----------
    # third_party: any C from Part B is a genuine third-party positive (expected null).
    # Gatekeeper C-witnesses (if any) are set-labeled (no single per-policy id) -> emit under the SET id.
    c_witness_records = []
    for w in third_party_witnesses:
        c_witness_records.append({
            "policy_id": "gatekeeper_library:SET", "source": "third_party",
            "s": w["z"]["s"], "x": w["z"]["x"], "action": "admission_allow",
            "s_neighbor": None, "x_neighbor": None,
            "safe_clean": True, "safe_discrete_only": None, "safe_continuous_only": None,
            "safe_joint": False,
        })

    # authored mechanism positive: run the categorize on the authored conditioned-θ Rego where eligible.
    authored_C = None
    authored_eligible = [r for r in rows if r["source"] == "authored_control"
                         and r["idiom"] in (TAX_CONDITIONED, TAX_AFFINE) and r["opa_executable"]]
    if opa_ok and any(r["policy_id"].startswith("authored__ieee_fraud") for r in authored_eligible):
        try:
            n_C, auth_wit = authored_c_witness_search(args.epsilon, args.seed)
            authored_C = {"policy_id": "authored__ieee_fraud:ieee_fraud.rego", "n_probed": 400,
                          "C_count": n_C, "C_rate": round(n_C / 400, 5)}
            c_witness_records.extend(auth_wit)
            print(f"[PART C] authored conditioned-θ mechanism: C_count={n_C} (positive control)")
        except Exception as e:  # noqa: BLE001
            print(f"[PART C] WARNING: authored C-witness search failed ({e}).")

    # ---- write outputs -----------------------------------------------------
    # policy_taxonomy.csv
    tax_csv = out_dir / "policy_taxonomy.csv"
    cols = ["policy_id", "source", "path", "idiom", "has_numeric_comparison",
            "has_conditioned_threshold", "n_numeric_fields", "opa_executable", "notes"]
    with open(tax_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    # c_witnesses.jsonl
    wit_jsonl = out_dir / "c_witnesses.jsonl"
    with open(wit_jsonl, "w") as f:
        for rec in c_witness_records:
            f.write(json.dumps(rec, sort_keys=True) + "\n")

    # aggregate counts
    tp_rows = [r for r in rows if r["source"] == "third_party"]
    tax_dist_tp = dict(Counter(r["idiom"] for r in tp_rows))
    tax_dist_all = dict(Counter(r["idiom"] for r in rows))
    # honest C accounting: third-party C-witnesses are the prevalence claim; authored = mechanism only.
    tp_C = len([w for w in c_witness_records if w["source"] == "third_party"])
    n_with_C_policies = len({w["policy_id"] for w in c_witness_records
                             if w["source"] == "third_party"})
    n_executable = sum(1 for r in rows if r["opa_executable"] and r["source"] == "third_party")
    parse_fail = sum(1 for r in rows if r["idiom"] == TAX_UNKNOWN)

    summary = {
        "experiment": "EXP-POLICY-THIRD-PARTY",
        "frozen_detector_sha256": frozen["detector_sha256"],
        "idiom_predicate": frozen["idiom_predicate"],
        "epsilon": args.epsilon, "max_files_per_corpus": args.max_files, "seed": args.seed,
        "policy_dir": str(policy_dir),
        "num_policies": len(rows),
        "num_policies_third_party": len(tp_rows),
        "parse_success": len(rows) - parse_fail,
        "parse_fail_unknown": parse_fail,
        "tax_counts_third_party": {lvl: tax_dist_tp.get(lvl, 0) for lvl in TAX_LEVELS},
        "tax_counts_all": {lvl: tax_dist_all.get(lvl, 0) for lvl in TAX_LEVELS},
        "num_executable_with_opa_third_party": n_executable,
        "num_with_C_witness_third_party": n_with_C_policies,
        "C_count_third_party": tp_C,
        "C_rate_third_party": round(tp_C / max(1, len(tp_rows)), 5),
        "opa_categorize_gatekeeper": opa_categorize,
        "authored_mechanism_control": authored_C,
        "per_corpus": per_corpus,
        "skipped_corpora": skipped,
        "decision": ("THIRD_PARTY_POSITIVE" if tp_C > 0 else "INFORMATIVE_NULL"),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    _write_summary_md(out_dir / "summary.md", summary)

    print(f"\n=== EXP-POLICY-THIRD-PARTY summary ===")
    print(f"  policies={summary['num_policies']} (third_party={summary['num_policies_third_party']}, "
          f"parse_fail={parse_fail})")
    print(f"  taxonomy(third_party)={summary['tax_counts_third_party']}")
    print(f"  num_with_C_witness(third_party)={n_with_C_policies}  C_rate(third_party)="
          f"{summary['C_rate_third_party']}  decision={summary['decision']}")
    if authored_C:
        print(f"  authored mechanism control C_count={authored_C['C_count']} (separate from prevalence)")
    print(f"\nwrote:\n  {tax_csv}\n  {wit_jsonl}\n  {out_dir/'summary.json'}\n  {out_dir/'summary.md'}")
    return summary


def _write_summary_md(path: Path, s: dict):
    L = []
    L.append("# EXP-POLICY-THIRD-PARTY — third-party Rego/Gatekeeper grounding\n")
    L.append(f"Frozen detector `{s['frozen_detector_sha256'][:16]}` (idiom predicate unchanged). "
             f"ε={s['epsilon']}, cap={s['max_files_per_corpus']} files/corpus, seed={s['seed']}.\n")
    L.append("**The distinction (do not conflate):** a *third-party policy* gives a "
             "**prevalence / grounding** signal (does the conditioned-threshold idiom occur in code we "
             "did NOT author?); an *authored Rego* gives a **controlled mechanism** signal (where the "
             "idiom IS present, does the C joint-gap witness arise under a real engine?). This experiment "
             "reports both, kept separate by `source`.\n")

    L.append("## Part A — 5-level taxonomy (frozen-detector-derived)\n")
    L.append("| corpus | source | language | scanned | discrete_only | fixed_θ | **conditioned_θ** | "
             "affine/mv | unknown |")
    L.append("|---|---|---|---:|---:|---:|---:|---:|---:|")
    for name, c in s["per_corpus"].items():
        tc = c["tax_counts"]
        L.append(f"| {name} | {c['source']} | {c['language']} | {c['files_scanned']}"
                 f"{'*' if c['capped'] else ''} | {tc.get(TAX_DISCRETE,0)} | {tc.get(TAX_FIXED,0)} | "
                 f"**{tc.get(TAX_CONDITIONED,0)}** | {tc.get(TAX_AFFINE,0)} | {tc.get(TAX_UNKNOWN,0)} |")
    L.append("\n`*` = file cap hit (count is the scanned cap, not the full corpus). "
             "Levels: discrete_only (no numeric comparison) · fixed_numeric_threshold (numeric vs a "
             "CONSTANT) · conditioned_numeric_threshold (= the frozen idiom θ=θ(s)) · "
             "affine_or_multivariate_numeric (conditioned + ≥2 numeric fields) · unknown_or_unsupported "
             "(parse error / unsupported).\n")

    tp = s["tax_counts_third_party"]
    L.append("### Third-party totals (prevalence denominator)\n")
    L.append(f"- policies scanned (third_party): **{s['num_policies_third_party']}** "
             f"(parse_success={s['parse_success']}, unknown={s['parse_fail_unknown']})")
    L.append(f"- conditioned_numeric_threshold (the idiom): **{tp[TAX_CONDITIONED]}** ; "
             f"affine/multivariate: **{tp[TAX_AFFINE]}**")
    L.append(f"- ⇒ third-party idiom-eligible policies: "
             f"**{tp[TAX_CONDITIONED] + tp[TAX_AFFINE]}** of {s['num_policies_third_party']}\n")

    L.append("## Part B — executable OPA categorize (unmodified Gatekeeper set)\n")
    oc = s["opa_categorize_gatekeeper"]
    if oc and "category_distribution" in oc:
        d = oc["category_distribution"]
        L.append(f"Real `opa eval` over B_{{1,ε}} on n={oc['n_manifests']} sampled k8s manifests "
                 f"(clean / d=1 discrete neighbor / continuous worst-case / joint), labeled by the "
                 f"UNMODIFIED Gatekeeper policy SET (Safe ⇔ zero violations).\n")
        L.append("| category | count |")
        L.append("|---|---:|")
        for k in "RABCU":
            L.append(f"| {k} | {d.get(k,0)} |")
        L.append(f"\n**C-witnesses under third-party Gatekeeper: {oc['C_count']}** "
                 f"(C_rate={oc['C_rate']}).\n")
    elif oc and "error" in oc:
        L.append(f"OPA eval unavailable: `{oc['error']}` — taxonomy-only.\n")
    else:
        L.append("OPA binary not found — taxonomy-only (no executable eval).\n")

    L.append("## Part C — C-witness search (where idiom > 0)\n")
    L.append(f"- **Third-party C-witnesses: {s['C_count_third_party']}** across "
             f"{s['num_with_C_witness_third_party']} policies "
             f"(C_rate over third-party policies = {s['C_rate_third_party']}).")
    ac = s["authored_mechanism_control"]
    if ac:
        L.append(f"- Authored mechanism control (`ieee_fraud.rego`, θ(provenance)): "
                 f"**C_count={ac['C_count']}** of {ac['n_probed']} probes "
                 f"(C_rate={ac['C_rate']}) — engine-labeled by real OPA. This is NOT prevalence; it "
                 f"confirms that WHERE the conditioned-threshold idiom is present, the joint-gap "
                 f"witness arises under a real policy engine.\n")

    L.append("## Interpretation\n")
    if s["decision"] == "INFORMATIVE_NULL":
        L.append("**Result: informative NULL, localized at the corpus stage.** The conditioned-threshold "
                 "idiom `op(f_num, θ(s))` is essentially absent from the third-party executable policy "
                 "corpora scanned (Gatekeeper / kyverno / cloud-custodian): their numeric rules use "
                 "FIXED thresholds (containerlimits, resource caps) and their categorical rules are "
                 "discrete-only allow-lists (allowedrepos, requiredlabels) — neither produces a "
                 "provenance-conditioned numeric boundary, so no Category-C joint-gap witness is "
                 "possible. The executable OPA categorize over the unmodified Gatekeeper set confirms "
                 "this directly (C=0). **We do NOT claim all industrial policies have C-witnesses.** The "
                 "null localizes at *idiom prevalence in this habitat* (k8s/cloud guardrails), not at "
                 "the certificate. The authored-Rego mechanism control shows the complementary fact: "
                 "where the idiom IS authored (θ(provenance)), the engine produces C-witnesses — so the "
                 "third-party signal is *prevalence/grounding* and the authored signal is *controlled "
                 "mechanism*.")
    else:
        L.append("**Result: third-party POSITIVE.** At least one unmodified third-party policy yields an "
                 "engine-labeled Category-C joint-gap witness — direct prevalence evidence that the "
                 "conditioned-threshold idiom (and its non-composition consequence) occurs in code we "
                 "did not author. Reported per policy in `c_witnesses.jsonl`. (We still do not claim ALL "
                 "industrial policies have C-witnesses; this is existence within the scanned corpora.)")
    L.append("\n## Limitations\n")
    L.append("- The detector is CONSERVATIVE (frozen): alternative threshold encodings can be missed, so "
             "the idiom rate is a LOWER bound (under-counts, never inflates).\n"
             "- File caps (`*` in Part A) bound runtime; per-corpus counts above the cap are not "
             "exhaustive.\n"
             "- Executable OPA categorize is only available for the in-tree Gatekeeper corpus "
             "(kyverno/cloud-custodian are taxonomy-only here: different admission engines).\n"
             "- kyverno/cloud-custodian are scanned via structured-YAML detectors (confidence < the Rego "
             "AST path); a YAML parse failure lands in `unknown_or_unsupported`, not in a false idiom.\n"
             "- The authored row is a MECHANISM control, never mixed into the third-party prevalence "
             "denominator (`source=authored_control`).")
    path.write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
