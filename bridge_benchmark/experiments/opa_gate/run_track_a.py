#!/usr/bin/env python3
"""
run_track_a.py — Track A third-party prevalence test (NEW_EXP_OPA_GATE_2).

Do C-witnesses arise under policies we did NOT author? We sample Kubernetes Deployment-style manifests,
label them with the SET of UNMODIFIED Gatekeeper-library policies (Safe iff zero violations), extract a
typed return z=(s,x), and categorize R/C/U/A/B over B_{1,eps} using OPA as a black-box oracle. Two
splits: `natural` (prevalence) and `boundary` (small realistic mutations near a policy boundary). We do
NOT tune policy thresholds; we only vary the sampled manifests.

Primary outcome: C-prevalence under unmodified third-party policies. Expected (and informative either
way): pure Gatekeeper validation policies encode hard discrete constraints (allowedrepos, requiredlabels,
privileged) and fixed numeric limits (containerlimits) that are NOT provenance-conditioned, so the
joint-gap category C is typically absent — vulnerabilities are discrete-only (A) or continuous-only (B).
This contrasts with the authored provenance-conditioned Rego (Track C), where C ~ 10-12%.
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import random
import sys
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE / "scripts"))
sys.path.insert(0, str(_HERE))
from eval_gatekeeper import safe_batch, load_provenance  # noqa: E402
import methodology as M  # noqa: E402

OUT = _HERE.parents[1] / "cert" / "out" / "opa_gate"
_GK_DIR = _HERE / "policies" / "third_party" / "gatekeeper_library"


def corpus_rego_paths():
    """Every Rego file in the vendored Gatekeeper corpus (templates + libs) — the denominator of the
    two-stage prevalence funnel (NEW_EXPS_8 gap 1)."""
    return sorted(glob.glob(str(_GK_DIR / "*" / "policy.rego")) +
                  glob.glob(str(_GK_DIR / "*" / "lib_*.rego")))

# fixed (untuned) policy-set parameters
POLICY_PARAMS = {
    "allowedrepos": {"repos": ["registry.company.com/"]},
    "requiredlabels": {"labels": [{"key": "owner", "allowedRegex": "team-a|platform"}]},
    "containerlimits": {"cpu": "1", "memory": "2Gi"},          # cpu<=1000m, memory<=2048Mi
    "privileged": {},
    "hostnetworkports": {"hostNetwork": False, "min": 0, "max": 0},
}
# merged parameters (union): each vendored rule reads only the keys it needs and ignores the rest, so
# one request to the authored aggregate package covers the whole policy set.
MERGED_PARAMS = {k: v for p in POLICY_PARAMS.values() for k, v in p.items()}
# discrete fields (s) and their domains (some values comply, some violate a policy)
REGISTRY = ["registry.company.com/", "docker.io/", "gcr.io/"]   # only the 1st complies (allowedrepos)
OWNER = ["team-a", "platform", "team-b", "__none__"]            # team-a/platform comply (requiredlabels)
ENV = ["prod", "staging", "dev"]                               # no vendored policy uses env (inert)
PRIV = [False, True]                                           # True violates (privileged)
HOSTPORT = [0, 8080]                                           # >0 violates (hostnetworkports)
# numeric (x) normalization scales (eps/sigma live in normalized space, doc sec.5)
CPU_CAP, MEM_CAP = 2000.0, 4096.0                              # millicores, MiB


def _sample_z(rng, boundary):
    """Sample a typed return z=(s,x). `natural`: mostly compliant; `boundary`: numeric near the cpu/mem
    limit and discrete occasionally non-compliant."""
    if not boundary:
        s = {"registry": REGISTRY[0] if rng.random() < 0.93 else rng.choice(REGISTRY),
             "owner": OWNER[0] if rng.random() < 0.90 else rng.choice(OWNER),
             "env": rng.choice(ENV), "privileged": rng.random() < 0.03,
             "hostport": 0 if rng.random() < 0.96 else 8080}
        cpu = rng.uniform(200, 900); mem = rng.uniform(256, 1800)
    else:
        s = {"registry": rng.choice(REGISTRY), "owner": rng.choice(OWNER), "env": rng.choice(ENV),
             "privileged": rng.random() < 0.3, "hostport": rng.choice(HOSTPORT)}
        cpu = rng.uniform(850, 1150); mem = rng.uniform(1800, 2300)   # straddle the 1000m / 2048Mi limit
    x = {"cpu_limit_m": round(cpu, 1), "memory_limit_mib": round(mem, 1),
         "replicas": rng.randint(1, 5), "container_count": 1}
    return {"s": s, "x": x}


def review_from_z(z):
    """Build the Gatekeeper admission-review object from z (the only place z -> policy input)."""
    s, x = z["s"], z["x"]
    labels = {"env": s["env"]}
    if s["owner"] != "__none__":
        labels["owner"] = s["owner"]
    container = {"name": "c", "image": f"{s['registry']}app:v1",
                 "resources": {"limits": {"cpu": f"{int(round(x['cpu_limit_m']))}m",
                                          "memory": f"{int(round(x['memory_limit_mib']))}Mi"}},
                 "securityContext": {"privileged": bool(s["privileged"])}}
    if s["hostport"]:
        container["ports"] = [{"hostPort": int(s["hostport"]), "containerPort": 8080}]
    return {"object": {"kind": "Deployment", "metadata": {"name": "d", "labels": labels},
                       "spec": {"containers": [container]}}}


def _case(z):
    return {"review": review_from_z(z), "parameters": MERGED_PARAMS}


# discrete neighbors: change exactly one categorical field to another value — but ONLY along edges that
# carry a TM2 mechanism in the FROZEN registry (NEW_EXPS_8 gap 4). `env` is excluded (no vendored policy
# reads it and no mechanism re-binds it across a boundary), so it does not enter the neighborhood.
_REGISTERED_EDGES = M.registered_edge_fields(M.K8S_KEY)        # frozen, mechanism-tagged
_DISC_DOMAINS = {f: spec["values"] for f, spec in _REGISTERED_EDGES.items()}


def _disc_neighbors(z):
    out = []
    for f, dom in _DISC_DOMAINS.items():
        for v in dom:
            if v != z["s"][f]:
                z2 = {"s": dict(z["s"]), "x": dict(z["x"])}
                z2["s"][f] = v
                out.append(z2)
    return out


def _cont_worst(z, eps):
    """Continuous worst case in the eps-ball (normalized): push cpu and memory limits UP toward the
    containerlimits boundary (the unsafe direction), split across the 2 normalized coords."""
    z2 = {"s": dict(z["s"]), "x": dict(z["x"])}
    step = eps / (2 ** 0.5)
    z2["x"]["cpu_limit_m"] = z["x"]["cpu_limit_m"] + step * CPU_CAP
    z2["x"]["memory_limit_mib"] = z["x"]["memory_limit_mib"] + step * MEM_CAP
    return z2


def categorize(zs, eps):
    """All probe points for all manifests in ONE stateless opa eval batch (clean + d=1 discrete
    neighbors + continuous worst-case + joint), then assemble A/B/C/R/U via OPA verdicts."""
    cases, spans = [], []
    for z in zs:
        neigh = _disc_neighbors(z)
        zc = _cont_worst(z, eps)
        ci = len(cases); cases.append(_case(z))
        di = []
        for n in neigh:
            di.append(len(cases)); cases.append(_case(n))
        coi = len(cases); cases.append(_case(zc))
        ji = []
        for n in neigh:
            ji.append(len(cases)); cases.append(_case(_cont_worst(n, eps)))
        spans.append((ci, di, coi, ji))
    verdict = safe_batch(cases)
    out = []
    for (ci, di, coi, ji) in spans:
        clean = verdict[ci]
        disc_flip = any(verdict[k] != clean for k in di)
        cont_flip = verdict[coi] != clean
        joint_flip = any(verdict[k] != clean for k in ji)
        if not clean:
            cat = "U"
        elif disc_flip:
            cat = "A"
        elif cont_flip:
            cat = "B"
        elif joint_flip:
            cat = "C"
        else:
            cat = "R"
        out.append(cat)
    return out


def run_split(n, eps, seed, boundary):
    rng = random.Random(seed + (777 if boundary else 0))
    zs = [_sample_z(rng, boundary) for _ in range(n)]
    cats = categorize(zs, eps)
    c = Counter(cats)
    n = len(cats)
    return {"split": "boundary" if boundary else "natural", "n": n,
            **{f"{k}_pct": round(c.get(k, 0) / n, 4) for k in "RCUAB"},
            **{k: c.get(k, 0) for k in "RCUAB"}}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    prov = load_provenance()

    # --- Stage 1 of the prevalence funnel (NEW_EXPS_8 gap 1): does the corpus even CONTAIN the
    # provenance-conditioned-threshold idiom? files_with_idiom / files_scanned. ---
    funnel = M.scan_corpus_for_idiom(corpus_rego_paths())
    print(f"[P1 funnel] files_scanned={funnel['files_scanned']} files_with_idiom="
          f"{funnel['files_with_idiom']} idiom_rate={funnel['idiom_rate']}")
    with open(OUT / "track_a_funnel.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["file", "has_category_conditioned_threshold", "evidence"])
        w.writeheader()
        for pf in funnel["per_file"]:
            w.writerow({"file": pf["file"], "has_category_conditioned_threshold": pf["present"],
                        "evidence": ";".join(pf["evidence"])})

    rows = [run_split(args.n, args.eps, args.seed, False),
            run_split(args.n, args.eps, args.seed, True)]
    for r in rows:
        print(f"{r['split']:9s} n={r['n']} | R={r['R_pct']:.3f} C={r['C_pct']:.3f} U={r['U_pct']:.3f} "
              f"A={r['A_pct']:.3f} B={r['B_pct']:.3f}")

    # Stage 2: C-rate GIVEN the idiom. With idiom_rate=0 no corpus policy is idiom-positive, so the
    # corpus prevalence bound P(C|corpus) = idiom_rate x C_rate_given_idiom collapses to ~0 at stage 1
    # (not via the sampler). We report the measured C% on the sampled manifests directly as well.
    c_rate_given_idiom = float("nan")          # undefined: no idiom-positive policy in this corpus
    p_c_corpus_bound = round(funnel["idiom_rate"] * (max(rows[0]["C_pct"], rows[1]["C_pct"]) or 0.0), 6)

    cols = ["split", "n", "R_pct", "C_pct", "U_pct", "A_pct", "B_pct", "R", "C", "U", "A", "B"]
    with open(OUT / "track_a_third_party.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore"); w.writeheader(); w.writerows(rows)

    pol_list = ", ".join(f"{p['name']} (`{p['constraint_kind']}`, {p['kind']})" for p in prov["policies"])
    md = ["# Track A — third-party Gatekeeper-library prevalence test\n",
          f"Policies: **unmodified** `open-policy-agent/gatekeeper-library` @ commit `{prov['commit']}` "
          f"({prov['license']}): {pol_list}. Safe(z) iff the policy SET reports zero violations. "
          f"Manifests sampled (n={rows[0]['n']}/split, eps={args.eps}); **policy thresholds NOT tuned**, "
          "only manifests vary. Discrete neighborhood = the FROZEN mechanism-tagged registry "
          "(`discrete_neighborhoods.json`; `env` excluded — no mechanism). C-witnesses categorized via "
          "OPA as a black-box oracle.\n",
          "## Table P1 — two-stage prevalence funnel (NEW_EXPS_8 gap 1)\n",
          "The prevalence claim is a PRODUCT: `P(C | corpus) = idiom_rate(corpus) × "
          "C_rate_given_idiom`. Stage 1 asks whether the corpus even contains the "
          "provenance-conditioned-threshold idiom (a numeric threshold indexed by a categorical).\n",
          f"| stage | quantity | value |",
          "| --- | --- | --- |",
          f"| 1 | files scanned | {funnel['files_scanned']} |",
          f"| 1 | files with idiom (`has_category_conditioned_threshold`) | {funnel['files_with_idiom']} |",
          f"| 1 | **idiom_rate** | **{funnel['idiom_rate']}** |",
          f"| 2 | C_rate given idiom | {('n/a — no idiom-positive policy' if funnel['files_with_idiom']==0 else c_rate_given_idiom)} |",
          f"| ✕ | **P(C \\| corpus) bound = idiom_rate × C_rate** | **{p_c_corpus_bound}** |\n",
          "## Category distribution by sampling scheme\n",
          "| split | n | R% | **C%** | U% | A% | B% |",
          "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        md.append(f"| {r['split']} | {r['n']} | {r['R_pct']} | **{r['C_pct']}** | {r['U_pct']} | "
                  f"{r['A_pct']} | {r['B_pct']} |")
    c_nat, c_bnd = rows[0]["C_pct"], rows[1]["C_pct"]
    null = (c_nat < 0.02 and c_bnd < 0.02)
    md.append(
        "\n**Reading.** " + (
            f"C-prevalence is ~0 under unmodified third-party Gatekeeper policies (an **informative "
            f"null**), and Table P1 localizes WHY: the null is driven by **stage 1** — "
            f"`idiom_rate = {funnel['idiom_rate']}` (no vendored policy conditions a numeric threshold "
            f"on a categorical) — **not** by the sampler. The boundary scheme over-samples the policy "
            f"limits yet still yields C≈0 (only the discrete-only (A) and continuous-only (B) "
            f"vulnerabilities of hard validation constraints). " if null else
            f"C-witnesses arise under unmodified third-party policies (natural {c_nat:.3f}, boundary "
            f"{c_bnd:.3f}). ") +
        "The scientific statement: **C-witnesses require policies where discrete provenance shifts a "
        "numerical decision boundary** — exactly the idiom Table P1 measures the rate of. Pure "
        "Gatekeeper validation policies lack it; the authored provenance-conditioned Rego (Track C, "
        "`opa_gate_results.*`) supplies it (idiom_present=True) and yields C ~ 10-12%. Unmodified "
        "third-party policies give **prevalence evidence**; authored Rego gives **controlled mechanism "
        "evidence**. We do not tune third-party thresholds, the sampler is pre-registered (natural + "
        "boundary), and the discrete neighborhood is the frozen mechanism-tagged registry.\n")
    (OUT / "track_a_third_party.md").write_text("\n".join(md) + "\n")
    print(f"\nwrote -> {OUT/'track_a_third_party.csv'} / .md")


if __name__ == "__main__":
    main()
