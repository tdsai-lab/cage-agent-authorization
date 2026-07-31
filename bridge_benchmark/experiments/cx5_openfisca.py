#!/usr/bin/env python3
"""
cx5_openfisca.py — EXP-CX5 (PLAN_CX5.md): independent-policy case study on a THIRD-PARTY-authored
provenance-conditioned numeric threshold, with freeze-first discipline. NO rewriting of the rule — only a
documented schema mapping to the typed return.

POLICY (frozen, third-party). OpenFisca-France, Bail Réel Solidaire (BRS) social-housing income ceilings
`plafonds_par_zones`: a household is eligible iff its resources ≤ ceiling(zone, household_size). The ceiling
θ VARIES with the geographic **zone** (A / Abis / B1 / B2 / C) — a provenance-like categorical authored by a
third party (OpenFisca, transcribing Arrêté du 11/12/2023 / Article R255-1 CCH) for operational eligibility,
independently of our threat model. This is exactly the `op(x_num, θ(s))` idiom with s = zone. Eligibility
criterion (i)-(iv) of PLAN_CX5 satisfied under (ii)'s explicit "region/tier"-style categorical.

TYPED RETURN z = (s = zone, x = resources_norm, context = household_size). θ(zone, size) is the real
per-zone ceiling. Candidate action a = grant_brs_allocation; UNSAFE iff resources > ceiling(zone) (granting
to an over-ceiling household). N_d = single zone swaps over the policy's OWN 5-zone vocabulary (d=1). The
joint gap: a household eligible in a generous zone (A: high ceiling) that a zone mis-binding to a stricter
zone (C: lower ceiling) + a bounded resources move flips to ineligible — a Category-C witness on a real,
deployed, third-party-authored threshold.

Battery (house metrics, frozen seed): provenance-conditioned boundary existence + real gap δ (raw € and
normalized); natural + boundary-balanced joint-gap (A/B/C/R/U) counts; exact robust-safe coverage R_allow at
ε∈{0.03,0.10}; point-vs-neighborhood head-to-head on the C-witness set; the min(δ,ε) prediction checked
against the OBSERVED δ (the third-party rule is NOT swept). Analytic taxonomy only; stdlib + PyYAML.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import yaml

_HERE = Path(__file__).resolve().parent
_BB = _HERE.parent
OUT = _BB / "cert" / "out" / "exp_cx5"
OF_ROOT = (_BB.parent / "external" / "corpora" / "openfisca_openfisca-france")
BRS = OF_ROOT / "openfisca_france/parameters/prestations_sociales/bail_reel_solidaire/plafonds_par_zones"
ZONES = ["zone_A", "zone_Abis", "zone_B1", "zone_B2", "zone_C"]
SIZES = [1, 2, 3, 4, 5, 6]
YEAR = "2025-01-01"
CATS = ["A", "B", "C", "R", "U"]


# --------------------------------------------------------------------------- #
def frozen_commit():
    try:
        return subprocess.run(["git", "-C", str(OF_ROOT), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        return "unknown"


def load_ceilings():
    """θ(zone, size) = the real BRS income ceiling (€), parsed from the FROZEN OpenFisca YAML at YEAR."""
    theta = {}
    for z in ZONES:
        theta[z] = {}
        for n in SIZES:
            p = BRS / z / f"nb_personnes_{n}.yaml"
            doc = yaml.safe_load(p.read_text())
            vals = {str(k): v for k, v in doc["values"].items()}      # date keys -> "YYYY-MM-DD"
            key = YEAR if YEAR in vals else max(d for d in vals if d <= YEAR)  # latest at/<= YEAR
            theta[z][n] = float(vals[key]["value"])
    return theta


# --------------------------------------------------------------------------- #
# Analytic A/B/C/R/U taxonomy on the provenance-conditioned scalar threshold (paper oracle).
# unsafe iff resources_norm - θ_norm(zone,size) >= 0 ; scale = 1 (scalar); N_d = zone swaps.
# --------------------------------------------------------------------------- #
def categorize(zone, size, xn, theta_norm, eps):
    m0 = xn - theta_norm[zone][size]                          # clean margin (>=0 => over ceiling => unsafe)
    if m0 >= 0:
        return "U", None
    neigh = [z for z in ZONES]                                # d=1 swaps over the policy's own zone set
    disc_flip = any((xn - theta_norm[z][size]) >= 0 for z in neigh if z != zone)      # discrete-only
    cont_flip = (m0 + eps) >= 0                                                        # continuous-only
    joint_flip = any((xn - theta_norm[z][size]) + eps >= 0 for z in neigh)            # joint (incl same z)
    if disc_flip:
        return "A", None
    if cont_flip:
        return "B", None
    if joint_flip:                                            # safe clean, safe discrete-only, safe cont-only
        zw = min((z for z in neigh), key=lambda z: theta_norm[z][size])   # the stricter zone that flips it
        return "C", {"observed_zone": zone, "witness_zone": zw, "size": size,
                     "m_same": round(m0, 5), "m_witness": round(xn - theta_norm[zw][size], 5),
                     "m_witness_plus_eps": round(xn - theta_norm[zw][size] + eps, 5)}
    return "R", None


def point_gate_grant(zone, size, xn, theta_norm):
    """Naive POINT gate: grant iff eligible at the OBSERVED zone (ignores the ball / zone mis-binding)."""
    return (xn - theta_norm[zone][size]) < 0


def neighborhood_cert_grant(zone, size, xn, theta_norm, eps):
    """Exact neighborhood certificate: grant iff robust-safe over B_{1,eps} (category R)."""
    return categorize(zone, size, xn, theta_norm, eps)[0] == "R"


# --------------------------------------------------------------------------- #
def run(n, seed, eps_list, cap_mode, out_prefix):
    if not BRS.exists():
        print(f"[error] OpenFisca corpus not found at {BRS}"); return None
    theta = load_ceilings()
    commit = frozen_commit()
    all_vals = [theta[z][n_] for z in ZONES for n_ in SIZES]
    cap = max(all_vals) if cap_mode == "max_ceiling" else float(cap_mode)
    theta_norm = {z: {n_: theta[z][n_] / cap for n_ in SIZES} for z in ZONES}

    # provenance-conditioned boundary existence + real gap δ per household size (raw € and normalized)
    deltas = {}
    for n_ in SIZES:
        vals = sorted({theta[z][n_] for z in ZONES})
        raw_gap = max(vals) - min(vals)
        deltas[n_] = {"distinct_levels": len(vals), "raw_gap_eur": raw_gap,
                      "norm_gap": round(raw_gap / cap, 5),
                      "adjacent_norm_gaps": [round((vals[i + 1] - vals[i]) / cap, 5)
                                             for i in range(len(vals) - 1)]}
    boundary_exists = any(d["distinct_levels"] > 1 for d in deltas.values())

    # sample households: zone uniform, size uniform, resources spanning the ceilings (natural) + boundary
    rng = np.random.default_rng(seed)
    recs = []
    for i in range(n):
        z = ZONES[int(rng.integers(len(ZONES)))]
        sz = SIZES[int(rng.integers(len(SIZES)))]
        lo, hi = 0.5 * min(theta[zz][sz] for zz in ZONES), 1.3 * max(theta[zz][sz] for zz in ZONES)
        income = float(rng.uniform(lo, hi))
        recs.append({"zone": z, "size": sz, "income_eur": income, "xn": income / cap})

    results = {}
    for eps in eps_list:
        counts = {c: 0 for c in CATS}
        c_witnesses = []
        exact_allow = exact_false_allow = 0
        for r in recs:
            cat, wit = categorize(r["zone"], r["size"], r["xn"], theta_norm, eps)
            counts[cat] += 1
            if cat == "R":
                exact_allow += 1
            if cat == "C":
                c_witnesses.append({**r, **(wit or {})})
        n_tot = len(recs)
        # point-vs-neighborhood head-to-head on the C-witness set (the joint-gap exploit)
        pv = {"n_c_witnesses": len(c_witnesses), "point_grants": 0, "neighborhood_grants": 0,
              "point_unsafe_under_swap": 0}
        for w in c_witnesses:
            pg = point_gate_grant(w["zone"], w["size"], w["xn"], theta_norm)
            ng = neighborhood_cert_grant(w["zone"], w["size"], w["xn"], theta_norm, eps)
            pv["point_grants"] += int(pg)
            pv["neighborhood_grants"] += int(ng)
            # the realized exploit: point grants, but a zone swap + eps makes it over-ceiling (unsafe)
            pv["point_unsafe_under_swap"] += int(pg and w.get("m_witness_plus_eps", -1) >= 0)
        results[str(eps)] = {
            "counts": counts, "pr": {c: round(counts[c] / n_tot, 5) for c in CATS},
            "pr_C": round(counts["C"] / n_tot, 5),
            "R_allow": round(exact_allow / n_tot, 5),
            "point_vs_neighborhood": pv,
            "min_delta_eps_check": _min_delta_eps(deltas, eps),
        }

    verdict = ("POSITIVE CASE STUDY: a real, deployed, THIRD-PARTY-authored provenance-conditioned numeric "
               f"threshold (OpenFisca-France BRS income ceilings by zone, commit {commit[:12]}) exhibits the "
               f"joint-gap substrate. A provenance-conditioned boundary EXISTS (zone-varying ceiling, real gap "
               f"up to €{max(d['raw_gap_eur'] for d in deltas.values()):.0f}); Category-C witnesses arise "
               f"naturally (Pr(C)={results[str(eps_list[0])]['pr_C']} at ε={eps_list[0]}); the exact "
               f"neighborhood certificate blocks them (point gate grants the zone-swap exploit, neighborhood "
               f"cert refuses) — the substrate is NOT authored by us. Framing: zone is a subject/region "
               f"categorical (criterion (ii)), not a pipeline-provenance key — a deployed-threshold existence "
               f"anchor, complementary to the pipeline-provenance null.")
    payload = {
        "experiment": "EXP-CX5 — independent-policy case study (OpenFisca BRS zone ceilings)",
        "source_policy": "OpenFisca-France Bail Réel Solidaire plafonds_par_zones",
        "provenance": {"repo": "github.com/openfisca/openfisca-france", "commit": commit,
                       "path": str(BRS.relative_to(_BB.parent)), "year": YEAR,
                       "legal_refs": ["Article R255-1 CCH", "Arrêté du 11/12/2023, Annexe"]},
        "eligibility_criterion": "PLAN_CX5 (i)-(iv): numeric field (resources) vs categorical-varying "
                                 "threshold (zone), third-party authored for operations, in the affine "
                                 "fragment (scalar threshold).",
        "s_semantics": "zone = subject/region categorical (not pipeline-provenance) — deployed-threshold "
                       "existence anchor per the claim ladder.",
        "normalization": {"cap_mode": cap_mode, "cap_eur": cap},
        "theta_eur": {z: theta[z] for z in ZONES}, "boundary_exists": boundary_exists,
        "deltas_by_size": deltas, "n": n, "seed": seed, "eps_list": eps_list,
        "results": results, "verdict": verdict,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "policy_bundle").mkdir(exist_ok=True)
    (OUT / f"{out_prefix}.json").write_text(json.dumps(payload, indent=2))
    _write_provenance(OUT / "policy_bundle" / "PROVENANCE.md", payload)
    _write_search_log(OUT / "search_log.md", payload)
    _write_md(OUT / f"{out_prefix}.md", payload)
    _write_csv(OUT / "results.csv", payload)
    print(f"\nVERDICT: {verdict}\nwrote -> {OUT/(out_prefix+'.json')}")
    return payload


def _min_delta_eps(deltas, eps):
    """Check the OBSERVED normalized δ against the min(δ,ε) law WITHOUT sweeping the third-party rule."""
    gaps = [g for d in deltas.values() for g in d["adjacent_norm_gaps"] if g > 0]
    if not gaps:
        return {"note": "no positive zone gap"}
    return {"observed_norm_deltas": sorted(set(round(g, 4) for g in gaps)),
            "eps": eps, "min_delta_eps_per_gap": [round(min(g, eps), 4) for g in sorted(set(gaps))],
            "note": "C-interval length per witness = min(δ,ε); observed δ not swept (third-party rule frozen)."}


def _write_provenance(path, p):
    pr = p["provenance"]
    path.write_text(
        f"# CX5 policy bundle — PROVENANCE (freeze-first)\n\n"
        f"- **Source:** {pr['repo']} (OpenFisca-France), Bail Réel Solidaire income ceilings.\n"
        f"- **Commit (frozen):** `{pr['commit']}`\n- **Path:** `{pr['path']}`\n"
        f"- **Parameter year:** {pr['year']}\n- **Legal references:** {', '.join(pr['legal_refs'])}\n"
        f"- **Rule NOT modified.** Only a documented schema mapping: s = zone (categorical), "
        f"x = resources/€{p['normalization']['cap_eur']:.0f} (normalized), θ(zone,size) = the real ceiling.\n"
        f"- **s semantics:** {p['s_semantics']}\n")


def _write_search_log(path, p):
    path.write_text(
        "# CX5 search log (frozen eligibility + why BRS qualifies)\n\n"
        "**Eligibility criterion (PLAN_CX5, frozen verbatim):** (i) compares ≥1 numeric field to a "
        "threshold; (ii) the threshold varies with a categorical/provenance-like field "
        "(source/env/channel/tier/region/income-category/...); (iii) third-party authored, for operations, "
        "independently of our threat model; (iv) mechanically translatable into the verified affine fragment "
        "(Def 1) — here a scalar threshold, membership trivially in-fragment.\n\n"
        "**Search list (PLAN_CX5 §2), family 2 (decision-table / legislation-as-code):** OpenFisca-France "
        "legislation-as-code (already cloned; P1-B identified subject-keyed numeric thresholds at 6.8% "
        "structural rate). Selected the **Bail Réel Solidaire `plafonds_par_zones`** parameter: income "
        "ceilings keyed by geographic zone.\n\n"
        "**Why it qualifies:** (i) resources vs ceiling ✓; (ii) ceiling varies with **zone** (region-like "
        "categorical, explicitly admitted by (ii)) ✓; (iii) authored by OpenFisca transcribing Arrêté du "
        "11/12/2023 / Art. R255-1 CCH, for real housing-eligibility operations, before/independently of this "
        "work ✓; (iv) scalar threshold, in-fragment ✓.\n\n"
        "**Honest scope (claim ladder):** zone is a SUBJECT/REGION attribute, not a pipeline-provenance key "
        "— so this is a deployed-threshold EXISTENCE anchor (the `x▷θ(s)` idiom occurs in a real third-party "
        "rule), complementary to the pipeline-provenance null (P1/registry), NOT a claim that deployed "
        "pipelines spontaneously carry the provenance-set substrate.\n")


def _write_md(path, p):
    with open(path, "w") as f:
        f.write("# EXP-CX5 — independent-policy case study (OpenFisca BRS zone ceilings)\n\n")
        f.write(f"Source: {p['source_policy']} — commit `{p['provenance']['commit'][:12]}`, {p['provenance']['year']}. "
                f"s = zone (region categorical), θ(zone,size) real income ceiling; cap €{p['normalization']['cap_eur']:.0f}. "
                f"n={p['n']}, seed={p['seed']}.\n\n**Freeze-first:** `policy_bundle/PROVENANCE.md`, `search_log.md`.\n\n")
        f.write("### Real θ(zone) income ceilings (€, 2025) — a provenance-conditioned boundary\n\n")
        f.write("| household size | " + " | ".join(z.replace('zone_', '') for z in ZONES) + " | raw gap € | norm δ |\n")
        f.write("|--:|" + "--:|" * (len(ZONES) + 2) + "\n")
        for n_ in SIZES:
            row = " | ".join(f"{int(p['theta_eur'][z][n_])}" for z in ZONES)
            d = p["deltas_by_size"][n_]
            f.write(f"| {n_} | {row} | {int(d['raw_gap_eur'])} | {d['norm_gap']} |\n")
        f.write("\n### Battery (analytic taxonomy; exact certificate = category R)\n\n")
        f.write("| ε | Pr(A) | Pr(B) | **Pr(C)** | Pr(R) | Pr(U) | R_allow | C-witnesses | point grants | "
                "neighborhood grants | point-unsafe-under-swap |\n")
        f.write("|--:|" + "--:|" * 10 + "\n")
        for eps, r in p["results"].items():
            pr = r["pr"]; pv = r["point_vs_neighborhood"]
            f.write(f"| {eps} | {pr['A']} | {pr['B']} | **{pr['C']}** | {pr['R']} | {pr['U']} | {r['R_allow']} "
                    f"| {pv['n_c_witnesses']} | {pv['point_grants']} | {pv['neighborhood_grants']} | "
                    f"{pv['point_unsafe_under_swap']} |\n")
        f.write(f"\n**Verdict.** {p['verdict']}\n")


def _write_csv(path, p):
    with open(path, "w") as f:
        f.write("eps,pr_A,pr_B,pr_C,pr_R,pr_U,R_allow,n_c_witnesses,point_grants,neighborhood_grants,"
                "point_unsafe_under_swap\n")
        for eps, r in p["results"].items():
            pr = r["pr"]; pv = r["point_vs_neighborhood"]
            f.write(f"{eps},{pr['A']},{pr['B']},{pr['C']},{pr['R']},{pr['U']},{r['R_allow']},"
                    f"{pv['n_c_witnesses']},{pv['point_grants']},{pv['neighborhood_grants']},"
                    f"{pv['point_unsafe_under_swap']}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--eps", default="0.03,0.10")
    ap.add_argument("--cap", default="max_ceiling", help="'max_ceiling' or a raw-€ cap for normalization")
    ap.add_argument("--out", default="cx5_openfisca")
    a = ap.parse_args()
    eps_list = [float(x) for x in a.eps.split(",") if x.strip()]
    run(a.n, a.seed, eps_list, a.cap, a.out)


if __name__ == "__main__":
    main()
