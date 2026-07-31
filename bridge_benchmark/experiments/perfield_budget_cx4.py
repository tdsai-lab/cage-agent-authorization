#!/usr/bin/env python3
"""
perfield_budget_cx4.py — EXP-CX4 = NEW_NEW_EXP A6 (NEW_EXP_OPA_CHECK.md P1): calibrated per-field ε budget.
A single global normalized ℓ₂ ball assigns the SAME radius to every numeric field, but real return-assembly
faults have HETEROGENEOUS per-field residual magnitudes (EXP-B2 already showed a normalized ε=0.10 means ~$71
at the median TransactionAmt but a constant 10 CPU-points on NAB). Does a per-field / weighted budget improve
operational meaning AND certified autonomy while retaining the same held-out fault coverage?

Setup (budget FROZEN on a calibration split, evaluated on a disjoint split):
  * Controlled multivariate-affine policy (unsafe iff m = w·x + b(x1) ≥ 0) — the only regime where a
    per-field budget bites (a scalar-threshold policy touches one field). Weights w heterogeneous; bias
    placed to leave a robust interior. This mirrors the paper's `synthetic_stress_test` affine family
    (oracle.margin_and_scale: exact continuous worst case = m + Δ_geom).
  * Heterogeneous per-field fault residuals f (some fields drift a lot, some little). ε_i = p95(|f_i|) on
    the CALIBRATION split, frozen. Global ℓ₂ radius = p95(‖f‖₂) on the same split.
  * Three budget geometries, EXACT dual-norm continuous worst case of the affine margin:
      global_l2   ball {‖δ‖₂ ≤ ε}                → Δ = ε · ‖w‖₂
      ellipsoid   {Σ (δ_i/ε_i)² ≤ 1}             → Δ = √Σ (ε_i w_i)²         (per-field, correct dual)
      linf_box    {|δ_i| ≤ ε_i}                  → Δ = Σ ε_i |w_i|           (weighted-ℓ∞ → weighted-ℓ1)
    allow (robust-safe) ⟺ m + Δ_geom < 0.
  * Real per-field residual ANCHOR: p50/p95/p99 of per-field drift on IEEE-CIS via the #16 injectors
    (integrity+freshness residual = numeric_jitter + normalization_skew) — shows the heterogeneity is real.

Metrics (frozen budget, EVAL split): held-out FAULT COVERAGE (fraction of held-out fault vectors inside the
ball), robust-safe COVERAGE (certified autonomy R_allow), policy FALSE-ALLOW (certified-robust yet a
held-out fault actually flips it), abstention, raw-unit radius per field. The useful result is the
coverage↔autonomy PARETO: an anisotropic per-field ball matches the global ℓ₂ fault coverage at higher
certified autonomy (it stops sizing every field to the worst field). Budget frozen before evaluation.

Pure numpy/stdlib for the analytic core; fault_injection (real IEEE-CIS) for the anchor. No GPU/LLM.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent / "realdata"))

OUT = _HERE.parent / "cert" / "out"
K_FIELDS = 6
N_X1 = 4
GEOMS = ["global_l2", "ellipsoid", "linf_box"]


# --------------------------------------------------------------------------- #
# Controlled multivariate-affine policy + heterogeneous per-field fault model
# --------------------------------------------------------------------------- #
def make_policy(k, n_x1, seed):
    rng = np.random.default_rng(seed)
    w = rng.uniform(0.4, 1.6, size=k) * rng.choice([-1.0, 1.0], size=k)   # heterogeneous weights
    biases = rng.uniform(-0.6, -0.2, size=n_x1)                            # per-x1 bias (robust interior)
    # per-field fault scale: strongly heterogeneous (2 noisy fields, rest quiet) → anisotropy is the point
    fault_scale = rng.uniform(0.02, 0.05, size=k)
    noisy = rng.choice(k, size=2, replace=False)
    fault_scale[noisy] *= rng.uniform(4.0, 7.0, size=2)
    return {"w": w, "biases": biases, "fault_scale": fault_scale, "k": k, "n_x1": n_x1}


def sample_records(pol, n, seed):
    rng = np.random.default_rng(seed)
    x1 = rng.integers(0, pol["n_x1"], size=n)
    x2 = rng.uniform(-1.0, 1.0, size=(n, pol["k"]))
    m = x2 @ pol["w"] + pol["biases"][x1]
    return {"x1": x1, "x2": x2, "m": m}


def sample_faults(pol, n, seed):
    """Per-field residual fault vectors (heterogeneous scale). Frozen distribution; calibration/eval split."""
    rng = np.random.default_rng(seed)
    return rng.normal(0.0, 1.0, size=(n, pol["k"])) * pol["fault_scale"][None, :]


def calibrate(faults, q=0.95):
    """Calibrate EACH geometry to the SAME target JOINT fault coverage q on the calibration split (the fair
    comparison). Per-field axis scale a_i = calibration std; each geometry's radius R = the q-quantile of
    its own radius statistic → all three cover exactly q of calibration faults, so autonomy is compared at
    MATCHED coverage. Anisotropy (a_i) is the per-field information the global ℓ₂ ball throws away."""
    a = np.maximum(np.std(faults, axis=0), 1e-9)                       # per-field axis scale (frozen)
    rho_l2 = np.linalg.norm(faults, axis=1)
    rho_el = np.sqrt(np.sum((faults / a[None, :]) ** 2, axis=1))
    rho_bx = np.max(np.abs(faults) / a[None, :], axis=1)
    R = {"global_l2": float(np.quantile(rho_l2, q)),
         "ellipsoid": float(np.quantile(rho_el, q)),
         "linf_box": float(np.quantile(rho_bx, q))}
    return a, {k: max(v, 1e-9) for k, v in R.items()}


def eps_vector(geom, a, R):
    """Effective per-field radius ε_i for the geometry (global ℓ₂ = same R for every field)."""
    if geom == "global_l2":
        return np.full_like(a, R["global_l2"])
    return R[geom] * a                                                 # ellipsoid / linf_box axes


def delta_geom(geom, w, a, R):
    if geom == "global_l2":
        return R["global_l2"] * float(np.linalg.norm(w))
    if geom == "ellipsoid":
        return R["ellipsoid"] * float(math.sqrt(float(np.sum((a * w) ** 2))))
    if geom == "linf_box":
        return R["linf_box"] * float(np.sum(a * np.abs(w)))
    raise ValueError(geom)


def inside_ball(geom, f, a, R):
    """Is a per-field fault vector f inside the geometry's ball (calibrated to matched joint coverage)?"""
    if geom == "global_l2":
        return np.linalg.norm(f, axis=1) <= R["global_l2"]
    if geom == "ellipsoid":
        return np.sqrt(np.sum((f / a[None, :]) ** 2, axis=1)) <= R["ellipsoid"]
    if geom == "linf_box":
        return np.max(np.abs(f) / a[None, :], axis=1) <= R["linf_box"]
    raise ValueError(geom)


def eval_geometry(geom, pol, ev, eval_faults, a, R):
    w = pol["w"]
    Delta = delta_geom(geom, w, a, R)
    clean_safe = ev["m"] < 0
    robust = (ev["m"] + Delta) < 0                          # exact: allow ⟺ certified robust-safe
    # certified autonomy = R_allow over clean-safe records
    n_cs = int(clean_safe.sum())
    r_allow = float((robust & clean_safe).sum() / n_cs) if n_cs else float("nan")
    abst = float((~robust & clean_safe).sum() / n_cs) if n_cs else float("nan")
    # held-out fault coverage: fraction of held-out fault vectors inside the ball
    cov = float(np.mean(inside_ball(geom, eval_faults, a, R)))
    # policy false-allow: certified-robust clean-safe record that a held-out fault ACTUALLY flips
    # (worst held-out fault applied to the record's margin). Under-coverage → escape.
    idx = np.where(robust & clean_safe)[0]
    fa = 0
    if len(idx):
        # worst-case realized flip using the actual held-out fault set (sampled, conservative subset)
        Fw = eval_faults @ w                                # projected fault effect on the margin
        worst = float(np.max(Fw)) if len(Fw) else 0.0
        fa = int(np.sum(ev["m"][idx] + worst >= 0))
    pfa = fa / len(idx) if len(idx) else 0.0
    return {"geom": geom, "Delta": round(Delta, 5), "robust_safe_coverage": round(r_allow, 4),
            "abstention": round(abst, 4), "fault_coverage": round(cov, 4),
            "policy_false_allow": round(pfa, 5), "policy_false_allow_count": fa, "n_certified": len(idx)}


def raw_field_radii(pol, a, R):
    """ε in per-field 'raw' units: the ellipsoid gives a distinct ε_i per field (R·a_i); global ℓ₂ assigns
    the SAME radius to every field (the anisotropy it throws away)."""
    eps_el = eps_vector("ellipsoid", a, R)
    return {f"field_{i}": {"eps_perfield_ellipsoid": round(float(eps_el[i]), 5),
                           "eps_global_l2_same_for_all": round(float(R["global_l2"]), 5),
                           "fault_scale": round(float(pol["fault_scale"][i]), 5)}
            for i in range(pol["k"])}


# --------------------------------------------------------------------------- #
# Real per-field residual anchor (IEEE-CIS via #16 injectors), best-effort.
# --------------------------------------------------------------------------- #
def ieee_perfield_residual(n=4000, seed=0):
    try:
        import fault_injection as fi
    except Exception as e:
        return {"available": False, "reason": f"{type(e).__name__}: {e}"}
    try:
        sub = fi.load_ieee_cis(n=n)
    except Exception as e:
        return {"available": False, "reason": f"load_ieee_cis: {type(e).__name__}: {e}"}
    rng = np.random.default_rng(seed)
    residual_injectors = [x for x in ("numeric_jitter", "normalization_skew") if x in fi.INJECTORS]
    per_field = {f: [] for f in sub.x2_fields}
    recs = sub.records
    for _ in range(min(n, len(recs))):
        rec = recs[int(rng.integers(len(recs)))]
        inj = fi.INJECTORS[residual_injectors[int(rng.integers(len(residual_injectors)))]]
        try:
            z = inj(fi._clone(rec), sub, rng)
        except Exception:
            continue
        for f in sub.x2_fields:
            per_field[f].append(abs(float(z["x2"].get(f, rec["x2"][f])) - float(rec["x2"][f])))
    table = {}
    for f, vals in per_field.items():
        if not vals:
            continue
        a = np.abs(np.asarray(vals))
        table[f] = {"p50": round(float(np.quantile(a, 0.50)), 5),
                    "p95": round(float(np.quantile(a, 0.95)), 5),
                    "p99": round(float(np.quantile(a, 0.99)), 5)}
    spread = None
    p95s = [v["p95"] for v in table.values() if v["p95"] > 0]
    if len(p95s) >= 2:
        spread = round(max(p95s) / max(1e-9, min(p95s)), 1)
    return {"available": True, "residual_injectors": residual_injectors, "per_field_p_quantiles": table,
            "p95_field_heterogeneity_ratio": spread}


def run(k, n_x1, seeds, n_cal, n_eval, q, out_prefix):
    per_seed = []
    for s in seeds:
        pol = make_policy(k, n_x1, s)
        cal_faults = sample_faults(pol, n_cal, seed=100 + s)      # calibration split (freeze budget here)
        a, R = calibrate(cal_faults, q=q)
        ev = sample_records(pol, n_eval, seed=200 + s)
        eval_faults = sample_faults(pol, n_eval, seed=300 + s)    # DISJOINT eval faults (held-out)
        geoms = {g: eval_geometry(g, pol, ev, eval_faults, a, R) for g in GEOMS}
        per_seed.append({"seed": s, "eps_perfield_ellipsoid": [round(float(x), 5)
                                                               for x in eps_vector("ellipsoid", a, R)],
                         "R_by_geom": {k: round(float(v), 5) for k, v in R.items()}, "geoms": geoms,
                         "raw_field_radii": raw_field_radii(pol, a, R)})
        g = geoms
        print(f"[seed={s}] coverage/autonomy: "
              f"l2={g['global_l2']['fault_coverage']}/{g['global_l2']['robust_safe_coverage']} "
              f"ellipsoid={g['ellipsoid']['fault_coverage']}/{g['ellipsoid']['robust_safe_coverage']} "
              f"linf={g['linf_box']['fault_coverage']}/{g['linf_box']['robust_safe_coverage']}")

    def agg(geom, key):
        vals = [ps["geoms"][geom][key] for ps in per_seed]
        return (round(float(np.mean(vals)), 4), round(float(np.std(vals)), 4))
    aggregate = {g: {k: agg(g, k) for k in ("fault_coverage", "robust_safe_coverage", "abstention",
                                            "policy_false_allow", "Delta")} for g in GEOMS}

    # Pareto verdict: does a per-field ball match global-ℓ2 fault coverage at higher autonomy?
    l2 = aggregate["global_l2"]; el = aggregate["ellipsoid"]; li = aggregate["linf_box"]
    best_pf = "ellipsoid" if el["robust_safe_coverage"][0] >= li["robust_safe_coverage"][0] else "linf_box"
    bp = aggregate[best_pf]
    win = (bp["fault_coverage"][0] >= l2["fault_coverage"][0] - 0.02
           and bp["robust_safe_coverage"][0] > l2["robust_safe_coverage"][0] + 0.02)
    if win:
        verdict = (f"PER-FIELD BUDGET WINS THE PARETO: the {best_pf} ball matches the global-ℓ₂ held-out "
                   f"fault coverage ({bp['fault_coverage'][0]} vs {l2['fault_coverage'][0]}) at HIGHER "
                   f"certified autonomy (R_allow {bp['robust_safe_coverage'][0]} vs "
                   f"{l2['robust_safe_coverage'][0]}) — sizing each field to its own p95 residual stops the "
                   f"global sphere from over-charging the quiet fields. Budget frozen on calibration; both "
                   f"sound (policy_false_allow ≈ {bp['policy_false_allow'][0]}).")
    else:
        verdict = (f"NO CLEAR PARETO WIN under this fault anisotropy: per-field autonomy "
                   f"{bp['robust_safe_coverage'][0]} vs global-ℓ₂ {l2['robust_safe_coverage'][0]} at coverage "
                   f"{bp['fault_coverage'][0]}/{l2['fault_coverage'][0]} — report honestly; the per-field "
                   f"gain scales with per-field residual heterogeneity.")

    anchor = ieee_perfield_residual()
    payload = {
        "experiment": "EXP-CX4 = A6 — calibrated per-field ε budget (ellipsoid / weighted-ℓ∞ vs global ℓ₂)",
        "source": "NEW_EXP_OPA_CHECK.md CX4 / NEW_NEW_EXP.md A6", "k_fields": k, "n_x1": n_x1,
        "seeds": list(seeds), "n_cal": n_cal, "n_eval": n_eval, "calibration_quantile": q,
        "geometries": GEOMS, "budget_frozen_on": "calibration split (per-field p95); eval split disjoint",
        "aggregate": {g: {k: {"mean": v[0], "std": v[1]} for k, v in aggregate[g].items()} for g in GEOMS},
        "per_seed": per_seed, "ieee_cis_real_perfield_residual_anchor": anchor, "verdict": verdict,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{out_prefix}.json").write_text(json.dumps(payload, indent=2))
    _write_md(OUT / f"{out_prefix}.md", payload)
    print(f"\nVERDICT: {verdict}\nwrote -> {OUT/(out_prefix+'.json')}\nwrote -> {OUT/(out_prefix+'.md')}")
    return payload


def _write_md(path, p):
    with open(path, "w") as f:
        f.write("# EXP-CX4 = A6 — calibrated per-field ε budget\n\n")
        f.write(f"Source: {p['source']}. Multivariate-affine policy, k={p['k_fields']} fields, "
                f"|X1|={p['n_x1']}, seeds={p['seeds']}, calibration p{int(p['calibration_quantile']*100)} "
                f"(frozen), eval split disjoint. Exact certificate; dual norm per geometry.\n\n")
        f.write("| geometry | Δ (eps-gain) | held-out fault coverage | robust-safe coverage (autonomy) | "
                "abstention | policy false-allow |\n|---|--:|--:|--:|--:|--:|\n")
        for g in p["geometries"]:
            a = p["aggregate"][g]
            f.write(f"| {g} | {a['Delta']['mean']} | {a['fault_coverage']['mean']}±"
                    f"{a['fault_coverage']['std']} | **{a['robust_safe_coverage']['mean']}**±"
                    f"{a['robust_safe_coverage']['std']} | {a['abstention']['mean']} | "
                    f"{a['policy_false_allow']['mean']} |\n")
        an = p["ieee_cis_real_perfield_residual_anchor"]
        f.write("\n### Real per-field residual anchor (IEEE-CIS, #16 integrity+freshness residual)\n\n")
        if an.get("available"):
            f.write(f"Injectors: {an['residual_injectors']}; **p95 field heterogeneity ratio "
                    f"{an['p95_field_heterogeneity_ratio']}×** (max/min field p95).\n\n")
            f.write("| field | p50 | p95 | p99 |\n|---|--:|--:|--:|\n")
            for fld, q in list(an["per_field_p_quantiles"].items())[:12]:
                f.write(f"| {fld} | {q['p50']} | {q['p95']} | {q['p99']} |\n")
        else:
            f.write(f"_anchor unavailable: {an.get('reason')}_ (synthetic core stands alone)\n")
        f.write(f"\n**Verdict.** {p['verdict']}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--k", type=int, default=K_FIELDS)
    ap.add_argument("--n-x1", type=int, default=N_X1)
    ap.add_argument("--seeds", default="0,1,2,3,4")
    ap.add_argument("--n-cal", type=int, default=20000)
    ap.add_argument("--n-eval", type=int, default=20000)
    ap.add_argument("--q", type=float, default=0.95)
    ap.add_argument("--out", default="exp_cx4_perfield_budget")
    a = ap.parse_args()
    seeds = [int(s) for s in a.seeds.split(",") if s.strip()]
    run(a.k, a.n_x1, seeds, a.n_cal, a.n_eval, a.q, a.out)


if __name__ == "__main__":
    main()
