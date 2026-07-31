#!/usr/bin/env python3
"""
opa_fidelity_cx1.py — EXP-CX1 (NEW_EXP_OPA_CHECK.md, P0): learned-policy vs exact-OPA *gate-policy
fidelity* benchmark. When the true policy is executable and exactly robust-evaluable, how closely do the
learned CAGE backends recover its robust-safe set R_OPA? Framed as "the price of a surrogate", NOT as
evidence a learned gate should replace OPA (exact backend is the deployment choice when it applies).

Ground truth (engine-exact, one batched `opa eval`): `opa_joint_unsafe_map(orc)` → a return z is in the
exact robust-safe set R_OPA iff NO point of B_{1,ε} is OPA-unsafe (i.e. `not joint_unsafe`). Systems:
  1. opa_point      — the executable policy at the observed point (clean_safe). Ignores the ball.
  2. cage_exact     — allow ⟺ z ∈ R_OPA (the exact certificate; reference, policy-FA=0 by construction).
  3. point_mlp      — learned 1-Lipschitz gate raw sign at the point (no certificate) = "exactness at the
                      observed point buys nothing" baseline.
  4. cage_lip       — deterministic 1-Lipschitz certificate over B_{1,ε} (PRIMARY learned backend).
  5. cage_rs        — Gaussian randomized-smoothing certificate over B_{1,ε} (ABLATION).
Metrics vs R_OPA, per eval distribution (natural + boundary-balanced): policy_false_allow
Pr[z∉R_OPA | allowed] (Wilson 95% upper bound), robust_safe_coverage Pr[allow | z∈R_OPA] (=R_allow),
precision / recall / Jaccard of the allow set against R_OPA, point accuracy (secondary), runtime.

Pre-registered reading (NEW_EXP_OPA_CHECK): strong = tight policy-FA bound + substantial R_OPA recovery;
conservative = policy-FA≈0 with coverage ~0.3–0.4 (a useful autonomy tranche with a measurable learning
tax); fidelity failure = a learned certificate admits policy-unsafe points (⇒ gate-cert ≠ policy-cert).

Reuses d_sweep (build_opa/certify_lip_at_d/certify_at_d/opa_joint_unsafe_map) + opa_gate. Needs the bundled
`bin/opa` + torch/orthogonium (Lipschitz) + GPU. d=1 (MVP). No LLM/network.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import d_sweep as DS  # noqa: E402

OUT = _HERE.parent / "cert" / "out"
EPS = 0.10
SIGMA = 0.10
TAU = 0.90
ALPHA = 1e-3
DOMAINS = ["finance", "sre", "ops"]
# NOTE (verified): the three authored OPA domains are the SAME provenance-conditioned SCALAR-threshold
# policy (m=1 coordinate-w case, per PLAN_CX3) with the numeric field merely RENAMED
# (risk_score/signal/login_risk). categorize() is byte-identical across them (clean_safe 252/400, cats
# A52/U148/R137/C50/B13) → they are a field-RENAMING-invariance check, NOT three complexity tiers. The
# multivariate-affine tier lives in the synthetic affine family (EXP-CX4 / the paper's affine synthetic),
# not in this OPA suite. Do not claim scalar/piecewise/affine tiers here.
TIER = {"finance": "provenance-scalar-threshold (field=risk_score)",
        "sre": "provenance-scalar-threshold (field=signal, renamed)",
        "ops": "provenance-scalar-threshold (field=login_risk, renamed)"}


def _wilson_upper(k, n, z=1.96):
    """Wilson 95% upper bound for a binomial rate k/n (meaningful even when k=0)."""
    if n == 0:
        return float("nan")
    p = k / n
    d = 1 + z * z / n
    centre = p + z * z / (2 * n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (centre + half) / d


def _lip_point_allow(model, enc, rec, fscale):
    """Raw 1-Lipschitz gate decision AT the observed point (no neighborhood certificate)."""
    import torch
    v = np.asarray(enc.transform_point(rec["domain"], rec["tool_id"], rec["candidate_action"],
                                       rec["categorical_fields"], rec["numeric_fields"]), dtype=np.float32)
    if fscale != 1.0:
        start = enc.dim - len(enc.numeric_fields)
        v[start:] *= fscale
    with torch.no_grad():
        h = model(torch.from_numpy(v[None, :]).to(DS._LIP_DEVICE)).cpu().numpy().reshape(-1)[0]
    return bool(h > 0)


def _boundary_balanced(ev, ju, seed):
    """Resample to ~50/50 R_OPA vs not-R_OPA (the fidelity story lives near the boundary)."""
    rng = np.random.default_rng(1000 + seed)
    R = [r for r in ev if not ju[id(r)]]
    nR = [r for r in ev if ju[id(r)]]
    if not R or not nR:
        return ev
    m = min(len(R), len(nR))
    ridx = rng.choice(len(R), size=m, replace=False)
    nidx = rng.choice(len(nR), size=m, replace=False)
    return [R[i] for i in ridx] + [nR[i] for i in nidx]


def _metrics(recs, allow_of, ju, y_of=None):
    """allow_of: rec -> bool. ju[id]=True means z ∉ R_OPA (some ball point is OPA-unsafe)."""
    n = len(recs)
    n_allow = n_R = inter = fa = pt_correct = 0
    for r in recs:
        a = allow_of(r)
        inR = not ju[id(r)]
        n_R += inR
        if a:
            n_allow += 1
            inter += inR
            fa += (not inR)                       # allowed a non-robust-safe return = policy false-allow
        if y_of is not None:
            pt_correct += int(bool(y_of(r)) == a)
    union = n_allow + n_R - inter
    return {
        "n": n, "n_in_R_OPA": n_R, "n_allow": n_allow,
        "policy_false_allow": (fa / n_allow) if n_allow else 0.0,
        "policy_false_allow_wilson_upper": _wilson_upper(fa, n_allow) if n_allow else float("nan"),
        "policy_false_allow_count": fa,
        "robust_safe_coverage": (inter / n_R) if n_R else float("nan"),   # = R_allow vs exact R_OPA
        "precision": (inter / n_allow) if n_allow else float("nan"),
        "recall": (inter / n_R) if n_R else float("nan"),
        "jaccard": (inter / union) if union else float("nan"),
        "point_accuracy": (pt_correct / n) if y_of is not None else None,
    }


def _run_domain(domain, seed, n_train, n_eval, eps, sigma, tau, n_mc, alpha):
    orc, rt, ev, gate, lip = DS.build_opa(domain, seed, n_train, n_eval, eps, sigma)
    if lip is None:
        raise RuntimeError("Lipschitz backend unavailable")
    model, enc, fscale = lip
    ju_map = DS.opa_joint_unsafe_map(orc)
    ju = ju_map(ev, 1, eps)                                   # engine-exact R_OPA membership (one batch)

    # timed allow-oracles per system
    def opa_point(r):   return r.get("y", 0) == 1
    def cage_exact(r):  return not ju[id(r)]
    def point_mlp(r):   return _lip_point_allow(model, enc, r, fscale)
    def cage_lip(r):    return DS.certify_lip_at_d(model, enc, rt, r, 1, eps=eps, fscale=fscale)[0]
    def cage_rs(r):     return DS.certify_at_d(gate, rt, r, 1, sigma=sigma, eps=eps, tau=tau,
                                               n_mc=n_mc, alpha_fwer=alpha)[0]
    systems = {"opa_point": opa_point, "cage_exact": cage_exact, "point_mlp": point_mlp,
               "cage_lip": cage_lip, "cage_rs": cage_rs}
    y_of = lambda r: r.get("y", 0) == 1  # noqa: E731  (clean policy label; point-accuracy secondary)

    evalsets = {"natural": ev, "boundary": _boundary_balanced(ev, ju, seed)}
    out = {}
    for sysname, allow_of in systems.items():
        out[sysname] = {}
        for setname, recs in evalsets.items():
            t0 = time.perf_counter()
            m = _metrics(recs, allow_of, ju, y_of=y_of)
            m["mean_ms_per_decision"] = round(1000 * (time.perf_counter() - t0) / max(1, len(recs)), 4)
            out[sysname][setname] = m
    return {"domain": domain, "tier": TIER[domain], "seed": seed, "fscale": fscale,
            "n_eval": len(ev), "n_R_OPA_natural": int(sum(not ju[id(r)] for r in ev)), "systems": out}


def _aggregate(per_seed):
    """Mean±std across seeds, per (system, evalset)."""
    systems = per_seed[0]["systems"].keys()
    sets = ["natural", "boundary"]
    keys = ["policy_false_allow", "robust_safe_coverage", "precision", "recall", "jaccard",
            "point_accuracy", "policy_false_allow_wilson_upper"]
    agg = {}
    for s in systems:
        agg[s] = {}
        for st in sets:
            cells = [ps["systems"][s][st] for ps in per_seed]
            agg[s][st] = {}
            for k in keys:
                vals = [c[k] for c in cells if c[k] is not None and c[k] == c[k]]
                agg[s][st][k] = (round(float(np.mean(vals)), 4) if vals else float("nan"),
                                 round(float(np.std(vals)), 4) if vals else float("nan"))
            agg[s][st]["policy_false_allow_count_total"] = int(sum(ps["systems"][s][st]
                                                                   ["policy_false_allow_count"]
                                                                   for ps in per_seed))
            agg[s][st]["n_allow_total"] = int(sum(ps["systems"][s][st]["n_allow"] for ps in per_seed))
    return agg


def run(domains, seeds, n_train, n_eval, eps, sigma, tau, n_mc, alpha, out_prefix):
    if not DS._LIP_OK:
        print("[error] Lipschitz backend unavailable"); return None
    results = {}
    for dom in domains:
        per_seed = []
        for s in seeds:
            row = _run_domain(dom, s, n_train, n_eval, eps, sigma, tau, n_mc, alpha)
            per_seed.append(row)
            pf = {k: row["systems"][k]["boundary"]["policy_false_allow"] for k in row["systems"]}
            cov = {k: row["systems"][k]["boundary"]["robust_safe_coverage"] for k in row["systems"]}
            print(f"[{dom} seed={s}] boundary policy_FA: point_mlp={pf['point_mlp']:.3f} "
                  f"cage_lip={pf['cage_lip']:.3f} cage_rs={pf['cage_rs']:.3f} cage_exact={pf['cage_exact']:.3f}"
                  f" | cov cage_lip={cov['cage_lip']:.3f} cage_rs={cov['cage_rs']:.3f}")
        results[dom] = {"tier": TIER[dom], "per_seed": per_seed, "aggregate": _aggregate(per_seed)}

    # verdict per the pre-registered ladder (learned certs = cage_lip / cage_rs)
    lip_fa = max(results[d]["aggregate"]["cage_lip"][st]["policy_false_allow"][0]
                 for d in domains for st in ("natural", "boundary"))
    rs_fa = max(results[d]["aggregate"]["cage_rs"][st]["policy_false_allow"][0]
                for d in domains for st in ("natural", "boundary"))
    lip_cov = float(np.mean([results[d]["aggregate"]["cage_lip"]["natural"]["robust_safe_coverage"][0]
                             for d in domains]))
    if lip_fa > 0 or rs_fa > 0:
        verdict = (f"FIDELITY FAILURE: a learned certificate admits policy-unsafe points "
                   f"(cage_lip policy_FA max {lip_fa}, cage_rs {rs_fa}) → gate-certification does NOT imply "
                   f"policy-certification; report as evidence for the exact backend.")
    elif lip_cov >= 0.5:
        verdict = (f"STRONG: learned certs keep policy_false_allow=0 (Lip & RS, both eval sets, all tiers) "
                   f"AND recover a substantial fraction of R_OPA (Lip natural coverage mean {round(lip_cov,3)}) "
                   f"— tight surrogate with modest learning tax; the point baselines pay the boundary price.")
    else:
        verdict = (f"CONSERVATIVE: learned certs keep policy_false_allow=0 (Lip & RS, both eval sets, all "
                   f"tiers) while robust-safe coverage stays ~{round(lip_cov,2)} (Lip natural) — a useful "
                   f"autonomy tranche with a measurable, quantified learning tax vs the exact backend.")

    payload = {
        "experiment": "EXP-CX1 — learned-policy vs exact-OPA gate-policy fidelity benchmark",
        "source": "NEW_EXP_OPA_CHECK.md (P0)", "eps": eps, "sigma": sigma, "tau": tau, "n_mc": n_mc,
        "alpha": alpha, "d": 1, "domains": domains, "tiers": {d: TIER[d] for d in domains},
        "seeds": list(seeds), "n_train": n_train, "n_eval": n_eval,
        "systems": ["opa_point", "cage_exact", "point_mlp", "cage_lip", "cage_rs"],
        "ground_truth": "R_OPA = exact robust-safe set via opa_joint_unsafe_map (engine, batched)",
        "results": results, "verdict": verdict,
        "framing": ("gate-policy fidelity benchmark (price of a surrogate under known ground truth), NOT "
                    "evidence a learned gate should replace OPA; the exact backend is the deployment choice "
                    "when the policy is robustly evaluable at low cost. VERIFIED SCOPE: the three authored "
                    "OPA domains are the SAME provenance-conditioned scalar-threshold policy with the numeric "
                    "field renamed (categorize identical across them) — a renaming-invariance check, not "
                    "three complexity tiers; the multivariate-affine tier is covered by EXP-CX4."),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{out_prefix}.json").write_text(json.dumps(payload, indent=2))
    _write_md(OUT / f"{out_prefix}.md", payload)
    print(f"\nVERDICT: {verdict}\nwrote -> {OUT/(out_prefix+'.json')}\nwrote -> {OUT/(out_prefix+'.md')}")
    return payload


def _fmt(pair):
    m, s = pair
    return f"{m}" if (s == 0 or s != s) else f"{m}±{s}"


def _write_md(path, p):
    with open(path, "w") as f:
        f.write("# EXP-CX1 — learned-policy vs exact-OPA fidelity benchmark\n\n")
        f.write(f"Source: {p['source']}. Ground truth: {p['ground_truth']}. "
                f"ε={p['eps']}, σ={p['sigma']}, τ={p['tau']}, n_mc={p['n_mc']}, d={p['d']}, "
                f"seeds={p['seeds']}, n_train={p['n_train']}, n_eval={p['n_eval']}.\n\n")
        f.write(f"**Framing.** {p['framing']}\n\n")
        for dom in p["domains"]:
            agg = p["results"][dom]["aggregate"]
            f.write(f"### {dom} — tier: {p['tiers'][dom]}\n\n")
            for st in ("natural", "boundary"):
                f.write(f"**{st} eval** — policy_FA (Wilson 95% upper) | robust-safe coverage | precision | "
                        f"recall | Jaccard | point-acc\n\n")
                f.write("| system | policy_FA | ≤upper | coverage | precision | recall | Jaccard | pt-acc |\n")
                f.write("|---|--:|--:|--:|--:|--:|--:|--:|\n")
                for s in p["systems"]:
                    c = agg[s][st]
                    fa_tot = c["policy_false_allow_count_total"]; na = c["n_allow_total"]
                    f.write(f"| {s} | {_fmt(c['policy_false_allow'])} ({fa_tot}/{na}) | "
                            f"{_fmt(c['policy_false_allow_wilson_upper'])} | {_fmt(c['robust_safe_coverage'])} "
                            f"| {_fmt(c['precision'])} | {_fmt(c['recall'])} | {_fmt(c['jaccard'])} | "
                            f"{_fmt(c['point_accuracy'])} |\n")
                f.write("\n")
        f.write(f"**Verdict.** {p['verdict']}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domains", default=",".join(DOMAINS))
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--n-train", type=int, default=5000)
    ap.add_argument("--n-eval", type=int, default=4000)
    ap.add_argument("--eps", type=float, default=EPS)
    ap.add_argument("--sigma", type=float, default=SIGMA)
    ap.add_argument("--tau", type=float, default=TAU)
    ap.add_argument("--n-mc", type=int, default=800)
    ap.add_argument("--alpha", type=float, default=ALPHA)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default="exp_cx1_opa_fidelity")
    a = ap.parse_args()
    if a.quick:
        a.n_train, a.n_eval, a.n_mc = 1200, 800, 400
    domains = [d.strip() for d in a.domains.split(",") if d.strip()]
    seeds = [int(s) for s in a.seeds.split(",") if s.strip()]
    run(domains, seeds, a.n_train, a.n_eval, a.eps, a.sigma, a.tau, a.n_mc, a.alpha, a.out)


if __name__ == "__main__":
    main()
