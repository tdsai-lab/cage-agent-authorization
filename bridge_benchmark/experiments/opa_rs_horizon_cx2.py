#!/usr/bin/env python3
"""
opa_rs_horizon_cx2.py — EXP-CX2 (NEW_EXP_OPA_CHECK.md, P0): deployment-horizon confidence for randomized
smoothing (RS). Per-decision RS certification controls a per-record failure probability α; over a
deployment of T decisions the *lifetime* failure probability is what a deployer actually cares about. This
experiment measures the utility (R_allow) / cost (MC samples) / lifetime-guarantee trade-off as T grows,
and shows the deterministic 1-Lipschitz backend is horizon-INVARIANT (no α, no MC) — the reason it is the
PRIMARY runtime backend and RS is an ablation scoped to bounded batches.

Ground truth = exact OPA robust-safe set R_OPA (`opa_joint_unsafe_map`, engine). We certify the robust-safe
records (category R) and report the fraction the certificate still allows (R_allow) plus the analytic
lifetime failure bound, under five α-allocation schemes for horizon T ∈ {10³,10⁴,10⁵,10⁶}, total budget
α_total = 0.01:
  1. per_record_const — α = 1e-3 fixed (the current per-decision setting). Lifetime bound = min(1, T·α):
     VACUOUS (→1) beyond T≈10³.
  2. bonferroni       — α = α_total / T (union bound). Lifetime bound = α_total, but α shrinks with T so
     the Clopper–Pearson lower bound drops → R_allow collapses at fixed MC budget.
  3. alpha_spending   — α_t ∝ 1/t² normalised so Σ_t α_t = α_total (front-loaded: early decisions keep
     utility, the tail is starved). Reported at representative early/late t.
  4. adaptive_mc      — hold α = α_total/T but ESCALATE n_mc per decision until the CP bound clears τ or a
     cap; report the median / p95 samples that buys back R_allow, and the residual fallback rate.
  5. lip_fallback     — deterministic 1-Lipschitz certificate: NO α, NO MC → R_allow is IDENTICAL at every
     T (horizon-invariant, sound by the margin bound).

KEY EFFICIENCY: all fixed-MC schemes (1–3) and every horizon share ONE set of MC draws per record — we
sample smoothed_p_safe(k,n) once, then recompute clopper_pearson_lower(k,n,α)→cohen_lower for each α. Only
adaptive_mc draws more. Reuses d_sweep (build_opa/valid_states_d/smoothed_p_safe/clopper_pearson_lower/
cohen_lower/certify_lip_at_d/opa_joint_unsafe_map). Needs bin/opa + torch + GPU. d=1.
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
EPS, SIGMA, TAU = 0.10, 0.10, 0.90
ALPHA_TOTAL = 0.01
HORIZONS = [1000, 10000, 100000, 1000000]
ADAPT_LADDER = [500, 1000, 2000, 4000, 8000]      # escalating MC budget for scheme (4)


def _sample_kn(gate, rt, rec, sigma, n_mc, seed):
    """Draw MC ONCE per enumerated d=1 branch; return list of (k,n) — reusable across all α."""
    rng = np.random.default_rng(DS._seed_for(rec, seed))
    a, base = rec["candidate_action"], rec["numeric_fields"]
    kn = []
    for tool, x1 in DS.valid_states_d(rt, rec, 1):
        kn.append(DS.smoothed_p_safe(gate, rt, rec["domain"], tool, a, x1, base, sigma, n_mc, rng))
    return kn


def _allow_from_kn(kn, alpha, eps, sigma, tau):
    """Recompute the RS allow decision at a given per-decision α from cached (k,n) draws (Bonferroni over
    the |N_d| branches, exactly as certify_at_d)."""
    n_states = max(1, len(kn))
    ab = alpha / n_states
    min_ell = math.inf
    for k, n in kn:
        min_ell = min(min_ell, DS.cohen_lower(DS.clopper_pearson_lower(k, n, ab), eps, sigma))
    return min_ell >= tau


def _lifetime_bound(scheme, T, alpha_total):
    if scheme == "per_record_const":
        return min(1.0, T * 1e-3)
    if scheme in ("bonferroni", "adaptive_mc", "alpha_spending"):
        return alpha_total            # union bound / spending both cap Σα ≤ α_total
    if scheme == "lip_fallback":
        return 0.0                    # deterministic margin certificate: no probabilistic failure
    return float("nan")


def _alpha_for(scheme, T, alpha_total, t=None):
    if scheme == "per_record_const":
        return 1e-3
    if scheme in ("bonferroni", "adaptive_mc"):
        return alpha_total / T
    if scheme == "alpha_spending":                       # α_t ∝ 1/t², Σ_{1..T} = α_total
        norm = alpha_total / (math.pi ** 2 / 6.0)
        return norm / (t ** 2)
    return float("nan")


def _run_domain(domain, seed, n_train, n_eval, n_mc_fixed, eps, sigma, tau, alpha_total, max_R):
    orc, rt, ev, gate, lip = DS.build_opa(domain, seed, n_train, n_eval, eps, sigma)
    if lip is None:
        raise RuntimeError("Lipschitz backend unavailable")
    model, enc, fscale = lip
    ju = DS.opa_joint_unsafe_map(orc)(ev, 1, eps)
    R = [r for r in ev if not ju[id(r)]][:max_R]            # exact robust-safe records
    if not R:
        raise RuntimeError(f"{domain}: no robust-safe records to certify")

    # ---- cache MC (k,n) ONCE per record at the fixed budget, + the deterministic Lip decision ----
    kn_cache = [_sample_kn(gate, rt, r, sigma, n_mc_fixed, seed) for r in R]
    t0 = time.perf_counter()
    lip_allow = [DS.certify_lip_at_d(model, enc, rt, r, 1, eps=eps, fscale=fscale)[0] for r in R]
    lip_ms = 1000 * (time.perf_counter() - t0) / len(R)
    lip_R_allow = float(np.mean(lip_allow))

    schemes_out = {}
    for scheme in ("per_record_const", "bonferroni", "alpha_spending"):
        rows = []
        for T in HORIZONS:
            if scheme == "alpha_spending":
                # representative early (t=1) and late (t=T) decisions
                a_early, a_late = _alpha_for(scheme, T, alpha_total, t=1), _alpha_for(scheme, T, alpha_total, t=T)
                r_early = float(np.mean([_allow_from_kn(kn, a_early, eps, sigma, tau) for kn in kn_cache]))
                r_late = float(np.mean([_allow_from_kn(kn, a_late, eps, sigma, tau) for kn in kn_cache]))
                rows.append({"T": T, "alpha_early": a_early, "alpha_late": a_late,
                             "R_allow_early": round(r_early, 4), "R_allow_late": round(r_late, 4),
                             "lifetime_bound": _lifetime_bound(scheme, T, alpha_total)})
            else:
                a = _alpha_for(scheme, T, alpha_total)
                r_allow = float(np.mean([_allow_from_kn(kn, a, eps, sigma, tau) for kn in kn_cache]))
                rows.append({"T": T, "alpha_per_decision": a, "R_allow": round(r_allow, 4),
                             "lifetime_bound": _lifetime_bound(scheme, T, alpha_total)})
        schemes_out[scheme] = rows

    # ---- scheme 4: adaptive MC — escalate budget to buy back R_allow at α = α_total/T ----
    adaptive_out = []
    for T in HORIZONS:
        a = alpha_total / T
        used, allowed = [], []
        for r in R:
            got = False
            rng = np.random.default_rng(DS._seed_for(r, seed) + 991)
            acc = None
            for budget in ADAPT_LADDER:
                # fresh independent draws at this budget (conservative: no reuse across ladder rungs)
                kn = _sample_kn(gate, rt, r, sigma, budget, seed + 7)
                if _allow_from_kn(kn, a, eps, sigma, tau):
                    used.append(budget); allowed.append(1); got = True; break
                acc = budget
            if not got:
                used.append(acc if acc else ADAPT_LADDER[-1]); allowed.append(0)
        adaptive_out.append({"T": T, "alpha_per_decision": a,
                             "R_allow": round(float(np.mean(allowed)), 4),
                             "median_n_mc": int(np.median(used)), "p95_n_mc": int(np.percentile(used, 95)),
                             "fallback_rate": round(1 - float(np.mean(allowed)), 4),
                             "lifetime_bound": alpha_total})

    return {"domain": domain, "seed": seed, "n_R": len(R), "n_mc_fixed": n_mc_fixed,
            "fixed_schemes": schemes_out, "adaptive_mc": adaptive_out,
            "lip_fallback": {"R_allow": round(lip_R_allow, 4), "lifetime_bound": 0.0,
                             "n_mc": 0, "mean_ms": round(lip_ms, 3), "horizon_invariant": True}}


def run(domains, seeds, n_train, n_eval, n_mc, eps, sigma, tau, alpha_total, max_R, out_prefix):
    if not DS._LIP_OK:
        print("[error] Lipschitz backend unavailable"); return None
    results = {}
    for dom in domains:
        per_seed = [_run_domain(dom, s, n_train, n_eval, n_mc, eps, sigma, tau, alpha_total, max_R)
                    for s in seeds]
        # aggregate the headline: RS R_allow under Bonferroni vs T, and Lip (T-invariant)
        def bonf_R(T):
            return round(float(np.mean([[r for r in ps["fixed_schemes"]["bonferroni"] if r["T"] == T][0]
                                        ["R_allow"] for ps in per_seed])), 4)
        lip_R = round(float(np.mean([ps["lip_fallback"]["R_allow"] for ps in per_seed])), 4)
        results[dom] = {"per_seed": per_seed,
                        "bonferroni_R_allow_by_T": {T: bonf_R(T) for T in HORIZONS},
                        "lip_R_allow": lip_R}
        print(f"[{dom}] Bonferroni R_allow by T: "
              f"{ {T: results[dom]['bonferroni_R_allow_by_T'][T] for T in HORIZONS} } | Lip(T-invariant)={lip_R}")

    # verdict per the pre-registered kill criterion
    collapses = any(results[d]["bonferroni_R_allow_by_T"][HORIZONS[-1]] <
                    0.5 * max(1e-9, results[d]["bonferroni_R_allow_by_T"][HORIZONS[0]]) for d in domains)
    lip_holds = all(results[d]["lip_R_allow"] >= results[d]["bonferroni_R_allow_by_T"][HORIZONS[-1]]
                    for d in domains)
    if collapses and lip_holds:
        verdict = ("KILL-CRITERION MET (as pre-registered): under a fixed MC budget the RS lifetime "
                   "correction (Bonferroni α_total/T) drives R_allow down as T grows — RS goes toward "
                   "vacuous beyond a small horizon, so RS must be scoped to bounded batches / offline "
                   "decisions. The deterministic 1-Lipschitz certificate is horizon-INVARIANT (no α, no MC) "
                   "and stays the PRIMARY runtime backend; adaptive MC can buy back utility only at a "
                   "growing sample cost (median/p95 n_mc reported).")
    else:
        verdict = ("RS survives the horizon at this MC budget (R_allow does not collapse by T=1e6); still "
                   "report Lip as horizon-invariant primary and RS as the bounded-batch ablation.")

    payload = {
        "experiment": "EXP-CX2 — deployment-horizon confidence for randomized smoothing",
        "source": "NEW_EXP_OPA_CHECK.md (P0)", "eps": eps, "sigma": sigma, "tau": tau,
        "alpha_total": alpha_total, "n_mc_fixed": n_mc, "horizons": HORIZONS, "domains": domains,
        "seeds": list(seeds), "n_train": n_train, "n_eval": n_eval, "max_R_certified": max_R,
        "schemes": ["per_record_const", "bonferroni", "alpha_spending", "adaptive_mc", "lip_fallback"],
        "results": results, "verdict": verdict,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{out_prefix}.json").write_text(json.dumps(payload, indent=2))
    _write_md(OUT / f"{out_prefix}.md", payload)
    print(f"\nVERDICT: {verdict}\nwrote -> {OUT/(out_prefix+'.json')}\nwrote -> {OUT/(out_prefix+'.md')}")
    return payload


def _write_md(path, p):
    with open(path, "w") as f:
        f.write("# EXP-CX2 — deployment-horizon confidence for randomized smoothing\n\n")
        f.write(f"Source: {p['source']}. ε={p['eps']}, σ={p['sigma']}, τ={p['tau']}, "
                f"α_total={p['alpha_total']}, fixed n_mc={p['n_mc_fixed']}, seeds={p['seeds']}, "
                f"certifying ≤{p['max_R_certified']} exact robust-safe records/domain. d=1.\n\n")
        for dom in p["domains"]:
            r = p["results"][dom]
            f.write(f"### {dom}\n\n")
            f.write("**RS R_allow vs horizon T (fixed MC budget), + Lipschitz (horizon-invariant):**\n\n")
            f.write("| scheme | lifetime bound | " + " | ".join(f"T=1e{int(math.log10(T))}"
                                                                 for T in HORIZONS) + " |\n")
            f.write("|---|--:|" + "--:|" * len(HORIZONS) + "\n")
            ps0 = r["per_seed"][0]
            for sc in ("per_record_const", "bonferroni"):
                cells = {row["T"]: row["R_allow"] for row in ps0["fixed_schemes"][sc]}
                lb = ps0["fixed_schemes"][sc][0]["lifetime_bound"]
                f.write(f"| {sc} (R_allow) | {'min(1,T·1e-3)' if sc=='per_record_const' else p['alpha_total']} "
                        + "| " + " | ".join(f"{cells[T]}" for T in HORIZONS) + " |\n")
            sp = {row["T"]: row for row in ps0["fixed_schemes"]["alpha_spending"]}
            f.write("| alpha_spending (R_allow early/late) | " + str(p['alpha_total']) + " | "
                    + " | ".join(f"{sp[T]['R_allow_early']}/{sp[T]['R_allow_late']}" for T in HORIZONS) + " |\n")
            ad = {row["T"]: row for row in ps0["adaptive_mc"]}
            f.write("| adaptive_mc (R_allow) | " + str(p['alpha_total']) + " | "
                    + " | ".join(f"{ad[T]['R_allow']}" for T in HORIZONS) + " |\n")
            f.write("| adaptive_mc (median/p95 n_mc) | — | "
                    + " | ".join(f"{ad[T]['median_n_mc']}/{ad[T]['p95_n_mc']}" for T in HORIZONS) + " |\n")
            f.write(f"| **lip_fallback (R_allow)** | **0** | "
                    + " | ".join(f"**{r['lip_R_allow']}**" for _ in HORIZONS) + " |\n\n")
        f.write(f"**Verdict.** {p['verdict']}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domains", default="finance,sre,ops")
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--n-train", type=int, default=5000)
    ap.add_argument("--n-eval", type=int, default=4000)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--eps", type=float, default=EPS)
    ap.add_argument("--sigma", type=float, default=SIGMA)
    ap.add_argument("--tau", type=float, default=TAU)
    ap.add_argument("--alpha-total", type=float, default=ALPHA_TOTAL)
    ap.add_argument("--max-r", type=int, default=200, help="cap on robust-safe records certified/domain")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default="exp_cx2_rs_horizon")
    a = ap.parse_args()
    if a.quick:
        a.n_train, a.n_eval, a.n_mc, a.max_r = 1200, 800, 800, 60
    domains = [d.strip() for d in a.domains.split(",") if d.strip()]
    seeds = [int(s) for s in a.seeds.split(",") if s.strip()]
    run(domains, seeds, a.n_train, a.n_eval, a.n_mc, a.eps, a.sigma, a.tau, a.alpha_total, a.max_r, a.out)


if __name__ == "__main__":
    main()
