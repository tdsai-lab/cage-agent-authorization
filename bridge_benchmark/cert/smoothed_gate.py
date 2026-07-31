#!/usr/bin/env python3
"""
smoothed_gate.py — enumerative Gaussian randomized-smoothing certificate for the learned gate
s_theta(z, a), over the MVP threat set B_{1, eps} (PLAN3 sec.9).

For each reachable discrete state s = (t', x_1') in D_1(t, x_1):
    p_s   = P_{xi ~ N(0, sigma^2 I)} [ s_theta(t', x_1', x_2 + xi, a) = safe ]   (Monte Carlo)
    p_lb  = Clopper-Pearson one-sided lower bound (confidence 1 - alpha)
    ell_s(eps) = Phi( Phi^{-1}(p_lb) - eps / sigma )                            (Cohen 2019 bound)

Certificate variants (all action-indexed, over B_{1,eps}):
    discrete_only      : min_s p_lb_s            >= tau   (continuous radius 0)
    continuous_only    : ell_identity(eps)       >= tau   (no discrete swap)
    naive_composition  : discrete_only AND continuous_only
    hybrid             : min_s ell_s(eps)         >= tau   (sound for B_{1,eps})

Smoothing noise sigma and radius eps are in RAW numeric units (same space as the oracle threat set);
the encoder's per-field standardization is an internal fixed feature map applied after perturbation.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from scipy.stats import beta, norm

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "generators"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "models"))

from oracle import discrete_swaps, get_rule, _x1  # noqa: E402


def clopper_pearson_lower(k: int, n: int, alpha: float) -> float:
    if k <= 0:
        return 0.0
    if k >= n:
        return float(beta.ppf(alpha, k, 1))
    return float(beta.ppf(alpha, k, n - k + 1))


def cohen_lower(p_lb: float, eps: float, sigma: float) -> float:
    p_lb = min(max(p_lb, 1e-12), 1 - 1e-12)
    return float(norm.cdf(norm.ppf(p_lb) - eps / sigma))


def _states(rt, rec, d=1):
    """Reachable discrete states for the certificate's D_1, restricted to states that HAVE a rule for
    the candidate action — mirroring the analytic oracle, which skips no-rule states. A provenance
    swap to a tool that cannot produce this action is not a meaningful corruption (and would be an
    out-of-distribution query for the learned gate)."""
    dc = rt["domains"][rec["domain"]]
    a = rec["candidate_action"]
    x1 = _x1(rec)
    yield rec["tool_id"], dict(x1)
    for t2, x12, _r in discrete_swaps(dc, rec["tool_id"], x1, d):
        if get_rule(dc, t2, a, x12) is not None:
            yield t2, x12


def smoothed_p_safe(gate, rt, domain, tool, action, x1, x2_base, sigma, n_mc, rng):
    """Vectorized Monte-Carlo estimate of P[s_theta(state, x2+xi, a)=safe]; returns (k, n)."""
    enc = gate.enc
    v0 = np.asarray(enc.transform_point(domain, tool, action, x1, x2_base), dtype=np.float64)
    M = np.tile(v0, (n_mc, 1))
    start, fields, mean, std = enc.numeric_block()
    dom_fields = rt["domains"][domain]["numeric_fields"]
    for f in dom_fields:
        j = fields.index(f)
        col = start + j
        xi = rng.normal(0.0, sigma, size=n_mc)
        M[:, col] = (float(x2_base[f]) + xi - mean[j]) / std[j]
    proba = gate.est.predict_proba(M)[:, 1]
    k = int(np.sum(proba >= 0.5))
    return k, n_mc


def _seed_for(rec, seed):
    return seed + (hash(rec.get("id", "")) & 0xFFFF)


def per_state_bounds(gate, rt, rec, sigma, n_mc, alpha, seed=0):
    """Per discrete state: estimate p_s at the CLEAN x2 (delta = 0) and its Clopper-Pearson lower
    bound. Shared by certify() and the audit so the audit can recompute the eps penalty independently.
    """
    rng = np.random.default_rng(_seed_for(rec, seed))
    a = rec["candidate_action"]
    base = rec["numeric_fields"]
    out = []
    for tool, x1 in _states(rt, rec):
        k, n = smoothed_p_safe(gate, rt, rec["domain"], tool, a, x1, base, sigma, n_mc, rng)
        out.append({"tool": tool, "x1": x1, "is_identity": (tool == rec["tool_id"] and x1 == _x1(rec)),
                    "k": k, "n": n, "p_hat": k / n, "p_lb": clopper_pearson_lower(k, n, alpha)})
    return out


def certify(gate, rt, rec, sigma=0.25, eps=0.10, tau=0.95, n_mc=1000, alpha=1e-3, seed=0):
    a = rec["candidate_action"]
    # p_s is estimated at the CLEAN x2 (delta = 0); the eps radius is applied ONCE via cohen_lower.
    per_state = per_state_bounds(gate, rt, rec, sigma, n_mc, alpha, seed)
    for s in per_state:
        s["ell_eps"] = cohen_lower(s["p_lb"], eps, sigma)

    ident = next(s for s in per_state if s["is_identity"])
    min_p_lb = min(s["p_lb"] for s in per_state)       # discrete-only (eps = 0)
    worst = min(per_state, key=lambda s: s["ell_eps"])  # state achieving min_s ell_s(eps)
    min_ell = worst["ell_eps"]                          # hybrid lower bound

    discrete_only = min_p_lb >= tau
    continuous_only = ident["ell_eps"] >= tau
    naive = discrete_only and continuous_only
    hybrid = min_ell >= tau

    return {
        "id": rec.get("id"), "domain": rec["domain"], "candidate_action": a,
        "category": rec.get("category"), "safety_label": rec.get("safety_label"),
        "allow": bool(hybrid),
        "certificate_type": "enumerate_discrete_gaussian_rs",
        "discrete_certification": "exact_enumeration",
        "continuous_certification": "gaussian_randomized_smoothing",
        "d": 1, "epsilon": eps, "sigma": sigma, "tau": tau, "n_mc": n_mc, "alpha": alpha,
        "lower_bound_probability": round(min_ell, 4),
        "confidence": round(1 - alpha, 4),
        "worst_discrete_state": {"tool_id": worst["tool"], "categorical_fields": worst["x1"],
                                 "is_identity": worst["is_identity"], "p_hat": round(worst["p_hat"], 4),
                                 "p_lb": round(worst["p_lb"], 4)},
        "n_states": len(per_state),
        "cert_allow": {"discrete_only": bool(discrete_only), "continuous_only": bool(continuous_only),
                       "naive_composition": bool(naive), "hybrid": bool(hybrid)},
        "p_identity_hat": round(ident["p_hat"], 4),
    }


if __name__ == "__main__":
    import json
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "models"))
    import warnings
    warnings.filterwarnings("ignore")
    from baselines import train_all, train_certified_gate

    models, (tr, va, te), rt = train_all()
    gate = train_certified_gate(tr, rt, sigma=0.25, n_aug=4)
    # one C point and one R point
    c = next(r for r in te if r["category"] == "C")
    rpt = next(r for r in te if r["category"] == "R")
    for tag, rec in [("C", c), ("R", rpt)]:
        print(tag, json.dumps(certify(gate, rt, rec, n_mc=1000), indent=2))
