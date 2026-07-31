#!/usr/bin/env python3
"""
ieee_cis_policy.py — the CONSTRUCTED typed provenance-dependent authorization policy for the
IEEE-CIS real-data-grounded experiment.

The real dataset grounds the continuous channel (a held-out risk model produces risk_score, and the
other x2 fields are real transaction marginals). The authorization label is NOT the fraud label; it
is a constructed threshold policy over a provenance-dependent threshold:

    Safe(z, approve_transaction) = 1  <=>  risk_score <= theta_t(x1)

with two provenance regimes (loose tools trust more -> higher threshold):

    theta_strict(x1) = theta(x1)
    theta_loose(x1)  = theta(x1) + delta

Discrete budget d=1 = a single provenance swap within a related pair (loose <-> strict). Only the
risk_score coordinate is moved continuously (||.||_2 <= eps); the other x2 fields stay fixed (they
are real marginals used as gate features, not policy-binding). This is exactly the scalar-threshold
geometry of the synthetic oracle, so the analytic Category-C interval is

    r in (theta - eps, theta]  AND  r <= theta + delta - eps      (length min(delta, eps))

This module provides BOTH an independent analytic category and a brute-force enumeration so tests can
assert they agree (and agree with the shared oracle.py over the generated rule_table).
"""
from __future__ import annotations

import sys
from pathlib import Path

_GEN = Path(__file__).resolve().parents[1] / "generators"
sys.path.insert(0, str(_GEN))

DOMAIN = "finance_fraud_authorization"
ACTION = "approve_transaction"
RISK_FIELD = "risk_score"

# four provenance tools; loose tools trust the surfaced state more (higher threshold => +delta)
LOOSE_TOOLS = ("payment_gateway_loose", "manual_screen_loose")
STRICT_TOOLS = ("identity_risk_strict", "device_risk_strict")
TOOLS = ("payment_gateway_loose", "identity_risk_strict",
         "device_risk_strict", "manual_screen_loose")
# related discrete-neighbour pairs (a swap stays within a pair; never across unrelated provenances)
SWAP_PAIRS = {
    "payment_gateway_loose": "identity_risk_strict",
    "identity_risk_strict": "payment_gateway_loose",
    "manual_screen_loose": "device_risk_strict",
    "device_risk_strict": "manual_screen_loose",
}

# x2 (continuous) channel: risk_score is policy-binding; the rest are real marginals (gate features)
NUMERIC_FIELDS = ["risk_score", "amount_norm", "dist1_norm", "dist2_norm",
                  "c_mean_norm", "d_mean_norm", "v_mean_norm"]
# x1 (categorical) channel
CATEGORICAL_FIELDS = {
    "ProductCD": ["W", "C", "R", "H", "S"],
    "card4": ["visa", "mastercard", "amex", "discover"],
    "card6": ["debit", "credit", "charge card"],
    "amount_band": ["low", "medium", "high", "very_high"],
    "email_domain_match": ["same", "different", "missing"],
}


def is_loose(tool: str) -> bool:
    return tool in LOOSE_TOOLS


def theta_x1(theta_base: float, x1: dict, use_categorical_adjust: bool = False) -> float:
    """Per-state base threshold. The categorical adjustment is OPTIONAL (off by default in v1 so the
    discrete witness is a pure provenance swap and the analytic C-interval stays clean)."""
    theta = float(theta_base)
    if use_categorical_adjust:
        if x1.get("amount_band") == "very_high":
            theta -= 0.03
        if x1.get("card6") == "credit":
            theta -= 0.02
    return min(0.95, max(0.05, theta))


def threshold_for_tool(theta_base: float, tool: str, x1: dict, delta: float,
                       use_categorical_adjust: bool = False) -> float:
    t = theta_x1(theta_base, x1, use_categorical_adjust)
    return min(0.95, max(0.05, t + (delta if is_loose(tool) else 0.0)))


def safe(risk: float, tool: str, x1: dict, theta_base: float, delta: float,
         use_categorical_adjust: bool = False) -> bool:
    """Safe(z, approve) = 1 iff risk_score <= theta_t(x1)."""
    return float(risk) <= threshold_for_tool(theta_base, tool, x1, delta, use_categorical_adjust)


# --------------------------------------------------------------------------- #
# discrete neighbourhood (d=1): the related-pair provenance swap (x1 fixed in v1)
# --------------------------------------------------------------------------- #
def discrete_neighbors(tool: str):
    """Yield the d=1 provenance swap target(s) within the related pair (excludes identity)."""
    partner = SWAP_PAIRS.get(tool)
    if partner is not None:
        yield partner


# --------------------------------------------------------------------------- #
# analytic category (independent of oracle.py)
# --------------------------------------------------------------------------- #
def analytic_category(risk: float, tool: str, x1: dict, theta_base: float, delta: float,
                      eps: float, use_categorical_adjust: bool = False) -> dict:
    """A/B/C/R/U via the scalar-threshold geometry. Continuous move acts on risk_score only.

    clean_safe        : risk <= theta_t
    discrete_unsafe   : some related swap t' has risk > theta_t'        (eps = 0)
    continuous_unsafe : risk + eps > theta_t                            (own tool)
    joint_unsafe      : some related swap t' has risk + eps > theta_t'
    """
    r = float(risk)
    th_self = threshold_for_tool(theta_base, tool, x1, delta, use_categorical_adjust)
    clean_safe = r <= th_self
    nbrs = list(discrete_neighbors(tool))
    th_nbrs = [threshold_for_tool(theta_base, t2, x1, delta, use_categorical_adjust) for t2 in nbrs]

    disc_unsafe = any(r > th for th in th_nbrs)
    cont_unsafe = (r + eps) > th_self
    joint_unsafe = any((r + eps) > th for th in th_nbrs)

    if not clean_safe:
        cat = "U"
    elif disc_unsafe:
        cat = "A"
    elif cont_unsafe:
        cat = "B"
    elif joint_unsafe:
        cat = "C"
    else:
        cat = "R"

    witness = None
    if cat in ("A", "C"):
        # witness = the related swap that flips (after an <=eps risk move for C; at eps=0 for A)
        for t2, th in zip(nbrs, th_nbrs):
            flips_joint = (r + eps) > th
            flips_disc = r > th
            if (cat == "A" and flips_disc) or (cat == "C" and flips_joint):
                r_prime = min(r + eps, 1.0) if cat == "C" else r
                witness = {"type": "joint" if cat == "C" else "discrete",
                           "tool_id": t2, "x1": dict(x1),
                           "risk_score_witness": round(r_prime, 6),
                           "threshold_for_witness": round(th, 6), "label": 0}
                break
    return {"category": cat, "clean_safe": clean_safe, "discrete_only_unsafe": disc_unsafe,
            "continuous_only_unsafe": cont_unsafe, "joint_unsafe": joint_unsafe,
            "threshold_self": round(th_self, 6), "witness": witness}


def brute_force_category(risk: float, tool: str, x1: dict, theta_base: float, delta: float,
                         eps: float, use_categorical_adjust: bool = False) -> str:
    """Enumerate the d=1 provenance swaps and the risk-score perturbation endpoints {r, r+eps, r-eps}
    (clipped to [0,1]); assign the category from realized (un)safe flips. Used to cross-check the
    analytic label on fixtures."""
    r = float(risk)
    r_endpoints = [r, min(r + eps, 1.0), max(r - eps, 0.0)]
    states = [tool] + list(discrete_neighbors(tool))

    clean_safe = safe(r, tool, x1, theta_base, delta, use_categorical_adjust)
    disc_unsafe = any(not safe(r, t2, x1, theta_base, delta, use_categorical_adjust)
                      for t2 in discrete_neighbors(tool))
    cont_unsafe = any(not safe(rp, tool, x1, theta_base, delta, use_categorical_adjust)
                      for rp in r_endpoints)
    joint_unsafe = any(not safe(rp, t2, x1, theta_base, delta, use_categorical_adjust)
                       for t2 in states for rp in r_endpoints)

    if not clean_safe:
        return "U"
    if disc_unsafe:
        return "A"
    if cont_unsafe:
        return "B"
    if joint_unsafe:
        return "C"
    return "R"


# --------------------------------------------------------------------------- #
# rule_table in the EXISTING schema (so oracle.py / FeatureEncoder / smoothed_gate run unchanged)
# --------------------------------------------------------------------------- #
def build_rule_table(theta_base: float, delta: float, use_categorical_adjust: bool = False) -> dict:
    """One domain, one action, four provenance tools. Scalar-threshold rule on risk_score:
    unsafe iff risk_score >= threshold_t. Loose tools get threshold = theta_base + delta, strict get
    theta_base. (Categorical theta adjustment is off by default; when on it is encoded as
    threshold_offsets so the shared oracle stays consistent with this module.)"""
    offsets = {}
    if use_categorical_adjust:
        offsets = {"amount_band": {"very_high": -0.03}, "card6": {"credit": -0.02}}
    rules = []
    for tool in TOOLS:
        thr = min(0.95, max(0.05, theta_base + (delta if is_loose(tool) else 0.0)))
        rule = {"domain": DOMAIN, "tool_id": tool, "candidate_action": ACTION,
                "categorical_context": {}, "rule_family": "scalar_threshold",
                "numeric_field": RISK_FIELD, "unsafe_direction": ">=", "threshold": thr}
        if offsets:
            rule["threshold_offsets"] = offsets
        rules.append(rule)
    dc = {"tools": list(TOOLS), "numeric_fields": list(NUMERIC_FIELDS),
          "categorical_fields": {k: list(v) for k, v in CATEGORICAL_FIELDS.items()},
          "candidate_actions": [ACTION], "rules": rules}
    return {"meta": {"realdata": True, "source": "ieee_cis", "theta_base": theta_base,
                     "delta": delta, "K": len(TOOLS), "k": len(NUMERIC_FIELDS),
                     "use_categorical_adjust": use_categorical_adjust},
            "mvp": {"discrete_budget_mvp": 1}, "domains": {DOMAIN: dc}}


def c_interval(theta_base: float, delta: float, eps: float, x1: dict | None = None,
               use_categorical_adjust: bool = False) -> tuple[float, float]:
    """The analytic risk_score interval producing Category C for a LOOSE-tool record:
    (theta - eps, theta] intersect (-inf, theta + delta - eps].  Returns (lo, hi]; empty if lo>=hi."""
    th = theta_x1(theta_base, x1 or {}, use_categorical_adjust)
    lo = th - eps
    hi = min(th, th + delta - eps)
    return lo, hi
