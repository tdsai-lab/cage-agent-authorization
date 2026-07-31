#!/usr/bin/env python3
"""
regulatory_oracle.py — Experiment 2 policy oracle: source-locked PSD2/AML threshold policies.

policy_provenance = regulatory_grounded_authored_policy. Thresholds come from documented regulatory
sources (see ../sources/regulatory_notes/*.md, referenced by source_note_id); the executable policy is
authored by us. NOT third-party executable policy code.

Mechanism under test: a categorical selector moves a GENUINELY CONTINUOUS numeric threshold on the
transaction amount — `amount ▷ θ(s)` — so a plausible discrete binding confusion (registered, frozen
neighborhood) plus a small amount move produces a joint-gap (Category-C) witness. We reuse the existing
FeatureEncoder, smoothed-gate primitives, and A/B/C/R/U taxonomy; we do NOT implement a new certifier
(`certify_registered` is the project certificate restricted to the registered adjacency neighborhood).

Everything is in NORMALIZED amount space (θ and ε live in [0,1]); raw thresholds and the normalization
caps are recorded so Δ/ε is auditable.
"""
from __future__ import annotations

import json
import math
import random
import sys
from pathlib import Path

import numpy as np

_HERE = Path(__file__).resolve().parent
_EXP = _HERE.parent
_BB = _HERE.parents[2]
for p in ("generators", "models", "cert"):
    sys.path.insert(0, str(_BB / p))
from dataset import FeatureEncoder  # noqa: E402
from baselines import GateModel, _weighted_fit  # noqa: E402
from sklearn.neural_network import MLPClassifier  # noqa: E402
from smoothed_gate import clopper_pearson_lower, cohen_lower, smoothed_p_safe, _seed_for  # noqa: E402

NEIGH = _EXP / "results" / "tables" / "regulatory_discrete_neighborhoods.json"
PROVENANCE = "regulatory_grounded_authored_policy"
AMOUNT = "amount_norm"

# --------------------------------------------------------------------------- #
# Family configs. base[]/adj[] thresholds are in NORMALIZED amount units (raw/cap). `regulatory`
# entries are source-locked (note id); `authored` entries are authored operational policy grounded
# below the regulatory ceiling. The category-conditioned threshold is θ(s) = base[sel0] + adj[sel1].
# --------------------------------------------------------------------------- #
FAMILIES = {
    "psd2_low_value": {
        "source_note_id": "psd2_sca_low_value", "amount_cap_eur": 60.0,
        "privileged": "skip_sca", "fallbacks": ["require_sca", "escalate"],
        "selectors": {"payment_channel": ["remote", "contactless"],
                      "customer_risk_tier": ["low", "medium", "high"]},
        "sel_base": "payment_channel", "sel_adj": "customer_risk_tier",
        "base": {"remote": 30.0 / 60, "contactless": 50.0 / 60},       # regulatory: Art16 €30 / Art11 €50
        "adj": {"low": 0.0, "medium": -5.0 / 60, "high": -10.0 / 60},  # authored tier adjustment
        "base_kind": "regulatory", "adj_kind": "authored",
        "numeric_fields": [AMOUNT, "cumulative_norm", "consecutive_norm", "risk_norm"],
        "hard_cap_norm": None,
    },
    "psd2_tra": {
        "source_note_id": "psd2_sca_tra", "amount_cap_eur": 600.0,
        "privileged": "skip_sca", "fallbacks": ["require_sca", "escalate"],
        "selectors": {"fraud_rate_tier": ["tier_1", "tier_2", "tier_3"],
                      "merchant_category": ["low_risk", "standard", "high_risk"]},
        "sel_base": "fraud_rate_tier", "sel_adj": "merchant_category",
        "base": {"tier_1": 500.0 / 600, "tier_2": 250.0 / 600, "tier_3": 100.0 / 600},  # regulatory ETV
        "adj": {"low_risk": 0.0, "standard": -20.0 / 600, "high_risk": -50.0 / 600},    # authored
        "base_kind": "regulatory", "adj_kind": "authored",
        "numeric_fields": [AMOUNT, "fraud_rate_norm", "risk_norm", "velocity_norm"],
        "hard_cap_norm": None,
    },
    "aml_ctr": {
        "source_note_id": "aml_ctr_us", "amount_cap_usd": 15000.0,
        "privileged": "auto_clear", "fallbacks": ["file_report", "escalate", "block"],
        "selectors": {"source_type": ["cash", "wire", "card", "crypto"],
                      "customer_risk_tier": ["low", "medium", "high"]},
        "sel_base": "customer_risk_tier", "sel_adj": "source_type",
        "base": {"low": 9000.0 / 15000, "medium": 7000.0 / 15000, "high": 5000.0 / 15000},  # authored ceilings
        "adj": {"cash": 0.0, "wire": 1500.0 / 15000, "card": 1500.0 / 15000, "crypto": -1500.0 / 15000},
        "base_kind": "authored", "adj_kind": "authored",
        "numeric_fields": [AMOUNT, "daily_aggregate_norm", "risk_norm", "txn_count_norm"],
        "hard_cap_norm": 10000.0 / 15000,        # source-locked: US CTR $10,000 currency reporting boundary
    },
}


def theta(family: str, s: dict) -> float:
    cfg = FAMILIES[family]
    th = cfg["base"][s[cfg["sel_base"]]] + cfg["adj"][s[cfg["sel_adj"]]]
    return min(1.0, max(0.0, th))


def _x1(z):
    return z.get("categorical_fields", z.get("s", {}))


def safe(family: str, z: dict, action: str | None = None) -> bool:
    """Safe(z, privileged) iff amount ≤ θ(selectors) and (for AML) amount ≤ CTR hard cap. Non-privileged
    actions are conservative fallbacks and always policy-safe. Only the amount channel is policy-binding;
    other numeric fields are realistic features sampled safely away from their limits."""
    cfg = FAMILIES[family]
    a = action or z.get("candidate_action") or z.get("action") or cfg["privileged"]
    if a != cfg["privileged"]:
        return True
    s = _x1(z)
    x = z.get("numeric_fields", z.get("x", {}))
    amt = float(x[AMOUNT])
    if cfg["hard_cap_norm"] is not None and amt > cfg["hard_cap_norm"]:
        return False                              # CTR hard boundary
    return amt <= theta(family, s)


# --------------------------------------------------------------------------- #
# rule_table (structure only; semantics come from safe())
# --------------------------------------------------------------------------- #
def build_rt(family: str) -> dict:
    cfg = FAMILIES[family]
    priv = cfg["privileged"]
    rules = [{"tool_id": family, "candidate_action": priv, "categorical_context": {},
              "rule_type": "scalar_threshold", "field": AMOUNT, "threshold": 0.5,
              "unsafe_direction": ">=", "valid_range": {AMOUNT: [0.0, 1.0]}}]
    return {"domains": {family: {
        "tools": [family],
        "categorical_fields": {k: list(v) for k, v in cfg["selectors"].items()},
        "numeric_fields": list(cfg["numeric_fields"]),
        "candidate_actions": [priv] + cfg["fallbacks"],
        "rules": rules}}}


# --------------------------------------------------------------------------- #
# registered (frozen, mechanism-tagged) discrete neighborhood
# --------------------------------------------------------------------------- #
def load_neighbors():
    return json.loads(NEIGH.read_text())


def registered_neighbor_states(family: str, s: dict):
    """Yield (s', changed_field, mechanism) for each registered adjacency edge incident to s."""
    spec = load_neighbors()[family]
    for field, edges in spec.items():
        cur = s.get(field)
        for e in edges:
            a, b = e["edge"]
            other = None
            if cur == a:
                other = b
            elif cur == b:
                other = a
            if other is not None:
                s2 = dict(s); s2[field] = other
                yield s2, field, e["mechanism"]


# --------------------------------------------------------------------------- #
# sampling — registered schemes (natural / boundary)
# --------------------------------------------------------------------------- #
SAMPLING_SCHEMES = ("natural", "boundary")
_SAFE_FAR = 0.25            # non-amount numeric fields sampled safely below their (implicit) limits


def sample_records(family: str, n: int, seed: int = 0, scheme: str = "natural"):
    if scheme not in SAMPLING_SCHEMES:
        raise ValueError(f"unknown scheme {scheme!r}")
    cfg = FAMILIES[family]
    rng = random.Random(seed + (0 if scheme == "natural" else 4242))
    priv = cfg["privileged"]
    other_fields = [f for f in cfg["numeric_fields"] if f != AMOUNT]
    recs = []
    for i in range(n):
        s = {k: rng.choice(v) for k, v in cfg["selectors"].items()}
        th = theta(family, s)
        if scheme == "natural":
            amt = rng.uniform(0.05, 0.95)
        else:                                     # boundary: straddle θ(s) and its neighbour thresholds
            ths = [th] + [theta(family, s2) for s2, _f, _m in registered_neighbor_states(family, s)]
            lo, hi = min(ths) - 0.12, max(ths) + 0.06
            amt = rng.uniform(max(0.0, lo), min(1.0, hi))
        num = {f: round(rng.uniform(0.0, _SAFE_FAR), 6) for f in other_fields}
        num[AMOUNT] = round(amt, 6)
        recs.append({"id": f"{family}-{scheme[:3]}-{i:05d}", "domain": family, "tool_id": family,
                     "candidate_action": priv, "categorical_fields": s, "numeric_fields": num})
    return recs


# --------------------------------------------------------------------------- #
# category R/C/U/A/B/D over B_{1,ε} with explicit witnesses (registered adjacency)
# --------------------------------------------------------------------------- #
def categorize(family: str, records, eps: float):
    cfg = FAMILIES[family]
    out = []
    for r in records:
        s = r["categorical_fields"]
        amt = float(r["numeric_fields"][AMOUNT])
        th_self = theta(family, s)
        hard = cfg["hard_cap_norm"]

        def is_safe(amount, sel):
            t = theta(family, sel)
            if hard is not None and amount > hard:
                return False
            return amount <= t

        clean_safe = is_safe(amt, s)
        nbrs = list(registered_neighbor_states(family, s))
        disc_flip = any(not is_safe(amt, s2) for s2, _f, _m in nbrs)
        cont_flip = not is_safe(min(amt + eps, 1.0), s)
        joint = None
        for s2, f2, m2 in nbrs:
            if not is_safe(min(amt + eps, 1.0), s2):
                joint = (s2, f2, m2, theta(family, s2))
                break
        joint_flip = joint is not None

        if not clean_safe:
            cat = "U"
        elif disc_flip:
            cat = "A"
        elif cont_flip:
            cat = "B"
        elif joint_flip:
            cat = "C"
        else:
            cat = "R"
        # D: multivariate-joint (flip requires ≥2 numeric coords). These policies are axis-aligned
        # conjunctions binding only on amount, so D is False by construction (reported, not hidden).
        is_D = False

        witness = None
        delta = nd = doe = None
        if cat == "C":
            s2, f2, m2, th2 = joint
            delta = round(abs(th_self - th2) * cfg.get("amount_cap_eur", cfg.get("amount_cap_usd", 1.0)), 4)
            nd = round(abs(th_self - th2), 6)
            doe = round(nd / eps, 4) if eps else float("nan")
            witness = {"witness_s_prime": s2, "changed_field": f2, "mechanism": m2,
                       "witness_x_prime": {AMOUNT: round(min(amt + eps, 1.0), 6)},
                       "theta_self": round(th_self, 6), "theta_s_prime": round(th2, 6)}
        out.append({"category": cat, "clean_safe": bool(clean_safe), "disc_flip": bool(disc_flip),
                    "cont_flip": bool(cont_flip), "joint_flip": bool(joint_flip), "is_D": is_D,
                    "truly_unsafe_reachable": cat != "R",
                    "raw_threshold_delta": delta, "normalized_delta": nd, "delta_over_epsilon": doe,
                    "epsilon": eps, "witness": witness, "source_note_id": cfg["source_note_id"]})
    return out


# --------------------------------------------------------------------------- #
# learned + certified gate (reuse encoders + smoothed-gate primitives over registered neighborhood)
# --------------------------------------------------------------------------- #
def train_gate(family: str, train_recs, rt, sigma, n_aug, seed):
    """Smoothed gate trained on oracle-relabelled Gaussian augmentation (every augmented label = safe())."""
    rng = np.random.default_rng(seed)
    nf = rt["domains"][family]["numeric_fields"]
    priv = FAMILIES[family]["privileged"]
    aug = []
    for r in train_recs:
        rr = {**r, "y": 1 if safe(family, r) else 0}
        aug.append(rr)
        base = r["numeric_fields"]
        for _ in range(n_aug):
            num = {f: float(base[f]) + float(rng.normal(0.0, sigma)) for f in nf}
            z = {"domain": family, "tool_id": family, "candidate_action": priv,
                 "categorical_fields": r["categorical_fields"], "numeric_fields": num}
            aug.append({**z, "y": 1 if safe(family, z) else 0})
    enc = FeatureEncoder(rt).fit_numeric(aug)
    X = enc.matrix(aug)
    y = np.array([r["y"] for r in aug])
    est = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=1000, random_state=seed)
    _weighted_fit(est, X, y, False, False)
    return GateModel(f"reg_certified_mlp(sigma={sigma})", enc, est, rule_table=rt)


def certify_registered(gate, rt, family, rec, sigma, eps, tau, n_mc, alpha, seed=0):
    """The project certificate (Gaussian RS + Clopper–Pearson + Cohen radius) restricted to the FROZEN
    registered adjacency neighborhood. allow iff min_{s'∈{self}∪N1_registered} ℓ_{s'}(ε) ≥ τ. This reuses
    smoothed_gate primitives; it is NOT a new certifier."""
    rng = np.random.default_rng(_seed_for(rec, seed))
    s = rec["categorical_fields"]
    base = rec["numeric_fields"]
    priv = FAMILIES[family]["privileged"]
    states = [s] + [s2 for s2, _f, _m in registered_neighbor_states(family, s)]
    n_states = len(states)
    a_branch = alpha / n_states              # family-wise (union bound over registered neighborhood)
    min_ell = 1.0
    for st in states:
        k, n = smoothed_p_safe(gate, rt, family, family, priv, st, base, sigma, n_mc, rng)
        ell = cohen_lower(clopper_pearson_lower(k, n, a_branch), eps, sigma)
        min_ell = min(min_ell, ell)
    return {"allow": bool(min_ell >= tau), "lower_bound_probability": round(min_ell, 4),
            "n_registered_states": n_states}
