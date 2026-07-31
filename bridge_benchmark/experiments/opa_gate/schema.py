#!/usr/bin/env python3
"""
schema.py — typed-tool schema for the OPA-gate experiment, matched to the authored Rego policies.

Builds an `rt` (rule_table) in the SAME structure the existing utilities expect (FeatureEncoder,
oracle.discrete_swaps, oracle.get_rule, cert.smoothed_gate.certify) so they can be reused unchanged.
The rule thresholds in `rt` are placeholders used ONLY for structure (which (tool, action) have a rule,
field names); the actual safe/unsafe semantics come from OPA (see opa_oracle.py).
"""
from __future__ import annotations

import random
from pathlib import Path

_POL = Path(__file__).resolve().parent / "policies" / "authored"

# domain -> config. policy_field/direction drive the continuous worst-case probe (safe iff field <
# threshold, so the unsafe move is +eps on policy_field).
DOMAINS = {
    "finance": {
        "package": "opa_gate.finance", "rego": str(_POL / "finance.rego"),
        "privileged": "approve_transaction", "fallback": "manual_review",
        "tools": ["t_credit", "t_sanctions", "t_txmon"],
        "categorical_fields": {"jurisdiction": ["domestic", "eu", "high_risk", "sanctioned"],
                               "entity_type": ["individual", "sme", "corp"]},
        "numeric_fields": ["risk_score", "amount_norm", "confidence"],
        "policy_field": "risk_score", "field_range": (0.20, 0.80),
    },
    "sre": {
        "package": "opa_gate.sre", "rego": str(_POL / "sre.rego"),
        "privileged": "suppress_alert", "fallback": "page_on_call",
        "tools": ["t_latency", "t_errbudget", "t_saturation"],
        "categorical_fields": {"service_tier": ["tier3", "tier2", "tier1", "prod"],
                               "region": ["us", "eu", "apac"]},
        "numeric_fields": ["signal", "error_rate", "traffic"],
        "policy_field": "signal", "field_range": (0.20, 0.80),
    },
    "ops": {
        "package": "opa_gate.ops", "rego": str(_POL / "ops.rego"),
        "privileged": "allow_login", "fallback": "require_mfa",
        "tools": ["t_authn", "t_geoip", "t_device"],
        "categorical_fields": {"network": ["trusted", "normal", "new_device", "tor_exit"],
                               "device": ["managed", "byod", "unknown"]},
        "numeric_fields": ["login_risk", "geo_anomaly", "session_age"],
        "policy_field": "login_risk", "field_range": (0.20, 0.80),
    },
}


def build_rt(domain: str) -> dict:
    """rule_table compatible with FeatureEncoder / oracle.discrete_swaps / get_rule / certify."""
    d = DOMAINS[domain]
    priv, fb = d["privileged"], d["fallback"]
    # one structural rule per tool for the privileged action (empty categorical_context -> matches any
    # x1); threshold is a placeholder (semantics come from OPA, not from this number).
    rules = [{"tool_id": t, "candidate_action": priv, "categorical_context": {},
              "rule_type": "scalar_threshold", "field": d["policy_field"], "threshold": 0.5,
              "unsafe_direction": ">=", "valid_range": {d["policy_field"]: [0.0, 1.0]}}
             for t in d["tools"]]
    return {"domains": {domain: {
        "tools": list(d["tools"]),
        "categorical_fields": {k: list(v) for k, v in d["categorical_fields"].items()},
        "numeric_fields": list(d["numeric_fields"]),
        "candidate_actions": [priv, fb],
        "rules": rules,
    }}}


# Pre-registered sampling schemes (NEW_EXPS_8 gap 2). The input distribution is a registered degree of
# freedom: C% is a property of (policy, distribution over z) jointly. We report BOTH, labeled, mirroring
# the IEEE-CIS natural-vs-boundary structure — so "do not tune thresholds" is not silently satisfied
# while the same tuning happens through the sampler.
#   natural  : policy field uniform over the documented operating band field_range (= (0.20, 0.80)).
#   boundary : policy field clustered in the THRESHOLD band [min θ − ε, max θ + ε] where the
#              provenance-conditioned thresholds live (~0.48..0.66), so A/B/C are over-sampled.
SAMPLING_SCHEMES = ("natural", "boundary")
_BOUNDARY_BAND = (0.45, 0.70)


def sample_records(domain: str, n: int, seed: int = 0, scheme: str = "natural"):
    """Sample n typed returns z for the PRIVILEGED action under a REGISTERED sampling scheme
    ('natural' or 'boundary'). Numeric non-policy fields uniform; the policy field is drawn from the
    documented operating band (natural) or the threshold band (boundary). Labels and categories are
    assigned later by OPA (opa_oracle), NOT here."""
    if scheme not in SAMPLING_SCHEMES:
        raise ValueError(f"unknown sampling scheme {scheme!r} (use {SAMPLING_SCHEMES})")
    d = DOMAINS[domain]
    rng = random.Random(seed + (0 if scheme == "natural" else 9973))
    lo, hi = d["field_range"] if scheme == "natural" else _BOUNDARY_BAND
    recs = []
    for i in range(n):
        x1 = {f: rng.choice(vals) for f, vals in d["categorical_fields"].items()}
        num = {f: rng.uniform(0.0, 1.0) for f in d["numeric_fields"]}
        num[d["policy_field"]] = rng.uniform(lo, hi)
        recs.append({"id": f"opa-{domain}-{scheme[:3]}-{i:05d}", "domain": domain,
                     "tool_id": rng.choice(d["tools"]), "candidate_action": d["privileged"],
                     "categorical_fields": x1, "numeric_fields": num})
    return recs
