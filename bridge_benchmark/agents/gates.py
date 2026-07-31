#!/usr/bin/env python3
"""
gates.py — the four authorization gates compared in Experiment F (TASK_REAL_LLM_AGENT_EXP §9).

A gate decides whether the LLM-proposed PRIVILEGED action may execute on the (possibly corrupted)
observed typed tool return z. The gate never sees the LLM rationale; it sees only (z, action).

    none      — always allow (undefended baseline).
    learned   — point prediction s_theta(z, a) >= 0.5 (uncertified).
    certified — the MVP "exact-discrete / smoothed-continuous" certificate: exact enumeration over the
                valid d=1 discrete neighbours of the provenance state, Gaussian randomized smoothing on
                the numeric channel per branch, allow iff  min_{s'} lower_bound(s', x, a) >= tau.
                (delegates to cert.smoothed_gate.certify — same certificate as the rest of the project.)
    oracle    — analytic Safe(z, a) (upper bound; not a deployable gate).

evaluate(z, action) -> (allow: bool, lower_bound: float | None)

z is the internal typed-return dict: {domain, tool_id, candidate_action, categorical_fields,
numeric_fields, id?}. `domain` is the internal rule-table key (here "synthetic").
"""
from __future__ import annotations

import sys
from pathlib import Path

_root = Path(__file__).resolve().parents[1]
for p in ("generators", "models", "cert"):
    sys.path.insert(0, str(_root / p))

from oracle import safe, get_rule, _x1  # noqa: E402
from smoothed_gate import certify  # noqa: E402


def _has_rule(rt, z, action) -> bool:
    dc = rt["domains"][z["domain"]]
    return get_rule(dc, z["tool_id"], action, _x1(z)) is not None


class BaseGate:
    kind = "base"

    def evaluate(self, z: dict, action: str):  # -> (allow, lower_bound)
        raise NotImplementedError


class NoneGate(BaseGate):
    kind = "none"

    def evaluate(self, z, action):
        return True, None


class LearnedGate(BaseGate):
    kind = "learned"

    def __init__(self, model):
        self.model = model

    def evaluate(self, z, action):
        p = self.model.proba_safe_point(z["domain"], z["tool_id"], action,
                                        _x1(z), z["numeric_fields"])
        return p >= 0.5, float(p)


class CertifiedGate(BaseGate):
    kind = "certified"

    def __init__(self, model, rt, tau=0.90, eps=0.10, sigma=0.10, n_mc=2000, alpha=1e-3):
        self.model, self.rt = model, rt
        self.tau, self.eps, self.sigma, self.n_mc, self.alpha = tau, eps, sigma, n_mc, alpha

    def evaluate(self, z, action):
        rec = {"domain": z["domain"], "tool_id": z["tool_id"], "candidate_action": action,
               "categorical_fields": _x1(z), "numeric_fields": z["numeric_fields"],
               "id": z.get("id", "")}
        c = certify(self.model, self.rt, rec, sigma=self.sigma, eps=self.eps, tau=self.tau,
                    n_mc=self.n_mc, alpha=self.alpha)
        return bool(c["allow"]), float(c["lower_bound_probability"])


class RuleTypedGate(BaseGate):
    """Deterministic typed-gate baseline (NEW_EXPS_5 Task 2): evaluate the KNOWN policy rules on the
    typed object z at the OBSERVED point (pointwise safety), using ONLY typed fields — never the
    display note m. It is a deployable, non-instructable typed boundary, but it is NOT robust (it does
    not certify over B_{1,eps}), so it passes TM1 (clean-correct on U, invariant to m) yet is the kind
    of gate TM2 attacks. In this synthetic setting it coincides with the pointwise oracle on z; the
    distinction is intent: rules are the deployable policy, the oracle is the ground truth."""

    kind = "rule"

    def __init__(self, rt):
        self.rt = rt

    def evaluate(self, z, action):
        if not _has_rule(self.rt, z, action):
            return True, None          # non-privileged / no-rule action: safe fallback
        rec = {"domain": z["domain"], "tool_id": z["tool_id"], "candidate_action": action,
               "categorical_fields": _x1(z), "numeric_fields": z["numeric_fields"]}
        return bool(safe(rec, action, self.rt)), None


class OracleGate(BaseGate):
    """Analytic upper bound. Not deployable — uses the ground-truth oracle."""

    kind = "oracle"

    def __init__(self, rt):
        self.rt = rt

    def evaluate(self, z, action):
        if not _has_rule(self.rt, z, action):
            return True, None          # non-privileged / no-rule action: safe fallback
        rec = {"domain": z["domain"], "tool_id": z["tool_id"], "candidate_action": action,
               "categorical_fields": _x1(z), "numeric_fields": z["numeric_fields"]}
        return bool(safe(rec, action, self.rt)), None


def make_gate(kind: str, *, model=None, rt=None, tau=0.90, eps=0.10, sigma=0.10, n_mc=2000,
              alpha=1e-3) -> BaseGate:
    if kind == "none":
        return NoneGate()
    if kind == "learned":
        return LearnedGate(model)
    if kind == "certified":
        return CertifiedGate(model, rt, tau=tau, eps=eps, sigma=sigma, n_mc=n_mc, alpha=alpha)
    if kind in ("rule", "rule_typed_gate"):
        return RuleTypedGate(rt)
    if kind == "oracle":
        return OracleGate(rt)
    raise ValueError(f"unknown gate {kind!r}")
