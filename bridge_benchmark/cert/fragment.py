#!/usr/bin/env python3
"""
fragment.py — CAGE-Exact verified-affine POLICY FRAGMENT (implementation under test for EXP-CX3, the
empirical leg of paper A4). The formal leg is in the paper: see Supplement, Definition 1
(verified affine fragment) + Proposition 7 (support-function robust test). This module IMPLEMENTS Def 1 /
Prop 7 and is validated differentially against independent oracles by `experiments/cx3_differential.py`.
If the code disagrees with Def 1 / Prop 7, the CODE is wrong (never the test / never the definition).

FRAGMENT (Definition 1). A policy is IN-FRAGMENT iff it is:
  * finite categorical branching over the provenance-like key s' (a finite value set), AND
  * per branch, a finite CONJUNCTION of AFFINE numeric constraints  w_j · x <= b_j(s', a)
    (w_j a constant real vector over the k numeric fields; b_j a per-(branch, action) constant).
Anything else — disjunction over numeric constraints, nonlinearity (products/powers), division by a field,
string/regex ops on numeric-bearing fields, unbounded categorical space — is OUT-OF-FRAGMENT and MUST be
refused as `Unsupported` (no silent approximation).

ROBUST TEST (Proposition 7). A return (s, x, a) is robust-safe over B_{d,eps} (<= d categorical swaps of s
within the policy's own value set AND ||x'-x||_2 <= eps) iff for EVERY branch s' in N_d(s) and EVERY
constraint j of that branch:   w_j · x + eps * ||w_j||_2 <= b_j(s', a).
(The support function of the L2 eps-ball for the linear form w_j is eps*||w_j||_2; ties at exact equality
are SAFE, matching the closed unsafe set convention `<=`.) Cost O(|N_d(s)| * m * k).
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass


class Unsupported(Exception):
    """Raised/returned when a policy is outside the verified fragment (Definition 1). Never approximate."""
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Constraint:
    w: tuple            # length-k real weight vector (w_j)
    b: float            # per-(branch, action) bound; safe side is w·x <= b

    def wnorm(self) -> float:
        return math.sqrt(sum(float(c) * float(c) for c in self.w))


@dataclass(frozen=True)
class FragmentPolicy:
    numeric_fields: tuple            # ordered k numeric field names
    cat_field: str                   # the provenance-like categorical key (N_d swaps its value)
    cat_values: tuple                # finite branch set
    action: str                      # candidate action (b may depend on (branch, action); action fixed)
    branches: dict                   # cat_value -> tuple[Constraint, ...]  (per-(branch,action) bounds)

    @property
    def k(self) -> int:
        return len(self.numeric_fields)


# --------------------------------------------------------------------------- #
# parse_policy — syntactic membership on the policy spec (the "AST").
# --------------------------------------------------------------------------- #
_OUT_MARKERS = ("numeric_disjunction", "nonlinear", "division", "regex", "unbounded_categorical")


def parse_policy(spec: dict) -> FragmentPolicy:
    """Decide fragment membership on the structured policy spec (mirrors an AST walk). Returns a
    FragmentPolicy or raises Unsupported. NO silent approximation — any non-fragment feature is refused."""
    if not isinstance(spec, dict):
        raise Unsupported("policy spec is not a structured object")
    # explicit out-of-fragment feature markers (the generator tags disqualifying constructs)
    for mk in _OUT_MARKERS:
        if spec.get(mk):
            raise Unsupported(f"non-fragment construct: {mk}")
    nf = spec.get("numeric_fields")
    if not isinstance(nf, (list, tuple)) or not nf:
        raise Unsupported("missing/empty numeric_fields")
    k = len(nf)
    cat_field = spec.get("cat_field")
    cat_values = spec.get("cat_values")
    if not isinstance(cat_field, str):
        raise Unsupported("missing categorical key")
    if not isinstance(cat_values, (list, tuple)) or not cat_values:
        raise Unsupported("unbounded/empty categorical space")     # unbounded branching => refuse
    branches_in = spec.get("branches")
    if not isinstance(branches_in, dict):
        raise Unsupported("missing branches")
    branches = {}
    for sv in cat_values:
        cons_in = branches_in.get(sv)
        if not isinstance(cons_in, (list, tuple)):
            raise Unsupported(f"branch {sv!r} is not a finite conjunction list")
        cons = []
        for c in cons_in:                                          # each must be an affine w·x <= b
            if not isinstance(c, dict) or "w" not in c or "b" not in c:
                raise Unsupported("constraint is not affine {w, b}")
            w = c["w"]
            if isinstance(w, dict):
                w = [float(w.get(f, 0.0)) for f in nf]
            if not isinstance(w, (list, tuple)) or len(w) != k:
                raise Unsupported("weight vector wrong shape (non-affine or field mismatch)")
            try:
                w = tuple(float(x) for x in w)
                b = float(c["b"])
            except (TypeError, ValueError):
                raise Unsupported("non-numeric weight/bound")
            cons.append(Constraint(w=w, b=b))
        branches[sv] = tuple(cons)
    return FragmentPolicy(numeric_fields=tuple(nf), cat_field=cat_field, cat_values=tuple(cat_values),
                          action=str(spec.get("action", "a")), branches=branches)


def in_fragment(spec: dict) -> bool:
    try:
        parse_policy(spec)
        return True
    except Unsupported:
        return False


# --------------------------------------------------------------------------- #
# robust_eval — Proposition 7 support-function test over B_{d,eps}.
# --------------------------------------------------------------------------- #
def discrete_neighbors(policy: FragmentPolicy, s: str, d: int):
    """N_d(s): all categorical values reachable within <= d swaps of the single key over the policy's OWN
    value set. For one categorical key this is {s} at d=0 and {s} ∪ others at d>=1 (a swap changes it)."""
    vals = list(policy.cat_values)
    if d <= 0:
        return [s] if s in vals else []
    return list(dict.fromkeys([s] + [v for v in vals if v != s]))   # ordered, unique


def point_safe(policy: FragmentPolicy, s: str, x, a: str | None = None) -> bool:
    """POINT decision (no ball): safe iff every constraint of branch s holds, w·x <= b."""
    cons = policy.branches.get(s)
    if cons is None:
        return True                                        # value outside the policy's branches: vacuously
    xv = [float(x[f]) if isinstance(x, dict) else float(x[i]) for i, f in enumerate(policy.numeric_fields)]
    for c in cons:
        if sum(wi * xi for wi, xi in zip(c.w, xv)) > c.b:
            return False
    return True


def robust_eval(policy: FragmentPolicy, s: str, x, a: str | None, eps: float, d: int = 1) -> dict:
    """Prop 7: allow (robust-safe over B_{d,eps}) iff for every s' in N_d(s) and every constraint j:
    w_j·x + eps*||w_j||_2 <= b_j. Returns {allow, worst_slack, witness}."""
    xv = [float(x[f]) if isinstance(x, dict) else float(x[i]) for i, f in enumerate(policy.numeric_fields)]
    worst_slack = math.inf                                 # min over (s',j) of (b_j - (w·x + eps||w||))
    witness = None
    for sp in discrete_neighbors(policy, s, d):
        for j, c in enumerate(policy.branches.get(sp, ())):
            lhs = sum(wi * xi for wi, xi in zip(c.w, xv)) + eps * c.wnorm()
            slack = c.b - lhs                              # >= 0 safe (ties safe, <=)
            if slack < worst_slack:
                worst_slack = slack
                witness = {"branch": sp, "constraint": j, "slack": slack}
    allow = (worst_slack >= 0.0) if witness is not None else True
    return {"allow": bool(allow), "worst_slack": (None if witness is None else worst_slack),
            "witness": witness}


# --------------------------------------------------------------------------- #
# compile_to_rego — emit the POINT policy as Rego so `opa eval` can cross-check safety at probe points.
# --------------------------------------------------------------------------- #
def compile_to_rego(policy: FragmentPolicy, package: str = "cage.fragment") -> str:
    """Emit a Rego policy whose `decisions[i]` = point-safe(case_i). Each case = {s, x:[...], a}. safe iff
    every constraint of branch s holds (w·x <= b). O(n) object comprehension over input.cases (per the
    note: a partial rule would be O(n²))."""
    lines = [f"package {package}", "", "import rego.v1", ""]
    # per-branch bound tables: branch -> list of {w:[...], b:...}
    lines.append("constraints := {")
    for sv in policy.cat_values:
        rows = ", ".join("{\"w\": [%s], \"b\": %s}" % (", ".join(repr(float(wi)) for wi in c.w),
                                                       repr(float(c.b))) for c in policy.branches.get(sv, ()))
        lines.append(f"    {json.dumps(str(sv))}: [{rows}],")
    lines.append("}")
    lines.append("")
    # violated(case, c): the single affine constraint c is violated at case.x (w·x > b)
    lines.append("violated(case, c) if {")
    lines.append("    dot := sum([p | some i, xi in case.x; p := c.w[i] * xi])")
    lines.append("    dot > c.b")
    lines.append("}")
    lines.append("")
    # decisions[i] is TOTAL (a boolean for every case): safe iff zero constraints of branch case.s violated
    lines.append("decisions[i] := r if {")
    lines.append("    some i, case in input.cases")
    lines.append("    cons := object.get(constraints, case.s, [])")
    lines.append("    nviol := count([1 | some c in cons; violated(case, c)])")
    lines.append("    r := nviol == 0")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# self-test (fast sanity; the full battery is experiments/cx3_differential.py)
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    spec = {"numeric_fields": ["x0", "x1"], "cat_field": "s", "cat_values": ["trusted", "loose"],
            "action": "approve",
            "branches": {"trusted": [{"w": [1.0, 0.0], "b": 0.5}],
                         "loose": [{"w": [1.0, 0.0], "b": 0.2}]}}
    pol = parse_policy(spec)
    # a point safe under 'trusted' at eps=0: x0=0.3 <= 0.5 ok; robust at eps=0.1: 0.3+0.1*1=0.4<=0.2? no
    r0 = robust_eval(pol, "trusted", {"x0": 0.3, "x1": 0.0}, "approve", eps=0.0, d=1)
    r1 = robust_eval(pol, "trusted", {"x0": 0.3, "x1": 0.0}, "approve", eps=0.1, d=1)
    print("point_safe trusted:", point_safe(pol, "trusted", {"x0": 0.3, "x1": 0.0}))
    print("robust eps=0 (d=1, swaps to loose b=0.2 -> 0.3>0.2 unsafe):", r0["allow"], r0["witness"])
    print("robust eps=0.1:", r1["allow"], r1["witness"])
    # out-of-fragment must be refused
    for bad in ({"numeric_fields": ["x0"], "cat_field": "s", "cat_values": ["a"], "nonlinear": True,
                 "branches": {"a": []}},
                {"numeric_fields": ["x0"], "cat_field": "s", "cat_values": None, "branches": {}}):
        try:
            parse_policy(bad); print("BUG: accepted out-of-fragment", bad)
        except Unsupported as e:
            print("refused:", e.reason)
    print("rego head:\n" + "\n".join(compile_to_rego(pol).splitlines()[:6]))
