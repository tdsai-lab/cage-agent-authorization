#!/usr/bin/env python3
"""
complete_verification.py — a COMPLETE-VERIFICATION certificate backend (rung 1.5 of the ladder),
Tier-1 item 1.

The learned gate g_theta(z,a) is a TINY sklearn ReLU MLP (~26 -> 64 -> 32 -> 1, logistic output).
Existing certified backends pay a price for being architecture-agnostic:
  - randomized smoothing (cert/smoothed_gate.py)  pays a sigma*Phi^{-1}(tau) buffer + Monte-Carlo noise;
  - the 1-Lipschitz gate (experiments/lip_gate)    pays a global-Lipschitz architectural constraint.
A COMPLETE verifier certifies the eps-ball per discrete branch EXACTLY: no sigma buffer, no MC, no
Lipschitz constraint. Because g_theta is a small piecewise-linear ReLU network, this is a MILP.

  auto_LiRPA / alpha,beta-CROWN is NOT installable here (hard torch-version conflict; installing it would
  break the torch 2.8 + orthogonium env and the passing suite). We therefore use the *MILP branch* of the
  complete-verification family, via scipy.optimize.milp (scipy 1.17.1) with a textbook big-M ReLU encoding.
  This is complete for the encoded feasible set; the only conservativeness is the L2-ball outer polytope.

--------------------------------------------------------------------------------------------------------
Verifier (per record, per discrete branch s' in {identity} U N_1(s)):
  The discrete part is FIXED for the branch (one-hot constants), so the MLP input v = c + A @ delta is
  AFFINE in the raw numeric perturbation delta (dim k). c, A come straight from FeatureEncoder's numeric
  block (v_numeric[f] = (x2[f] + delta[f] - mean[f]) / std[f]).

  Minimize the gate's SAFE MARGIN over the perturbation set:
      margin(v) = final logit of the MLP    (p_safe = sigmoid(logit); p_safe >= 0.5  <=>  logit >= 0)
  subject to  ||delta||_2 <= eps  AND the big-M ReLU constraints (one binary per hidden unit).

  L2 ball -> TIGHT OUTER polytope: sample many unit directions u_i and add facets  u_i^T delta <= eps.
  This CIRCUMSCRIBES the L2 ball (every ball point satisfies every facet), so the feasible set is a
  SUPERSET of the ball => minimising over it gives a LOWER bound on the true min-margin => SOUND
  (verified-safe on the polytope => verified-safe on the ball). The over-approximation slack (outer vs
  inscribed polytope) is reported and is small for small k.

  Certified-safe(record) iff  min over branches of (min-margin) >= 0.

Outputs (bridge_benchmark/cert/out/exp_complete_verification/): summary.csv, per_record.jsonl,
summary.json, summary.md — per (domain x backend): R_allow mean+/-std, cert_false_allow, mean solve ms,
polytope slack.  Backends compared on the OPA track: complete_verif (MILP) vs randomized_smoothing
(M=10000) vs lipschitz.  cert_false_allow is measured against the OPA/analytic robust oracle.
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp


@contextlib.contextmanager
def _suppress_c_stderr():
    """Silence the HiGHS C++ stderr chatter emitted per integer-feasible solution (fd-level)."""
    try:
        fd = sys.stderr.fileno()
    except (AttributeError, OSError):
        yield; return
    saved = os.dup(fd)
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull, fd)
        yield
    finally:
        os.dup2(saved, fd); os.close(saved); os.close(devnull)

_HERE = Path(__file__).resolve().parent
_BB = _HERE.parent
for p in ("generators", "models", "cert"):
    sys.path.insert(0, str(_BB / p))
sys.path.insert(0, str(_BB / "experiments" / "opa_gate"))

from oracle import (discrete_swaps, joint_reachable_unsafe, load_rule_table,  # noqa: E402
                    margin_and_scale, get_rule, _x1)
from dataset import FeatureEncoder  # noqa: E402
from smoothed_gate import certify as rs_certify, _states  # noqa: E402


# ======================================================================================== #
# 1. Port a trained sklearn ReLU-MLP gate to explicit numpy weight matrices.
# ======================================================================================== #
class PortedMLP:
    """Explicit (Linear, ReLU)* + Linear port of an sklearn MLPClassifier with logistic output.

    forward(v) returns the final logit; p_safe = sigmoid(logit). Layers: hidden use ReLU, output linear.
    Matches est.predict_proba(...)[:,1] to ~1e-6 (asserted by port_and_check)."""

    def __init__(self, coefs, intercepts):
        self.W = [np.asarray(c, dtype=np.float64) for c in coefs]
        self.b = [np.asarray(bb, dtype=np.float64).ravel() for bb in intercepts]
        self.n_hidden_layers = len(self.W) - 1

    def logit(self, V):
        h = np.atleast_2d(np.asarray(V, dtype=np.float64))
        for i in range(len(self.W)):
            h = h @ self.W[i] + self.b[i]
            if i < len(self.W) - 1:
                h = np.maximum(h, 0.0)
        return h.ravel()

    def p_safe(self, V):
        z = self.logit(V)
        return 1.0 / (1.0 + np.exp(-z))


def port_and_check(gate, sample_V, tol=1e-6):
    """Port gate.est (sklearn MLPClassifier) to a PortedMLP and assert the forward pass matches
    est.predict_proba(...)[:,1] to `tol` on `sample_V`."""
    est = gate.est
    assert est.activation == "relu", f"expected relu activation, got {est.activation}"
    assert est.out_activation_ == "logistic", f"expected logistic out, got {est.out_activation_}"
    ported = PortedMLP(est.coefs_, est.intercepts_)
    p_ref = est.predict_proba(np.atleast_2d(sample_V))[:, 1]
    p_port = ported.p_safe(sample_V)
    max_diff = float(np.max(np.abs(p_ref - p_port))) if len(p_ref) else 0.0
    assert max_diff <= tol, f"port mismatch: max |dp| = {max_diff:.2e} > {tol:.0e}"
    return ported, max_diff


# ======================================================================================== #
# 2. L2-ball outer polytope (circumscribing => sound).
# ======================================================================================== #
def outer_polytope_dirs(k, per_dim=8, seed=0):
    """Unit directions whose halfspaces u^T delta <= eps CIRCUMSCRIBE the L2 eps-ball. We include the
    +/- axis directions (guarantees a bounded box) plus a deterministic quasi-uniform sphere sample.
    Number of facets ~ 2*k*per_dim. Returns an array of unit vectors (rows)."""
    rng = np.random.default_rng(seed)
    dirs = []
    for j in range(k):                       # +/- axes (box) -> feasible set is bounded
        e = np.zeros(k); e[j] = 1.0
        dirs.append(e.copy()); dirs.append(-e)
    m = max(0, 2 * k * per_dim - 2 * k)
    if m:
        G = rng.standard_normal((m, k))
        G /= np.linalg.norm(G, axis=1, keepdims=True) + 1e-12
        dirs.extend(list(G))
    U = np.asarray(dirs, dtype=np.float64)
    return U


def polytope_slack(U):
    """Conservativeness of the circumscribing polytope P = {delta : U delta <= 1} vs the unit ball.
    Every ball point is in P (sound). The inscribed ball of P has radius r_in = min over facets of
    1/||u|| = 1 (unit rows). We report the OUTER radius: the max ||delta|| still feasible along the
    worst gap direction, approximated as 1/max_i (u_i . d*) minimised over sampled probe directions d*.
    A small slack means the polytope hugs the ball. Returned as (outer_over_inner_ratio)."""
    rng = np.random.default_rng(12345)
    D = rng.standard_normal((4000, U.shape[1]))
    D /= np.linalg.norm(D, axis=1, keepdims=True) + 1e-12
    # for probe direction d, the polytope boundary distance is 1 / max_i (u_i . d) (support along d)
    supp = (D @ U.T).max(axis=1)              # >= |d| projection; support function of P^*
    supp = np.clip(supp, 1e-9, None)
    outer_radii = 1.0 / supp                  # feasible extent of P along d (for eps=1)
    # inner ball radius is 1 (unit-scaled); slack = worst-case outer extent beyond the ball
    return float(np.max(outer_radii))         # >= 1; ->1 as the polytope tightens


# ======================================================================================== #
# 3. Numeric affine map: MLP input v = c + A @ delta  (delta = raw numeric perturbation).
# ======================================================================================== #
def numeric_affine(enc, domain, tool, action, x1, x2_base, threat_fields):
    """Return (c, A): the MLP INPUT vector v as an affine function of the raw numeric perturbation delta
    over `threat_fields` (the domain's numeric fields). Discrete part (one-hots) is constant for this
    branch. The encoder numeric block spans the UNION of all domains' fields; only the domain's fields
    are perturbed, so A has one column per threat field mapped to its encoder-block index."""
    c = np.asarray(enc.transform_point(domain, tool, action, x1, x2_base), dtype=np.float64)
    start, block_fields, mean, std = enc.numeric_block()
    k = len(threat_fields)
    A = np.zeros((len(c), k))
    for j, f in enumerate(threat_fields):
        bi = block_fields.index(f)
        # v[start+bi] = (x2_base[f] + delta_j - mean[bi]) / std[bi]  => dv/d delta_j = 1/std[bi]
        A[start + bi, j] = 1.0 / std[bi]
    return c, A, list(threat_fields)


# ======================================================================================== #
# 4. Big-M MILP: minimise the MLP logit over {v = c + A delta, ||delta||_2<=eps (outer poly), ReLU}.
# ======================================================================================== #
def _preactivation_bounds(ported, c, A, eps):
    """Interval bounds on delta (box |delta_f|<=eps) propagated through the network to bound each
    neuron's pre-activation (for big-M). Sound interval arithmetic; used only to size M, not for the
    verdict."""
    k = A.shape[1]
    # v = c + A delta, delta in [-eps, eps]^k (box OUTER-approx of the L2 ball for bound-sizing only)
    lo_v = c + A @ (-eps * np.ones(k)) - np.abs(A) @ np.zeros(k)
    # do proper interval: v_i in c_i +/- eps*sum_j|A_ij|
    rad_v = eps * np.abs(A).sum(axis=1)
    lo = c - rad_v
    hi = c + rad_v
    bounds = []                                   # (lo, hi) per HIDDEN neuron, per layer
    cur_lo, cur_hi = lo, hi
    for i in range(ported.n_hidden_layers):
        W, b = ported.W[i], ported.b[i]
        Wp, Wn = np.maximum(W, 0.0), np.minimum(W, 0.0)
        pre_lo = cur_lo @ Wp + cur_hi @ Wn + b
        pre_hi = cur_hi @ Wp + cur_lo @ Wn + b
        bounds.append((pre_lo.copy(), pre_hi.copy()))
        cur_lo = np.maximum(pre_lo, 0.0)
        cur_hi = np.maximum(pre_hi, 0.0)
    return bounds


def milp_min_margin(ported, c, A, eps, U, time_limit=None):
    """Exact (given the outer polytope) minimum of the final logit over the perturbation set.

    Variables: delta (k), then per hidden layer l: pre-activation z^l (n_l), post-activation a^l (n_l),
    binary beta^l (n_l). Objective: final linear layer applied to the last post-activation.
    Returns (min_margin, status_ok)."""
    k = A.shape[1]
    layer_sizes = [W.shape[1] for W in ported.W]           # incl. output size (1)
    hidden = layer_sizes[:-1]
    bounds = _preactivation_bounds(ported, c, A, eps)

    # variable layout
    idx = {}
    n = 0
    idx["delta"] = (n, n + k); n += k
    z_idx, a_idx, b_idx = [], [], []
    for nl in hidden:
        z_idx.append((n, n + nl)); n += nl
        a_idx.append((n, n + nl)); n += nl
        b_idx.append((n, n + nl)); n += nl
    nvar = n

    A_rows, lb_rows, ub_rows = [], [], []

    def row(coefs):
        r = np.zeros(nvar);
        for i, v in coefs:
            r[i] += v
        return r

    # input to first hidden layer: v = c + A delta ; pre = v @ W0 + b0
    # z^0_p = sum_i (c_i + sum_j A_ij delta_j) W0[i,p] + b0[p]
    #       = (const) + sum_j (sum_i A_ij W0[i,p]) delta_j
    prev_kind = "input"
    for l, nl in enumerate(hidden):
        W, b = ported.W[l], ported.b[l]
        z0, z1 = z_idx[l]
        if l == 0:
            AW = A.T @ W                              # (k, nl)
            const = c @ W + b                        # (nl,)
            for p in range(nl):
                r = np.zeros(nvar)
                r[z0 + p] = 1.0
                for j in range(k):
                    r[idx["delta"][0] + j] = -AW[j, p]
                A_rows.append(r); lb_rows.append(const[p]); ub_rows.append(const[p])
        else:
            pa0, _ = a_idx[l - 1]
            n_prev = hidden[l - 1]
            for p in range(nl):
                r = np.zeros(nvar)
                r[z0 + p] = 1.0
                for q in range(n_prev):
                    r[pa0 + q] = -W[q, p]
                A_rows.append(r); lb_rows.append(b[p]); ub_rows.append(b[p])

        # ReLU big-M:  a = relu(z),  z in [lo,hi]
        #   a >= z ; a >= 0 ; a <= z - lo*(1-beta) ; a <= hi*beta
        lo, hi = bounds[l]
        za0, za1 = a_idx[l]
        bb0, bb1 = b_idx[l]
        for p in range(nl):
            zvar, avar, bvar = z0 + p, za0 + p, bb0 + p
            lop, hip = float(lo[p]), float(hi[p])
            if lop >= 0:                    # neuron always active -> a = z
                A_rows.append(row([(avar, 1.0), (zvar, -1.0)])); lb_rows.append(0.0); ub_rows.append(0.0)
                continue
            if hip <= 0:                    # neuron always inactive -> a = 0
                A_rows.append(row([(avar, 1.0)])); lb_rows.append(0.0); ub_rows.append(0.0)
                continue
            # a - z >= 0
            A_rows.append(row([(avar, 1.0), (zvar, -1.0)])); lb_rows.append(0.0); ub_rows.append(np.inf)
            # a >= 0  (bounds enforce)
            # a - z + lop*(1-beta) <= 0  ->  a - z - lop*beta <= -lop
            A_rows.append(row([(avar, 1.0), (zvar, -1.0), (bvar, -lop)]))
            lb_rows.append(-np.inf); ub_rows.append(-lop)
            # a - hip*beta <= 0
            A_rows.append(row([(avar, 1.0), (bvar, -hip)])); lb_rows.append(-np.inf); ub_rows.append(0.0)

    # L2-ball outer polytope facets: (U @ delta) <= eps   (rows scaled by eps since U are unit)
    for u in U:
        r = np.zeros(nvar)
        r[idx["delta"][0]:idx["delta"][1]] = u
        A_rows.append(r); lb_rows.append(-np.inf); ub_rows.append(eps)

    # objective: final logit = a^{L-1} @ W_out + b_out   (output size 1). With NO hidden layers the
    # "last activation" is the input v = c + A delta, so the objective is linear in delta directly.
    Wout, bout = ported.W[-1], ported.b[-1]        # (n_last, 1)
    obj = np.zeros(nvar)
    if len(hidden) == 0:
        AW = (A.T @ Wout).ravel()                  # d logit / d delta
        d0i = idx["delta"][0]
        for j in range(k):
            obj[d0i + j] = float(AW[j])
        obj_const = float((c @ Wout).ravel()[0] + bout[0])
    else:
        pa0, _ = a_idx[-1]
        for q in range(hidden[-1]):
            obj[pa0 + q] = float(Wout[q, 0])
        obj_const = float(bout[0])

    # variable bounds
    lb = np.full(nvar, -np.inf); ub = np.full(nvar, np.inf)
    d0, d1 = idx["delta"]
    lb[d0:d1] = -eps; ub[d0:d1] = eps
    integrality = np.zeros(nvar)
    for l, nl in enumerate(hidden):
        za0, za1 = a_idx[l]; lb[za0:za1] = 0.0     # post-activation >= 0
        zl0, zl1 = z_idx[l]
        lo, hi = bounds[l]
        lb[zl0:zl1] = np.minimum(lo, 0.0); ub[zl0:zl1] = np.maximum(hi, 0.0)
        ua0 = a_idx[l][0]
        ub[ua0:ua0 + nl] = np.maximum(hi, 0.0)
        bb0, bb1 = b_idx[l]
        lb[bb0:bb1] = 0.0; ub[bb0:bb1] = 1.0
        integrality[bb0:bb1] = 1               # binaries

    Aub = np.asarray(A_rows, dtype=np.float64)
    cons = LinearConstraint(Aub, np.asarray(lb_rows), np.asarray(ub_rows))
    options = {}
    if time_limit:
        options["time_limit"] = time_limit
    with _suppress_c_stderr():
        res = milp(c=obj, constraints=cons, integrality=integrality,
                   bounds=Bounds(lb, ub), options=options)
    if not res.success or res.fun is None:
        # fall back to interval lower bound (sound) if the solver failed
        return None, False
    return float(res.fun + obj_const), True


def cv_certify(ported, enc, rt, rec, eps, U):
    """Complete-verification allow: min over branches of the MILP min-margin >= 0 => certified safe."""
    domain, action = rec["domain"], rec["candidate_action"]
    x2 = rec["numeric_fields"]
    threat_fields = rt["domains"][domain]["numeric_fields"]
    min_margin = np.inf
    solved_all = True
    for tool, x1 in _states(rt, rec):
        c, A, _fields = numeric_affine(enc, domain, tool, action, x1, x2, threat_fields)
        mm, ok = milp_min_margin(ported, c, A, eps, U)
        solved_all = solved_all and ok
        if mm is None:
            min_margin = -np.inf; break
        min_margin = min(min_margin, mm)
    return {"allow": bool(min_margin >= 0.0), "min_margin": float(min_margin),
            "solved_all": solved_all, "n_branches": 1 + sum(1 for _ in _states(rt, rec)) - 1}


# ======================================================================================== #
# 5. VALIDATION on the analytic halfspace domain (MILP verdict == analytic robust oracle).
# ======================================================================================== #
class LinearPortedMLP(PortedMLP):
    """A 'network' that is a single linear layer implementing an exact halfspace margin m(x2) so the
    MILP verdict can be checked against the analytic joint_reachable_unsafe. Represents the SAFE margin
    as `-m` (safe iff m<0 iff -m>0), matching the gate convention (safe iff logit>=0)."""


def _linear_gate_for_domain(rt, domain, action):
    """Build (LinearPortedMLP, enc) whose logit(v) == -m(z,a) EXACTLY for the analytic scalar_threshold
    domain (financial_compliance), where m = s*(x2[field] - theta_eff(tool, x1)) and theta_eff is
    per-tool + per-country-offset. theta_eff is affine in the one-hots, so a single linear layer over
    the full (one-hots + numeric) feature vector reproduces the analytic margin per branch:
        logit = -m = -s*x2[field] + s*theta_tool*1[tool] + s*offset_country*1[country].
    Identity numeric normalization (mean0 std1) => the numeric weight is exactly -s. This makes the MILP
    verdict directly comparable to joint_reachable_unsafe over every discrete branch."""
    dc = rt["domains"][domain]
    enc = FeatureEncoder(rt)                                   # identity numeric normalization
    start, fields, mean, std = enc.numeric_block()
    dim = enc.dim
    rules = [r for r in dc["rules"] if r["candidate_action"] == action]
    assert rules, f"no rule for action {action}"
    field = rules[0]["numeric_field"]
    s = 1.0 if rules[0]["unsafe_direction"] == ">=" else -1.0
    jf = fields.index(field)
    W = np.zeros((dim, 1))
    W[start + jf, 0] = -s * std[jf]                            # -s (std=1 under identity enc)
    # per-tool threshold rides on the tool one-hot (affine, exact). Country threshold_offsets are a
    # tool*country PRODUCT (not linearly representable in one layer); validation fixes country to a
    # zero-offset value (US) so theta_eff = theta_tool exactly.
    n_dom = len(enc.domains)
    tool_start = n_dom
    for r in rules:
        theta = float(r["threshold"])
        ti = enc.tools.index((domain, r["tool_id"]))
        W[tool_start + ti, 0] += s * theta
    b = np.array([0.0])
    return LinearPortedMLP([W], [b]), enc, field, None, s


def validate_on_analytic(eps=0.10, n=120, seed=0, per_dim=8, verbose=False):
    """Assert: on financial_compliance (halfspace Safe), the MILP verdict (certified-safe) equals
    `not joint_reachable_unsafe` for every sampled record. Returns (agreement, n)."""
    import copy
    rt = load_rule_table()
    # strip threshold_offsets so theta_eff = theta_tool exactly (a tool*country product is not linearly
    # representable in a single-layer gate; the MILP encoding is what's under test, not offset handling).
    rt = copy.deepcopy(rt)
    for r in rt["domains"]["financial_compliance"]["rules"]:
        r.pop("threshold_offsets", None)
    domain, action = "financial_compliance", "approve_transaction"
    dc = rt["domains"][domain]
    ported, enc, field, theta, s = _linear_gate_for_domain(rt, domain, action)
    U = outer_polytope_dirs(len(dc["numeric_fields"]), per_dim=per_dim, seed=seed)
    rng = np.random.default_rng(seed)
    tools = [t for t in dc["tools"]
             if any(r["tool_id"] == t and r["candidate_action"] == action for r in dc["rules"])]
    cats = dc["categorical_fields"]
    agree = 0
    for i in range(n):
        x1 = {f: rng.choice(vals) for f, vals in cats.items()}
        if "counterparty_country" in x1:            # fix to zero-offset value (see _linear_gate_for_domain)
            x1["counterparty_country"] = "US"
        x2 = {"risk_score": float(rng.uniform(0.0, 1.0)), "amount_norm": float(rng.uniform(0.0, 1.0))}
        tool = str(rng.choice(tools))
        z = {"domain": domain, "tool_id": tool, "candidate_action": action,
             "categorical_fields": x1, "numeric_fields": x2}
        rec = dict(z, id=f"val-{i}")
        # analytic robust oracle: clean safe AND not joint-reachable-unsafe over B_{1,eps}
        clean = get_rule(dc, tool, action, x1) is not None
        jru = joint_reachable_unsafe(z, action, rt, d=1, eps=eps)
        # also the clean-point margin
        m0, _ = margin_and_scale(get_rule(dc, tool, action, x1), x1, x2, dc["numeric_fields"])
        analytic_robust_safe = (m0 < 0.0) and (not jru["reachable"])
        cv = cv_certify(ported, enc, rt, rec, eps, U)
        if bool(cv["allow"]) == bool(analytic_robust_safe):
            agree += 1
        elif verbose:
            print(f"  MISMATCH i={i} cv={cv['allow']} analytic={analytic_robust_safe} "
                  f"min_margin={cv['min_margin']:.4f} m0={m0:.4f} jru_after={jru['max_margin']:.4f}")
    return agree / n, n


# ======================================================================================== #
# 6. OPA-track comparison: CV (MILP) vs RS(M) vs Lipschitz.
# ======================================================================================== #
def _import_opa():
    from schema import DOMAINS, sample_records  # noqa
    from opa_oracle import OpaOracle  # noqa
    from run_opa_gate import train_gate_opa  # noqa
    return DOMAINS, sample_records, OpaOracle, train_gate_opa


def _lip_available():
    try:
        import torch  # noqa
        sys.path.insert(0, str(_BB / "experiments" / "lip_gate" / "models"))
        from lip_gate import train_lipgate  # noqa
        return True
    except Exception:
        return False


def run_domain(domain, seed, eps, sigma, tau, n_eval, n_train, rs_mc, alpha_fwer,
               per_dim, do_lip, cv_cap):
    DOMAINS, sample_records, OpaOracle, train_gate_opa = _import_opa()
    orc = OpaOracle(domain)
    rt = orc.rt
    dc = orc.dc
    k = len(dc["numeric_fields"])
    train = sample_records(domain, n_train, seed=seed, scheme="natural")
    ev = sample_records(domain, n_eval, seed=seed + 1, scheme="natural")
    cats = orc.categorize(ev, eps)
    gate = train_gate_opa(orc, train, sigma, n_aug=4, seed=seed)

    # port + check on eval feature vectors
    sampleV = gate.enc.matrix(ev[: min(64, len(ev))])
    ported, port_diff = port_and_check(gate, sampleV)

    U = outer_polytope_dirs(k, per_dim=per_dim, seed=seed)
    slack = polytope_slack(U)

    # optional Lipschitz gate (same OPA labels, raw-unit encoder)
    lip_model = lip_enc = None
    if do_lip:
        from lip_gate import (train_lipgate, make_encoder, certify_lip,  # noqa
                              CLAIMED_L)
        lip_enc = make_encoder(rt)
        lip_model = train_lipgate(orc, lip_enc, train, variant="robust-aug", sigma=sigma, seed=seed)

    per_record = []
    cv_times, rs_times, lip_times = [], [], []
    n_branches_list = []
    # evaluate a bounded subset for the (slow) MILP; RS/Lip run on the same subset for a fair compare
    subset = ev if (cv_cap is None or len(ev) <= cv_cap) else ev[:cv_cap]
    subset_cats = cats[: len(subset)]
    for r, cinfo in zip(subset, subset_cats):
        n_states = 1 + len(list(discrete_swaps(dc, r["tool_id"], r["categorical_fields"], 1)))
        alpha_branch = alpha_fwer / n_states
        rec = dict(r)

        t0 = time.perf_counter()
        cv = cv_certify(ported, gate.enc, rt, rec, eps, U)
        cv_times.append((time.perf_counter() - t0) * 1000.0)
        n_branches_list.append(cv["n_branches"] + 1)

        t0 = time.perf_counter()
        rs = rs_certify(gate, rt, rec, sigma=sigma, eps=eps, tau=tau, n_mc=rs_mc, alpha=alpha_branch)
        rs_times.append((time.perf_counter() - t0) * 1000.0)

        lip_allow = None
        if do_lip:
            from lip_gate import certify_lip, CLAIMED_L  # noqa
            t0 = time.perf_counter()
            lc = certify_lip(lip_model, lip_enc, rt, rec, eps, L=CLAIMED_L)
            lip_times.append((time.perf_counter() - t0) * 1000.0)
            lip_allow = bool(lc["allow"])

        per_record.append({
            "domain": domain, "seed": seed, "id": r["id"], "category": cinfo["category"],
            "truly_unsafe_reachable": bool(cinfo["truly_unsafe_reachable"]),
            "cv_allow": bool(cv["allow"]), "cv_min_margin": round(cv["min_margin"], 5),
            "cv_solved_all": bool(cv["solved_all"]),
            "rs_allow": bool(rs["allow"]), "rs_lb": rs["lower_bound_probability"],
            "lip_allow": lip_allow, "n_branches": cv["n_branches"] + 1,
        })

    return {"domain": domain, "seed": seed, "k": k, "port_diff": port_diff,
            "polytope_slack": slack, "per_record": per_record,
            "cv_ms": cv_times, "rs_ms": rs_times, "lip_ms": lip_times,
            "n_branches": n_branches_list, "do_lip": do_lip}


# ======================================================================================== #
# 7. Aggregation + outputs.
# ======================================================================================== #
def _rate(recs, allow_key, cat=None, unsafe_only=False):
    sub = recs
    if cat is not None:
        sub = [r for r in sub if r["category"] == cat]
    if unsafe_only:
        sub = [r for r in sub if r["truly_unsafe_reachable"]]
    if not sub:
        return float("nan")
    return sum(1 for r in sub if r[allow_key]) / len(sub)


def _false_allow(recs, allow_key):
    """cert_false_allow = fraction of ALLOWED records that are truly-unsafe-reachable (category != R)."""
    allowed = [r for r in recs if r[allow_key]]
    if not allowed:
        return 0.0
    return sum(1 for r in allowed if r["truly_unsafe_reachable"]) / len(allowed)


def aggregate(domain, seed_results):
    backends = [("complete_verif", "cv_allow"), ("randomized_smoothing", "rs_allow")]
    if seed_results[0]["do_lip"]:
        backends.append(("lipschitz", "lip_allow"))
    rows = []
    for backend, key in backends:
        R_allows, cfas = [], []
        for sr in seed_results:
            recs = sr["per_record"]
            R_allows.append(_rate(recs, key, cat="R"))
            cfas.append(_false_allow(recs, key))
        all_recs = [r for sr in seed_results for r in sr["per_record"]]
        if backend == "complete_verif":
            ms = [t for sr in seed_results for t in sr["cv_ms"]]
        elif backend == "randomized_smoothing":
            ms = [t for sr in seed_results for t in sr["rs_ms"]]
        else:
            ms = [t for sr in seed_results for t in sr["lip_ms"]]
        rows.append({
            "domain": domain, "backend": backend,
            "R_allow_mean": round(float(np.nanmean(R_allows)), 4),
            "R_allow_std": round(float(np.nanstd(R_allows)), 4),
            "cert_false_allow": round(float(np.nanmean(cfas)), 4),
            "mean_solve_ms": round(float(np.mean(ms)), 3) if ms else float("nan"),
            "polytope_slack": round(float(np.mean([sr["polytope_slack"] for sr in seed_results])), 5),
            "mean_branches": round(float(np.mean([b for sr in seed_results for b in sr["n_branches"]])), 2),
            "n_eval_total": len(all_recs),
        })
    return rows


def write_outputs(outdir, summary_rows, all_per_record, meta):
    outdir.mkdir(parents=True, exist_ok=True)
    cols = ["domain", "backend", "R_allow_mean", "R_allow_std", "cert_false_allow",
            "mean_solve_ms", "polytope_slack", "mean_branches", "n_eval_total"]
    with open(outdir / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader(); w.writerows(summary_rows)
    with open(outdir / "per_record.jsonl", "w") as f:
        for r in all_per_record:
            f.write(json.dumps(r) + "\n")
    (outdir / "summary.json").write_text(json.dumps({"meta": meta, "summary": summary_rows}, indent=2))

    by_dom = defaultdict(list)
    for r in summary_rows:
        by_dom[r["domain"]].append(r)
    md = ["# T1-1 — Complete-verification backend (MILP, rung 1.5)\n",
          f"Config: eps={meta['eps']}, sigma={meta['sigma']}, tau={meta['tau']}, RS M={meta['rs_mc']}, "
          f"seeds={meta['seeds']}, n_eval/seed(subset)={meta['cv_cap']}, "
          f"L2 outer polytope facets={meta['per_dim']}*2k.\n",
          f"Port fidelity (max |Δp_safe| vs sklearn predict_proba): {meta['max_port_diff']:.2e} "
          f"(assert ≤ 1e-6). Analytic-halfspace validation agreement: "
          f"{meta['validation_agreement']:.4f} (assert = 1.0).\n",
          "Backend = MILP branch of complete verification (α,β-CROWN not installable here). L2 ball is "
          "certified via a **circumscribing** outer polytope (sound: verified-safe ⇒ truly L2-safe); "
          "`polytope_slack` = outer/inner radius (→1 = tight).\n",
          "| domain | backend | R_allow (mean±std) | cert_false_allow | mean_solve_ms | polytope_slack | "
          "mean_branches |",
          "| --- | --- | --- | --- | --- | --- | --- |"]
    for dom in by_dom:
        for r in by_dom[dom]:
            md.append(f"| {r['domain']} | {r['backend']} | {r['R_allow_mean']:.4f} ± "
                      f"{r['R_allow_std']:.4f} | {r['cert_false_allow']:.4f} | {r['mean_solve_ms']} | "
                      f"{r['polytope_slack']} | {r['mean_branches']} |")
    md.append("\n**Reading.** All backends certify the SAME learned OPA gate. The complete verifier pays "
              "no σΦ⁻¹(τ) buffer / no MC / no Lipschitz constraint, so R_allow^CV should meet or exceed "
              "R_allow^RS(M) with cert_false_allow=0. If CV≈RS, the smoothing-transition-tax decomposition "
              "(LIP) is mis-attributed (kill criterion).\n")
    (outdir / "summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))
    print(f"\nwrote -> {outdir}/summary.{{csv,json,md}} ; per_record.jsonl")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", default="0 1 2")
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--domains", default="finance sre ops")
    ap.add_argument("--n-eval", type=int, default=200)
    ap.add_argument("--n-train", type=int, default=1500)
    ap.add_argument("--rs-mc", type=int, default=10000)
    ap.add_argument("--alpha-fwer", type=float, default=0.001)
    ap.add_argument("--per-dim", type=int, default=8, help="outer-polytope directions per dimension")
    ap.add_argument("--cv-cap", type=int, default=120, help="MILP eval subset cap per (domain,seed)")
    ap.add_argument("--no-lip", action="store_true", help="skip the Lipschitz backend even if available")
    ap.add_argument("--out", default=str(_BB / "cert" / "out" / "exp_complete_verification"))
    ap.add_argument("--quick", action="store_true", help="1 seed, n-eval 60, rs-mc 2000, finance sre")
    args = ap.parse_args()

    if args.quick:
        args.seeds = "0"; args.n_eval = 60; args.rs_mc = 2000; args.cv_cap = 60
        args.domains = "finance sre"; args.n_train = 800

    seeds = [int(s) for s in args.seeds.replace(",", " ").split()]
    domains = [d for d in args.domains.replace(",", " ").split()]
    do_lip = (not args.no_lip) and _lip_available()

    # deterministic
    np.random.seed(0)

    print("=== validating MILP verifier on the analytic halfspace domain ===")
    val_agree, val_n = validate_on_analytic(eps=args.eps, n=(60 if args.quick else 120),
                                            per_dim=args.per_dim, verbose=True)
    print(f"analytic-halfspace agreement: {val_agree:.4f} over n={val_n}")
    assert val_agree == 1.0, f"MILP verdict disagrees with analytic robust oracle ({val_agree:.4f})"

    all_summary, all_per_record = [], []
    max_port_diff = 0.0
    for domain in domains:
        seed_results = []
        for seed in seeds:
            print(f"\n=== {domain} seed={seed} (CV MILP vs RS M={args.rs_mc}{' vs Lip' if do_lip else ''}) ===")
            sr = run_domain(domain, seed, args.eps, args.sigma, args.tau, args.n_eval, args.n_train,
                            args.rs_mc, args.alpha_fwer, args.per_dim, do_lip, args.cv_cap)
            max_port_diff = max(max_port_diff, sr["port_diff"])
            recs = sr["per_record"]
            print(f"  port|Δp|={sr['port_diff']:.1e} slack={sr['polytope_slack']:.4f} "
                  f"branches~{np.mean(sr['n_branches']):.1f} | "
                  f"R_allow CV={_rate(recs,'cv_allow',cat='R'):.3f} RS={_rate(recs,'rs_allow',cat='R'):.3f}"
                  + (f" Lip={_rate(recs,'lip_allow',cat='R'):.3f}" if do_lip else "")
                  + f" | cfa CV={_false_allow(recs,'cv_allow'):.3f} RS={_false_allow(recs,'rs_allow'):.3f}"
                  + f" | CV ms~{np.mean(sr['cv_ms']):.1f}")
            seed_results.append(sr)
            all_per_record.extend(recs)
        all_summary.extend(aggregate(domain, seed_results))

    meta = {"eps": args.eps, "sigma": args.sigma, "tau": args.tau, "rs_mc": args.rs_mc,
            "seeds": seeds, "domains": domains, "per_dim": args.per_dim, "cv_cap": args.cv_cap,
            "do_lip": do_lip, "max_port_diff": max_port_diff, "validation_agreement": val_agree,
            "backend": "milp_complete_verification", "note": "alpha_beta_crown_unavailable"}
    write_outputs(Path(args.out), all_summary, all_per_record, meta)


if __name__ == "__main__":
    main()
