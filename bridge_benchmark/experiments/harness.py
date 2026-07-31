#!/usr/bin/env python3
"""
harness.py — run the full pipeline (train gate -> attack -> certify) on ONE synthetic/realistic
setting and return a metrics row. Reuses the existing modules unchanged (no theorem change, no
discrete smoothing): FeatureEncoder, the certified gate, the empirical attack, and the
enumerate-discrete + Gaussian-RS certificate.

Returned metrics (per setting):
  category prevalence  (A/B/C/R/U %)
  clean_acc            (certified gate, by category)
  attack_false_allow   (uncertified gate, robust false-allow on U under B_{1,eps})
  naive_C_falseallow   (DETERMINISTIC naive-composition certificate falsely certifies C as safe)
  cert C/R/U/A/B allow (learned enumerate_discrete_gaussian_rs certificate)
  cert_false_allow     (certified-allow points that are truly joint-unsafe -> must be 0)
  runtime_seconds
"""
from __future__ import annotations

import math
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np

_root = Path(__file__).resolve().parents[1]
for p in ("generators", "models", "attacks", "cert"):
    sys.path.insert(0, str(_root / p))

from oracle import discrete_swaps, get_rule, joint_reachable_unsafe, _x1  # noqa: E402
from split import stratified_split  # noqa: E402
from baselines import train_certified_gate, evaluate  # noqa: E402
from smoothed_gate import certify  # noqa: E402
import certificate_oracles as detcert  # noqa: E402


def _ring_offsets(k, eps, n_radii=3, n_ang=12):
    radii = [eps * (i + 1) / n_radii for i in range(n_radii)]
    offs = [[0.0] * k]
    if k == 2:
        for r in radii:
            for j in range(n_ang):
                th = 2 * math.pi * j / n_ang
                offs.append([r * math.cos(th), r * math.sin(th)])
    else:
        for r in radii:
            for c in range(k):
                for s in (+1.0, -1.0):
                    v = [0.0] * k; v[c] = s * r; offs.append(v)
    return offs


def _valid_states(rt, rec):
    dc = rt["domains"][rec["domain"]]
    a, x1 = rec["candidate_action"], _x1(rec)
    yield rec["tool_id"], dict(x1)
    for t2, x12, _r in discrete_swaps(dc, rec["tool_id"], x1, 1):
        if get_rule(dc, t2, a, x12) is not None:
            yield t2, x12


def batched_attack_false_allow(gate, rt, recs, eps, thr=0.5):
    """Robust false-allow on truly-unsafe records: does the gate allow ANYWHERE in B_{1,eps}?
    Vectorized: one predict per record over all (valid state x ring offset) points."""
    if not recs:
        return 0.0
    nf = rt["domains"][recs[0]["domain"]]["numeric_fields"]
    offs = _ring_offsets(len(nf), eps)
    hits = 0
    for r in recs:
        base = r["numeric_fields"]; a = r["candidate_action"]
        rows = []
        for tool, x1 in _valid_states(rt, r):
            for off in offs:
                num = {f: float(base[f]) + off[i] for i, f in enumerate(nf)}
                rows.append(gate.enc.transform_point(r["domain"], tool, a, x1, num))
        proba = gate.est.predict_proba(np.asarray(rows))[:, 1]
        if np.any(proba >= thr):
            hits += 1
    return hits / len(recs)


def run_setting(rt, records, *, eps=0.10, sigma=0.10, tau=0.95, n_mc=1000, alpha=1e-3,
                n_cert=40, n_attack=80, train_cap=12000, n_aug=4, seed=0, label=""):
    t0 = time.perf_counter()
    n = len(records)
    prev = Counter(r["category"] for r in records)
    train, val, test = stratified_split(records)

    gate = train_certified_gate(train[:train_cap], rt, sigma=sigma, n_aug=n_aug, seed=seed)
    ev = evaluate(gate, test)

    def sub(cat, k):
        return [r for r in test if r["category"] == cat][:k]

    U = sub("U", n_attack)
    attack_fa = batched_attack_false_allow(gate, rt, U, eps)

    # deterministic naive-composition false-certify on C (model-free; marginal certs fail)
    Csub = sub("C", 120)
    naive_C = (np.mean([detcert.certify(r, r["candidate_action"], rt, 1, eps).get(
        "naive_composition_false_certify", False) for r in Csub]) if Csub else float("nan"))

    # learned enumerate_discrete_gaussian_rs certificate
    cert_recs = sum((sub(c, n_cert) for c in "ABCRU"), [])
    certs = [certify(gate, rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=n_mc, alpha=alpha)
             for r in cert_recs]
    allow = np.array([c["allow"] for c in certs])
    cats = np.array([r["category"] for r in cert_recs])

    def ar(c):
        msk = cats == c
        return float(np.mean(allow[msk])) if msk.any() else float("nan")

    allowed_idx = np.where(allow)[0]
    false_allow = 0
    for i in allowed_idx:
        r = cert_recs[i]
        if r["y"] == 0 or joint_reachable_unsafe(r, r["candidate_action"], rt, 1, eps)["reachable"]:
            false_allow += 1
    cert_fa = false_allow / max(1, len(allowed_idx))

    runtime = time.perf_counter() - t0
    return {
        "label": label, "K": rt["meta"].get("K"), "k": rt["meta"].get("k"),
        "x1": rt["meta"].get("x1_size"), "n_records": n,
        "A_pct": round(100 * prev.get("A", 0) / n, 1), "B_pct": round(100 * prev.get("B", 0) / n, 1),
        "C_pct": round(100 * prev.get("C", 0) / n, 1), "R_pct": round(100 * prev.get("R", 0) / n, 1),
        "U_pct": round(100 * prev.get("U", 0) / n, 1),
        "clean_acc": round(ev["clean_acc"], 4),
        "attack_false_allow": round(attack_fa, 4),
        "naive_C_falseallow": round(float(naive_C), 4),
        "C_allow": round(ar("C"), 4), "R_allow": round(ar("R"), 4), "U_allow": round(ar("U"), 4),
        "A_allow": round(ar("A"), 4), "B_allow": round(ar("B"), 4),
        "cert_false_allow": round(cert_fa, 4),
        "sigma": sigma, "tau": tau, "eps": eps, "n_mc": n_mc,
        "runtime_seconds": round(runtime, 1),
    }


SCALING_COLS = ["label", "K", "k", "x1", "n_records", "A_pct", "B_pct", "C_pct", "R_pct", "U_pct",
                "clean_acc", "attack_false_allow", "naive_C_falseallow",
                "C_allow", "R_allow", "U_allow", "cert_false_allow",
                "sigma", "tau", "eps", "n_mc", "runtime_seconds"]


def to_md(rows, cols, title, note=""):
    out = [f"# {title}\n", note + "\n" if note else "",
           "| " + " | ".join(cols) + " |", "| " + " | ".join("---" for _ in cols) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
    return "\n".join(out) + "\n"
