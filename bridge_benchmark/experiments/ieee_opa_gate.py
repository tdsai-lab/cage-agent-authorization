#!/usr/bin/env python3
"""
ieee_opa_gate.py — learned gate g_θ + certified backends (AllowRS, AllowLip) on the REAL IEEE-CIS
**executable** OPA policy `risk_score < θ(provenance)` (policies/authored/ieee_fraud.rego).

This is the missing wiring NEW_EXPS EXP1 needs: the existing OPA-gate certificates run on the synthetic
OpaOracle domains (finance/sre/ops) and on the IEEE *implicit* isFraud policy (#32), but NOT on the IEEE
*executable* Rego. Here every training label and every soundness check is produced by the real OPA 1.17.1
engine via the same `opa_bridge.eval_batch` path that #9b uses, so the learned/RS/Lip rows are comparable
to the exact rung-1 row (the only difference is the gate family, not the policy or the eval path).

Structure (deliberately compact, IEEE-specific — does NOT reroute through smoothed_gate.certify, whose
generic rule-table interface does not fit the IEEE provenance/risk_score neighborhood):
  - encode_point(tool, x2): provenance one-hot (4 tools) ++ raw numeric x2 (NO standardization, so the
    smoothing/Lipschitz ε-ball is the raw risk_score ε-ball, matching lip_gate's identity-encoder choice).
  - opa_safe(cases): batched real-OPA Safe labels (reused for training relabels AND soundness checks).
  - IeeeGate: a small sklearn MLP trained on OPA-relabelled Gaussian+discrete augmentations.
  - allow_rs : enumerate N_1(tool) = {tool, swap-partner}; per branch Gaussian RS on risk_score
               (Clopper–Pearson lower → Cohen ℓ_s(ε)); allow ⟺ min_s ℓ_s(ε) ≥ τ.   (sound over B_{1,ε})
  - LipGate (orthogonium) + allow_lip: deterministic margin min_{s'∈N_1} h(s',x2) > L·ε.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

_HERE = Path(__file__).resolve().parent
_BB = _HERE.parent
sys.path.insert(0, str(_HERE / "opa_gate"))
sys.path.insert(0, str(_BB / "realdata"))
sys.path.insert(0, str(_BB / "cert"))

import opa_bridge  # noqa: E402
import ieee_cis_policy as pol  # noqa: E402
from smoothed_gate import clopper_pearson_lower, cohen_lower  # noqa: E402

REGO = _HERE / "opa_gate" / "policies" / "authored" / "ieee_fraud.rego"
PACKAGE = "opa_gate.ieee_fraud"
ACTION = "approve_transaction"
RISK = "risk_score"
TOOLS = list(pol.TOOLS)
NUMERIC_FIELDS = list(pol.NUMERIC_FIELDS)          # risk_score first
_TOOL_IDX = {t: i for i, t in enumerate(TOOLS)}


# --------------------------------------------------------------------------- #
# real-OPA label path (one batched `opa eval` per call) — identical to #9b
# --------------------------------------------------------------------------- #
def _case(tool, x2):
    return {"tool": tool, "action": ACTION, "x1": {}, "x2": x2}


def opa_safe(cases, chunk=2000):
    """Batched real-OPA Safe(z, approve) for a list of (tool, x2) cases -> list[bool]."""
    out = []
    for s in range(0, len(cases), chunk):
        out.extend(opa_bridge.eval_batch(REGO, PACKAGE, cases[s:s + chunk]))
    return out


def neighbors(tool):
    """N_1(tool) = {tool} ∪ provenance swap partner(s) (loose↔strict), the real d=1 adapter swap."""
    return [tool] + list(pol.discrete_neighbors(tool))


# --------------------------------------------------------------------------- #
# encoding (provenance one-hot ++ raw numeric x2; identity numeric => raw ε-ball)
# --------------------------------------------------------------------------- #
def encode_point(tool, x2):
    v = np.zeros(len(TOOLS) + len(NUMERIC_FIELDS), dtype=np.float32)
    v[_TOOL_IDX[tool]] = 1.0
    for j, f in enumerate(NUMERIC_FIELDS):
        v[len(TOOLS) + j] = float(x2.get(f, 0.0))
    return v


def _risk_col():
    return len(TOOLS) + NUMERIC_FIELDS.index(RISK)


# --------------------------------------------------------------------------- #
# learned point gate g_θ (sklearn MLP on OPA-relabelled augmentation)
# --------------------------------------------------------------------------- #
class IeeeGate:
    def __init__(self, est):
        self.est = est

    def proba_safe_matrix(self, X):
        return self.est.predict_proba(X)[:, 1]

    def proba_safe(self, tool, x2):
        return float(self.est.predict_proba(encode_point(tool, x2)[None, :])[0, 1])

    def allow_point(self, tool, x2, thr=0.5):
        return self.proba_safe(tool, x2) >= thr


def _augment(records, sigma, n_aug, seed):
    """OPA-relabelled augmentation (PLAN3 convention: every augmented label is the OPA verdict, NEVER a
    clean label). Clean point + all provenance branches + Gaussian risk_score perturbations."""
    rng = np.random.default_rng(seed)
    aug = []
    for r in records:
        tool, x2 = r["tool_id"], r["x2"]
        aug.append((tool, dict(x2)))
        for t2 in pol.discrete_neighbors(tool):
            aug.append((t2, dict(x2)))
        for _ in range(n_aug):
            x2p = dict(x2); x2p[RISK] = float(x2[RISK]) + float(rng.normal(0.0, sigma))
            aug.append((tool, x2p))
    labels = opa_safe([_case(t, x2) for t, x2 in aug])          # one batched OPA call
    X = np.stack([encode_point(t, x2) for t, x2 in aug])
    y = np.array([1 if s else 0 for s in labels], dtype=int)
    return X, y


def build_training_set(records, sigma=0.10, n_aug=4, seed=0):
    """OPA-relabelled (X, y) — compute ONCE per seed and share between the MLP gate and the LipGate (the
    OPA labeling pass is the cost; both gates train on the identical augmented set)."""
    return _augment(records, sigma, n_aug, seed)


def train_gate(records, sigma=0.10, n_aug=4, seed=0, xy=None):
    from sklearn.neural_network import MLPClassifier
    X, y = xy if xy is not None else _augment(records, sigma, n_aug, seed)
    est = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=600, random_state=seed)
    # guard the degenerate single-class case (OPA labels are well-mixed in practice)
    if len(np.unique(y)) < 2:
        from sklearn.dummy import DummyClassifier
        est = DummyClassifier(strategy="constant", constant=int(y[0])).fit(X, y)
        return IeeeGate(est)
    est.fit(X, y)
    return IeeeGate(est)


# --------------------------------------------------------------------------- #
# AllowRS — enumerative Gaussian randomized smoothing over N_1(tool) (sound over B_{1,ε})
# --------------------------------------------------------------------------- #
def allow_rs(gate, tool, x2, sigma=0.10, eps=0.10, tau=0.90, n_mc=2000, alpha=1e-3, seed=0):
    rng = np.random.default_rng(seed + (hash((tool, round(float(x2[RISK]), 4))) & 0xFFFF))
    rc = _risk_col()
    min_ell = 1.0
    worst = None
    for s in neighbors(tool):
        base = encode_point(s, x2)
        M = np.tile(base, (n_mc, 1))
        M[:, rc] = float(x2[RISK]) + rng.normal(0.0, sigma, size=n_mc)
        k = int(np.sum(gate.proba_safe_matrix(M) >= 0.5))
        p_lb = clopper_pearson_lower(k, n_mc, alpha)
        ell = cohen_lower(p_lb, eps, sigma)
        if ell < min_ell:
            min_ell, worst = ell, s
    return {"allow": bool(min_ell >= tau), "min_ell": round(float(min_ell), 4), "worst_state": worst}


# --------------------------------------------------------------------------- #
# AllowLip — 1-Lipschitz gate + deterministic margin over N_1(tool)
# --------------------------------------------------------------------------- #
def train_lip_gate(records, sigma=0.10, n_aug=4, epochs=250, seed=0, xy=None):
    import torch
    import torch.nn.functional as F
    sys.path.insert(0, str(_BB / "experiments" / "lip_gate" / "models"))
    from orthogonium_adapter import LipGate
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    X, y = xy if xy is not None else _augment(records, sigma, n_aug, seed)
    torch.manual_seed(seed)
    Xt = torch.from_numpy(X.astype(np.float32)).to(dev)
    yt = torch.from_numpy((2 * y - 1).astype(np.float32)).to(dev)
    w_pos = float((y == 0).sum() / max(1, (y == 1).sum()))
    wt = torch.where(yt > 0, torch.tensor(w_pos, device=dev), torch.tensor(1.0, device=dev))
    model = LipGate(X.shape[1], width=128, depth=3).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    model.train()
    for _ in range(epochs):
        opt.zero_grad()
        h = model(Xt)
        loss = (wt * (F.softplus(-yt * h) + 0.5 * F.relu(0.25 - yt * h))).mean()
        loss.backward(); opt.step()
    model.eval()
    return model, dev


def _lip_margins(model, dev, tool, x2):
    import torch
    rows = np.stack([encode_point(s, x2) for s in neighbors(tool)])
    with torch.no_grad():
        h = model(torch.from_numpy(rows.astype(np.float32)).to(dev)).cpu().numpy()
    return h


def allow_lip(model, dev, tool, x2, eps=0.10, L=1.0):
    h = _lip_margins(model, dev, tool, x2)
    return {"allow": bool(float(np.min(h)) > L * eps), "min_margin": round(float(np.min(h)), 4)}


def lip_allow_point(model, dev, tool, x2):
    import torch
    with torch.no_grad():
        v = encode_point(tool, x2)
        return float(model(torch.from_numpy(v[None, :]).to(dev)).item()) > 0.0
