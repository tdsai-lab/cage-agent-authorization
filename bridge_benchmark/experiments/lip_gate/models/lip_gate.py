#!/usr/bin/env python3
"""
lip_gate.py — core for EXP_LIP_VS_RS: train a 1-Lipschitz gate on OPA/Rego labels and certify it two
ways on the SAME model — (a) the project SMOOTHING certificate and (b) a DETERMINISTIC margin
certificate — so the smoothing "tax" can be isolated from learned-margin deficiency.

Reuses: opa_gate.OpaOracle (executable Safe labels + R/C/U/A/B exact categories), schema.build_rt,
FeatureEncoder, and smoothed_gate.certify / _states. The FeatureEncoder is used WITHOUT numeric
standardization (identity), so the network's 1-Lipschitz-in-input property is 1-Lipschitz in the RAW
ε-ball, and the smoothing path (σ,ε in raw units) and the deterministic path share one encoding.

policy_provenance = authored_provenance_conditioned_rego (authored Rego evaluated by OPA). The
deterministic certificate certifies the LEARNED Lipschitz gate; oracle false-allows remain empirical
measurements against the executable policy.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F

_HERE = Path(__file__).resolve().parent
_EXP = _HERE.parent
_BB = _EXP.parents[1]
for p in ("generators", "models", "cert"):
    sys.path.insert(0, str(_BB / p))
sys.path.insert(0, str(_BB / "experiments" / "opa_gate"))
sys.path.insert(0, str(_HERE))

from dataset import FeatureEncoder  # noqa: E402
from smoothed_gate import certify as smooth_certify, _states  # noqa: E402
from opa_oracle import OpaOracle  # noqa: E402
from schema import sample_records  # noqa: E402
from orthogonium_adapter import LipGate, empirical_lipschitz, backend_name, CLAIMED_L  # noqa: E402

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
PROVENANCE = "authored_provenance_conditioned_rego"


def make_encoder(rt):
    """FeatureEncoder with IDENTITY numeric normalization (no fit_numeric) -> raw ε-ball == input ε-ball."""
    return FeatureEncoder(rt)             # mean=0, std=1 by default


def _xy(orc, enc, records):
    X = enc.matrix(records).astype(np.float32)
    y = np.array([1 if s else 0 for s in orc.safe_records(records)], dtype=np.float32)
    return X, y


# --------------------------------------------------------------------------- #
# training (signed-margin loss; variants small/medium/robust-aug)
# --------------------------------------------------------------------------- #
def _augment(orc, train, sigma, n_aug, seed):
    """Oracle-relabelled augmentation: discrete neighbours + Gaussian x perturbations (labels via OPA)."""
    rng = np.random.default_rng(seed)
    rt, dc = orc.rt, orc.dc
    nf = dc["numeric_fields"]
    extra = []
    for r in train:
        for tool, x1 in _states(rt, {**r, "domain": orc.domain}):
            extra.append({"domain": orc.domain, "tool_id": tool, "candidate_action": r["candidate_action"],
                          "categorical_fields": x1, "numeric_fields": dict(r["numeric_fields"])})
        for _ in range(n_aug):
            num = {f: float(r["numeric_fields"][f]) + float(rng.normal(0, sigma)) for f in nf}
            extra.append({"domain": orc.domain, "tool_id": r["tool_id"],
                          "candidate_action": r["candidate_action"],
                          "categorical_fields": r["categorical_fields"], "numeric_fields": num})
    return extra


def train_lipgate(orc, enc, train, variant="medium", epochs=250, lr=1e-3, gamma=0.25,
                  lam_margin=0.5, sigma=0.10, seed=0, width=None, depth=None, n_aug=4):
    """1-Lipschitz orthogonal gate. `width`/`depth` override the variant default (capacity sweep);
    `n_aug` sets the robust-aug per-record Gaussian augmentation count. Backward-compatible: with
    width=depth=None and n_aug=4 the behaviour is identical to the original variant map."""
    w0, d0 = {"small": (64, 2), "medium": (128, 3), "robust-aug": (128, 3)}[variant]
    width, depth = (w0 if width is None else width), (d0 if depth is None else depth)
    recs = list(train)
    if variant == "robust-aug":
        recs = recs + _augment(orc, train, sigma, n_aug=n_aug, seed=seed)
    X, y = _xy(orc, enc, recs)
    torch.manual_seed(seed)
    Xt = torch.from_numpy(X).to(DEVICE)
    yt = torch.from_numpy(2 * y - 1).to(DEVICE)             # {-1,+1}
    w_pos = float((y == 0).sum() / max(1, (y == 1).sum()))  # class weights (balance)
    wt = torch.where(yt > 0, torch.tensor(w_pos, device=DEVICE), torch.tensor(1.0, device=DEVICE))
    model = LipGate(X.shape[1], width=width, depth=depth).to(DEVICE)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    model.train()
    for _ in range(epochs):
        opt.zero_grad()
        h = model(Xt)
        loss = (wt * (F.softplus(-yt * h) + lam_margin * F.relu(gamma - yt * h))).mean()
        loss.backward()
        opt.step()
    model.eval()
    return model


# --------------------------------------------------------------------------- #
# smoothing on the LipGate: wrap as a GateModel-compatible object for smoothed_gate.certify
# --------------------------------------------------------------------------- #
class _LipEst:
    def __init__(self, model):
        self.model = model

    def predict_proba(self, X):
        with torch.no_grad():
            h = self.model(torch.from_numpy(np.asarray(X, dtype=np.float32)).to(DEVICE))
            p = torch.sigmoid(h).cpu().numpy()
        return np.stack([1 - p, p], axis=1)


class LipSmoothWrapper:
    """Exposes `.enc` and `.est.predict_proba` so smoothed_gate.certify runs the smoothing certificate
    on the LipGate (same encoding the deterministic certificate uses)."""

    def __init__(self, model, enc, rt):
        self.enc, self.est, self.rt = enc, _LipEst(model), rt
        self.name = "lipgate"

    def proba_safe_point(self, domain, tool, action, x1, numeric):
        v = np.asarray(self.enc.transform_point(domain, tool, action, x1, numeric), dtype=np.float32)
        return float(self.est.predict_proba(v[None, :])[0, 1])

    def allow_point(self, domain, tool, action, x1, numeric, thr=0.5):
        return self.proba_safe_point(domain, tool, action, x1, numeric) >= thr


# --------------------------------------------------------------------------- #
# deterministic Lipschitz certificate: min_{s'∈N_d(s)} h_θ(s',x,a) > L·ε
# --------------------------------------------------------------------------- #
def margins_over_branches(model, enc, rt, rec):
    rows, branches = [], []
    action = rec["candidate_action"]
    for tool, x1 in _states(rt, rec):
        branches.append((tool, x1))
        rows.append(enc.transform_point(rec["domain"], tool, action, x1, rec["numeric_fields"]))
    with torch.no_grad():
        h = model(torch.from_numpy(np.asarray(rows, dtype=np.float32)).to(DEVICE)).cpu().numpy()
    return h, branches


def certify_lip(model, enc, rt, rec, eps, L=CLAIMED_L):
    h, branches = margins_over_branches(model, enc, rt, rec)
    min_margin = float(np.min(h))
    return {"allow": bool(min_margin > L * eps), "min_margin": round(min_margin, 4),
            "cert_radius": round(min_margin / L, 4), "L": L, "n_branches": len(branches)}


def lip_pointwise_allow(model, enc, rec):
    with torch.no_grad():
        v = np.asarray(enc.transform_record(rec), dtype=np.float32)
        return float(model(torch.from_numpy(v[None, :]).to(DEVICE)).item()) > 0.0


# --------------------------------------------------------------------------- #
# smoothing certificate on the LipGate (reuses the project certifier)
# --------------------------------------------------------------------------- #
def certify_smooth(wrapper, rt, rec, sigma, eps, tau, n_mc, alpha):
    return smooth_certify(wrapper, rt, rec, sigma=sigma, eps=eps, tau=tau, n_mc=n_mc, alpha=alpha)


# --------------------------------------------------------------------------- #
# exact robust oracle (OPA: enumerate N_1, check threshold at x±ε per branch -> category R)
# --------------------------------------------------------------------------- #
def exact_categories(orc, records, eps):
    """Returns (cats, status). status='exact' for the monotone-threshold authored policies."""
    return orc.categorize(records, eps), "exact"
