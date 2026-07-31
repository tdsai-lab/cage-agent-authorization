#!/usr/bin/env python3
"""
certify_lipschitz_bound.py — FOLLOWUP (1): compute a CERTIFIED per-layer Lipschitz bound for the
LipGate (vs the empirical estimate), to check whether the deterministic certificate's `L=1` carries
removable slack.

Certified global bound = Π_layers σ_max(W_layer) (× 1 for the 1-Lipschitz MaxMin activations). Because
every linear layer is Orthogonium-orthogonal (`OrthoLinear` / `UnitNormLinear` are semi-orthogonal,
σ_max = 1 exactly), the product is exactly 1 — and even RESTRICTED to the continuous input sub-block the
first (over-complete) layer's column-submatrix is orthonormal (σ_max = 1). So `L_cert = 1` is the TIGHT
certified global bound: the gap to the empirical Lipschitz (≈0.4) is the gate's UNUSED capacity / local
flatness, NOT a removable backend tax. The deterministic decomposition with L=1 is therefore already
clean (no L-slack to subtract from `learned_margin_deficiency`).

A strictly tighter bound would require a LOCAL (per-example, region-restricted) Lipschitz certificate —
a different, heavier object, out of scope here.
"""
from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

import numpy as np
import torch

warnings.filterwarnings("ignore")
_EXP = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_EXP / "models"))
import lip_gate as LG  # noqa: E402
from orthogonium_adapter import empirical_lipschitz  # noqa: E402


def _spectral(W: torch.Tensor) -> float:
    return float(torch.linalg.matrix_norm(W.detach().float(), 2).cpu())


def certified_lipschitz(model, cont_cols):
    """Certified global Lipschitz = product of per-layer spectral norms (MaxMin = 1). Also the bound
    RESTRICTED to the continuous columns of the first linear layer (the only block the certificate
    perturbs)."""
    per_layer, first_W = [], None
    for mod in model.net:
        W = getattr(mod, "weight", None)
        if W is not None and W.ndim == 2:
            s = _spectral(W)
            per_layer.append({"layer": type(mod).__name__, "shape": list(W.shape), "sigma_max": round(s, 4)})
            if first_W is None:
                first_W = W.detach().float()
    L_global = float(np.prod([l["sigma_max"] for l in per_layer]))
    # continuous-block bound: σ_max of the first layer's continuous columns × ∏ rest (=1)
    rest = float(np.prod([l["sigma_max"] for l in per_layer[1:]])) if len(per_layer) > 1 else 1.0
    sigma_cont = _spectral(first_W[:, cont_cols]) if first_W is not None and cont_cols else float("nan")
    L_cont = sigma_cont * rest
    return per_layer, L_global, sigma_cont, L_cont


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domain", default="finance")
    ap.add_argument("--variant", default="robust-aug")
    ap.add_argument("--n-train", type=int, default=1500)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    DIAG = _EXP / "results" / "diagnostics"; DIAG.mkdir(parents=True, exist_ok=True)

    orc = LG.OpaOracle(args.domain)
    enc = LG.make_encoder(orc.rt)
    train = LG.sample_records(args.domain, args.n_train, seed=args.seed)
    model = LG.train_lipgate(orc, enc, train, variant=args.variant, seed=args.seed)
    dim = enc.matrix(train[:1]).shape[1]
    start, fields, _m, _s = enc.numeric_block()
    cont_cols = list(range(start, start + len(fields)))
    per_layer, L_global, sigma_cont, L_cont = certified_lipschitz(model, cont_cols)
    emp = empirical_lipschitz(model, dim, device=LG.DEVICE)

    out = {
        "domain": args.domain, "variant": args.variant, "in_dim": dim,
        "continuous_cols": cont_cols,
        "per_layer_spectral_norms": per_layer,
        "L_cert_global": round(L_global, 4),
        "L_cert_continuous_block": round(L_cont, 4),
        "sigma_max_first_layer_continuous_cols": round(sigma_cont, 4),
        "L_emp": round(emp, 4),
        "L_used_in_certificate": 1.0,
        "L_slack_global_vs_emp": round(L_global - emp, 4),
        "verdict": ("L_cert = 1 is TIGHT (orthogonal layers); the gap to L_emp is unused capacity / "
                    "local flatness, NOT removable backend tax — the L=1 decomposition is already clean."
                    if abs(L_global - 1.0) < 1e-3 else
                    "L_cert < 1: re-run certify_lip with this tighter bound to reduce L-slack."),
        "note": "A strictly tighter bound needs a LOCAL per-example Lipschitz certificate (out of scope).",
    }
    (DIAG / f"lipschitz_bound_{args.domain}_{args.variant}.json").write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps({k: out[k] for k in ("L_cert_global", "L_cert_continuous_block",
                                          "sigma_max_first_layer_continuous_cols", "L_emp",
                                          "verdict")}, indent=2))
    print(f"per-layer σ_max: {[l['sigma_max'] for l in per_layer]}")
    print(f"wrote -> {DIAG/f'lipschitz_bound_{args.domain}_{args.variant}.json'}")


if __name__ == "__main__":
    main()
