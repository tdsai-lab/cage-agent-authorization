#!/usr/bin/env python3
"""
orthogonium_adapter.py — a 1-Lipschitz scalar signed-margin gate (EXP_LIP_VS_RS).

LipGate(features) -> scalar signed margin h_θ; decision: safe ⟺ h_θ > 0. The network is 1-Lipschitz
w.r.t. its full input vector in the L2 norm, hence ≤ 1-Lipschitz w.r.t. the (raw, un-standardized)
continuous sub-block — which is what the deterministic margin certificate needs. The categorical
one-hot block is fixed per discrete branch and is handled by exact enumeration, not the Lipschitz bound.

Backend: Orthogonium orthogonal linear layers (`OrthoLinear`, norm-preserving), `MaxMin` activation
(GroupSort-style, gradient-norm-preserving → 1-Lipschitz), and a `UnitNormLinear` scalar head
(1-Lipschitz). No BatchNorm, no Dropout, no unconstrained Linear, no activation with Lip > 1.

If Orthogonium is unavailable, falls back to torch orthogonal-parametrized Linear + a MaxMin shim, so
the experiment still runs (the claimed L is then validated empirically, same as the primary path).
"""
from __future__ import annotations

import torch
import torch.nn as nn

CLAIMED_L = 1.0          # global Lipschitz bound of LipGate w.r.t. its input (L2)

try:
    from orthogonium.layers import OrthoLinear, UnitNormLinear, MaxMin
    _BACKEND = "orthogonium"
except Exception:                                  # pragma: no cover - fallback path
    _BACKEND = "torch_fallback"
    from torch.nn.utils.parametrizations import orthogonal

    def OrthoLinear(i, o, bias=True):              # noqa: N802
        return orthogonal(nn.Linear(i, o, bias=bias))

    def UnitNormLinear(i, o, bias=True):           # noqa: N802
        lin = nn.Linear(i, o, bias=bias)
        with torch.no_grad():
            lin.weight.div_(lin.weight.norm(dim=1, keepdim=True) + 1e-12)
        return lin

    class MaxMin(nn.Module):                        # 1-Lipschitz GroupSort with group size 2
        def __init__(self, axis=1):
            super().__init__(); self.axis = axis

        def forward(self, x):
            a, b = x[..., 0::2], x[..., 1::2]
            return torch.cat([torch.maximum(a, b), torch.minimum(a, b)], dim=-1)


def backend_name() -> str:
    return _BACKEND


class LipGate(nn.Module):
    """1-Lipschitz scalar signed-margin gate. `width` must be even (MaxMin pairs channels)."""

    def __init__(self, in_dim: int, width: int = 128, depth: int = 3):
        super().__init__()
        assert width % 2 == 0, "width must be even for MaxMin"
        layers = [OrthoLinear(in_dim, width), MaxMin()]
        for _ in range(depth - 1):
            layers += [OrthoLinear(width, width), MaxMin()]
        layers += [UnitNormLinear(width, 1)]
        self.net = nn.Sequential(*layers)
        self.claimed_L = CLAIMED_L

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        """Return scalar signed margin h_θ (shape [N])."""
        return self.net(features).squeeze(-1)


@torch.no_grad()
def empirical_lipschitz(model: nn.Module, dim: int, n_pairs: int = 4000, device="cpu",
                        scale: float = 3.0) -> float:
    """Empirical L2 Lipschitz estimate over random input pairs — a sanity check, NOT the certificate.
    Catches implementation mistakes (should be ≤ claimed_L)."""
    model.eval()
    g = torch.Generator(device=device).manual_seed(0)
    x1 = (torch.rand(n_pairs, dim, generator=g, device=device) - 0.5) * 2 * scale
    x2 = (torch.rand(n_pairs, dim, generator=g, device=device) - 0.5) * 2 * scale
    y1, y2 = model(x1), model(x2)
    num = (y1 - y2).abs()
    den = (x1 - x2).norm(dim=1) + 1e-12
    return float((num / den).max().cpu())
