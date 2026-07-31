#!/usr/bin/env python3
"""EXP_LIP_VS_RS — deterministic 1-Lipschitz gate backend vs the smoothing certificate.

Checks: LipGate is empirically 1-Lipschitz (sanity for the deterministic certificate); the deterministic
margin certificate is SOUND (certified-allowed points are never truly-unsafe under the OPA oracle) and
non-vacuous; the exact oracle status is 'exact'; and provenance is labelled authored_provenance_
conditioned_rego. OPA/torch-dependent tests are skipped if unavailable.
"""
import sys
from pathlib import Path

_EXP = Path(__file__).resolve().parents[1] / "bridge_benchmark" / "experiments" / "lip_gate"
sys.path.insert(0, str(_EXP / "models"))

import pytest  # noqa: E402

try:
    import torch  # noqa: F401
    import lip_gate as LG
    from orthogonium_adapter import LipGate, empirical_lipschitz, backend_name, CLAIMED_L
    _OK = True
    try:
        import opa_bridge  # noqa: F401
        opa_bridge.opa_version()
        _OPA = True
    except Exception:
        _OPA = False
except Exception:
    _OK = _OPA = False

skip_torch = pytest.mark.skipif(not _OK, reason="torch/orthogonium not available")
skip_opa = pytest.mark.skipif(not (_OK and _OPA), reason="OPA binary not available")


@skip_torch
def test_lipgate_is_1_lipschitz_and_scalar():
    import torch
    m = LipGate(12, width=64, depth=2)
    out = m(torch.randn(7, 12))
    assert out.shape == (7,)                                    # scalar signed margin per example
    assert empirical_lipschitz(m, 12) <= CLAIMED_L + 1e-3       # 1-Lipschitz sanity (not the cert)
    assert backend_name() in ("orthogonium", "torch_fallback")


@skip_torch
def test_provenance_label():
    assert LG.PROVENANCE == "authored_provenance_conditioned_rego"


@skip_opa
def test_deterministic_certificate_is_sound_and_nonvacuous():
    orc = LG.OpaOracle("finance")
    enc = LG.make_encoder(orc.rt)
    train = LG.sample_records("finance", 800, seed=0)
    ev = LG.sample_records("finance", 300, seed=1)
    model = LG.train_lipgate(orc, enc, train, variant="robust-aug", epochs=150, seed=0)
    cats, status = LG.exact_categories(orc, ev, 0.10)
    assert status == "exact"
    allowed_R = 0
    for c, r in zip(cats, ev):
        cz = LG.certify_lip(model, enc, orc.rt, r, 0.10)
        if cz["allow"]:
            assert not c["truly_unsafe_reachable"], "deterministic-allowed point is truly unsafe (UNSOUND)"
            if c["category"] == "R":
                allowed_R += 1
    assert allowed_R > 0, "deterministic certificate is vacuous (recovers no R) — expected non-vacuous"


@skip_opa
def test_smoothing_on_lipgate_is_sound():
    orc = LG.OpaOracle("sre")
    enc = LG.make_encoder(orc.rt)
    train = LG.sample_records("sre", 800, seed=0)
    ev = LG.sample_records("sre", 150, seed=2)
    model = LG.train_lipgate(orc, enc, train, variant="medium", epochs=120, seed=0)
    wrap = LG.LipSmoothWrapper(model, enc, orc.rt)
    cats, _ = LG.exact_categories(orc, ev, 0.10)
    for c, r in zip(cats, ev):
        cz = LG.certify_smooth(wrap, orc.rt, r, 0.10, 0.10, 0.90, 600, 1e-3)
        if cz["allow"]:
            assert not c["truly_unsafe_reachable"], "smoothing-allowed point is truly unsafe (UNSOUND)"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
