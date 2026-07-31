#!/usr/bin/env python3
"""
test_p4_soundness.py — PLAN_2 P4 (defensive cleanup). Two structural invariants:

  Task G (soundness_suite): across base-gate architectures the smoothing certificate keeps
    cert_false_allow == 0 (soundness invariant) while R_allow moves (utility), on the executable OPA
    finance policy.
  Task H (tighten_lcert): the certified LOCAL Lipschitz bound is (i) SOUND — allowed points are never
    truly-unsafe — and (ii) a SUPERSET of the global L=1 certificate (L_loc ≤ 1 ⇒ allow_local ⊇
    allow_global), with the raw continuous-block gradient norm a valid local Lipschitz value in [0, 1].

torch/orthogonium/OPA-dependent; skipped if unavailable (matches test_lip_gate.py).
"""
import sys
from pathlib import Path

import pytest

_EXP = Path(__file__).resolve().parents[1] / "bridge_benchmark" / "experiments" / "lip_gate"
sys.path.insert(0, str(_EXP / "models"))
sys.path.insert(0, str(_EXP / "scripts"))

try:
    import torch  # noqa: F401
    import lip_gate as LG  # noqa: F401
    _OK = True
    try:
        import opa_bridge  # noqa: F401
        opa_bridge.opa_version()
        _OPA = True
    except Exception:
        _OPA = False
except Exception:
    _OK = _OPA = False

skip_opa = pytest.mark.skipif(not (_OK and _OPA), reason="torch/orthogonium/OPA not available")


@skip_opa
def test_base_gate_sweep_soundness_invariant():
    import soundness_suite as S
    orc = LG.OpaOracle("finance")
    enc_lip = LG.make_encoder(orc.rt)
    train = LG.sample_records("finance", 400, seed=0)
    ev = LG.sample_records("finance", 200, seed=1)
    rows = S.study_base_gates(orc, enc_lip, train, ev, per_cat=20, sigma=0.10, eps=0.10, tau=0.90,
                              n_mc=400, alpha=1e-3, n_aug=4, seed=0)
    assert {r["base_gate"] for r in rows} >= {"mlp", "gbt", "logistic", "lipgate"}
    # soundness invariant: NO base gate / backend produces a certified false-allow
    assert max(r["cert_false_allow"] for r in rows) == 0.0
    # utility moves across architectures (not all identical) — the "procedure not architecture" point
    assert len({r["R_allow"] for r in rows}) > 1


@skip_opa
def test_local_lipschitz_cert_sound_and_superset():
    import tighten_lcert as H
    orc = LG.OpaOracle("finance")
    enc = LG.make_encoder(orc.rt)
    train = LG.sample_records("finance", 400, seed=0)
    ev = LG.sample_records("finance", 200, seed=1)
    model = LG.train_lipgate(orc, enc, train, variant="robust-aug", epochs=150, seed=0)
    cats = orc.categorize(ev, 0.10)
    sub = H._balanced(cats, ev, 25, 0)
    n_super = 0
    for c, r in sub:
        cz = H.certify_local(model, enc, orc.rt, r, 0.10, LG.DEVICE)
        # raw continuous-block gradient norm is a valid local Lipschitz value (orthogonal backbone ⇒ ≤ 1)
        assert 0.0 <= cz["raw_grad_mean"] <= 1.0 + 1e-4
        # superset: L_loc ≤ 1 ⇒ the local certificate allows everything the L=1 certificate allows
        if cz["allow_global"]:
            assert cz["allow_local"], "local cert dropped a point the global L=1 cert allowed (not a superset)"
            n_super += 1
        # soundness: a locally-allowed point is never truly unsafe under the OPA oracle
        if cz["allow_local"]:
            assert not c["truly_unsafe_reachable"], "local-Lipschitz-allowed point is truly unsafe (UNSOUND)"
    assert n_super > 0, "expected at least one globally-allowed R point to anchor the superset check"
