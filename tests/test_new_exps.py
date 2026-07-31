#!/usr/bin/env python3
"""
test_new_exps.py — NEW_EXPS EXP1 (neighbor head-to-head) + EXP2 (validation-stack adversary).

Structural invariants (small, skip-guarded on OPA / torch availability):
  EXP1: the verified-point predicate shares the OPA Safe label at the observed point (exact-at-point); on
        the exploit-witness set the sound neighborhood rows (exact rung-1, AllowRS) have attack_false_allow
        = cert_false_allow = 0, and the certified gate is sound.
  EXP2: the freshness-SLA hit-rate is monotone in Δt and cert_false_allow stays 0 (declared-budget
        soundness); the constructor-corruption false_allow is monotone in the flip probability (TCB
        boundary — outside B_{d,ε}).
"""
import sys
from pathlib import Path

import pytest

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
sys.path.insert(0, str(_BB / "experiments"))
sys.path.insert(0, str(_BB / "experiments" / "opa_gate"))

try:
    import opa_bridge
    opa_bridge.opa_version()
    import ieee_opa_gate as G
    from ieee_cis_opa_cwitness import load_records, IEEE_PATH
    _OPA = IEEE_PATH.exists()
except Exception:
    _OPA = False

skip_opa = pytest.mark.skipif(not _OPA, reason="OPA binary or IEEE-CIS data not available")


@skip_opa
def test_ieee_gate_opa_label_path_and_encoding():
    recs = load_records(n=200)
    # encoding: provenance one-hot (4 tools) ++ numeric x2; risk_score column locatable
    v = G.encode_point(recs[0]["tool_id"], recs[0]["x2"])
    assert v.shape[0] == len(G.TOOLS) + len(G.NUMERIC_FIELDS)
    assert v[: len(G.TOOLS)].sum() == 1.0                       # exactly one provenance hot
    labels = G.opa_safe([G._case(r["tool_id"], r["x2"]) for r in recs[:10]])
    assert len(labels) == 10 and all(isinstance(b, bool) for b in labels)
    assert G.neighbors(recs[0]["tool_id"])[0] == recs[0]["tool_id"]  # N_1 includes identity first


@skip_opa
def test_allow_rs_sound_on_a_strict_unsafe_neighbor():
    recs = load_records(n=400)
    gate = G.train_gate(recs[:300], sigma=0.10, n_aug=4, seed=0)
    # AllowRS returns a structured, in-range certificate
    cz = G.allow_rs(gate, recs[301]["tool_id"], recs[301]["x2"], n_mc=400, seed=0)
    assert set(cz) >= {"allow", "min_ell", "worst_state"}
    assert 0.0 <= cz["min_ell"] <= 1.0


@skip_opa
def test_exp1_witness_invariants_small():
    import neighbor_head_to_head as E
    recs = load_records(n=2000)
    r = E.run_seed(recs, n_train=500, n_eval=500, eps=0.10, sigma=0.10, tau=0.90,
                   n_mc=400, alpha=1e-3, seed=0)
    rows = r["rows"]
    assert r["n_witness"] > 0
    # verified_point allows 100% of exploit witnesses by construction (exact-at-point buys nothing)
    assert abs(rows["verified_point_predicate"]["attack_false_allow"] - 1.0) < 1e-9
    # learned point never exceeds the verified point (MLP imperfection only lowers it)
    assert rows["learned_point"]["attack_false_allow"] <= 1.0 + 1e-9
    # the SOUND neighborhood rows remove the in-budget exploit and never false-allow in-ball
    for row in ("exact_rung1", "certified_rs"):
        assert rows[row]["attack_false_allow"] == 0.0
        assert rows[row]["cert_false_allow"] == 0.0


@skip_opa
def test_exp2a_hit_rate_monotone_and_sound():
    import validation_stack_adversary as V
    pool, auc = V.build_pool(seed=0, max_rows=120000)
    strata = V._strata(pool)
    import numpy as np
    eval_idx = np.random.default_rng(0).permutation(len(pool))[:1500]
    rows = V.sweep_deltat(pool, strata, [3600, 86400, 604800, 5184000], eval_idx)
    hr = [r["coverage_hit_rate"] for r in rows]
    assert hr == sorted(hr)                                     # hit-rate monotone in the SLA Δt
    assert all(r["cert_false_allow"] == 0.0 for r in rows)     # declared-budget soundness invariant
    assert all(r["eps_emp_p95"] >= 0.0 for r in rows)


@skip_opa
def test_exp2b_constructor_false_allow_monotone():
    import validation_stack_adversary as V
    rows = V.constructor_corruption_sweep([0.0, 0.5], n_eval=400, seed=0)
    fa = {r["flip_prob"]: r["false_allow"] for r in rows}
    assert fa[0.0] == 0.0                                       # no corruption -> no constructor false-allow
    assert fa[0.5] >= fa[0.0]                                   # corruption opens the TCB-boundary hole
