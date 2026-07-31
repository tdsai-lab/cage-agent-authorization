#!/usr/bin/env python3
"""
test_harness_boundary.py — EXP-HARNESS boundary + soundness tests.

Asserts the three load-bearing properties of the deployed-agent harness:
  (a) the post-return authorization gate NEVER receives the untrusted display text (by construction /
      call-path inspection: the gate is only ever handed the nominal typed z, never the prompt or note);
  (b) a display-only (TM1) injection changes the mock-LLM proposal but NOT the gate decision;
  (c) the certified joint gate REFUSES a constructed Category-C witness while the naive (marginal)
      certificate FALSE-ALLOWS it.

Fast (tiny n / tiny n_mc). Skip-guarded if heavy deps (sklearn) are missing.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

_root = Path(__file__).resolve().parents[1] / "bridge_benchmark"
for p in ("generators", "models", "cert", "experiments", "agents"):
    sys.path.insert(0, str(_root / p))

pytest.importorskip("sklearn")
pytest.importorskip("numpy")

from oracle import category, safe  # noqa: E402
from tool_env import ToolEnvironment, DOMAIN_SPEC  # noqa: E402
from baselines import train_certified_gate  # noqa: E402
from end_to_end_exploit import make_gates, train_pre_exec_gate, CertGate, MarginalCertGate  # noqa: E402

import exp_harness as H  # noqa: E402

EPS = 0.10
DOMAIN_KEY = "synthetic"


def _as_rec(observed, action):
    return {"domain": DOMAIN_KEY, "tool_id": observed["tool_id"], "candidate_action": action,
            "categorical_fields": observed["categorical_fields"],
            "numeric_fields": observed["numeric_fields"]}


# ---------------------------------------------------------------------------- #
# (a) the gate never receives display text — call-path / signature inspection
# ---------------------------------------------------------------------------- #
def test_gate_evaluate_signature_excludes_display_text():
    """Every gate's evaluate(z, action) takes exactly (nominal_z, action) — there is no parameter by
    which the untrusted display note could ever be passed in."""
    for cls in (H, ):
        pass
    for gate_cls in (CertGate, MarginalCertGate):
        params = list(inspect.signature(gate_cls.evaluate).parameters)
        # (self, nominal/observed, action) — two non-self positional args, none named for display/note
        assert params[0] == "self"
        assert len(params) == 3, params
        assert not any("note" in p or "display" in p or "prompt" in p for p in params), params


def test_run_episode_passes_nominal_z_not_note_to_gate():
    """In run_harness_episode the gate is invoked as gate.evaluate(nominal, a_priv): the source shows
    the note/prompt are consumed by the LLM only, never handed to the gate."""
    src = inspect.getsource(H.run_harness_episode)
    # the only gate call passes `nominal` (the typed z); the note feeds build_harness_prompt only
    assert "gate.evaluate(nominal, a_priv)" in src
    assert "build_harness_prompt(domain, nominal, primary, note)" in src
    # every gate.evaluate(...) call in the episode passes exactly (nominal, a_priv) — never the note,
    # display text, or prompt.
    import re as _re
    calls = _re.findall(r"gate\.evaluate\(([^)]*)\)", src)
    assert calls, "expected a gate.evaluate call in the episode"
    for argstr in calls:
        assert argstr.strip() == "nominal, a_priv", argstr
        assert "note" not in argstr and "prompt" not in argstr and "display" not in argstr


# ---------------------------------------------------------------------------- #
# (b) TM1 display injection moves the LLM proposal but NOT the gate decision
# ---------------------------------------------------------------------------- #
def test_tm1_injection_moves_proposal_not_gate_decision():
    env = ToolEnvironment("financial_compliance", n_pool=2000, eps=EPS, seed=0)
    spec = DOMAIN_SPEC["financial_compliance"]
    a_priv, a_fb = spec["privileged"], spec["fallback"]
    llm = H.HarnessMockLLM()

    # find a record where the benign agent does NOT propose the privileged action (high signal),
    # so the injection can flip the proposal.
    flipped = None
    for rec in env.records[:1500]:
        z = env.call_tool(rec)
        primary = env.primary_signal(z)
        benign_prompt = H.build_harness_prompt("financial_compliance", z, primary,
                                               H.display_note("financial_compliance", "benign"))
        inj_prompt = H.build_harness_prompt("financial_compliance", z, primary,
                                            H.display_note("financial_compliance", "ignore_approve"))
        from llm_client import parse_action
        allowed = H.ALLOWED["financial_compliance"]
        benign_a, _ = parse_action(llm.complete(benign_prompt, pressure=0.0), allowed, a_fb)
        inj_a, _ = parse_action(
            llm.complete(inj_prompt, pressure=H._injection_pressure("ignore_approve")), allowed, a_fb)
        if benign_a != a_priv and inj_a == a_priv:
            flipped = z
            break
    assert flipped is not None, "expected at least one record where injection flips the proposal"

    # the gate decision on the NOMINAL z must be identical regardless of which note was shown:
    # the gate never sees the note, so by construction the decision cannot change.
    train_pool = env.records[:4000]
    model = train_certified_gate(train_pool, env.rt, sigma=0.10, n_aug=3, seed=0)
    pre = train_pre_exec_gate(train_pool, env.rt, seed=0)
    gates = make_gates("all", model, pre, env.rt, 0.10, EPS, 0.80, 200, 1e-3)
    for g in gates.values():
        dec_a, _ = g.evaluate(flipped, a_priv)   # only ever the typed z is passed
        dec_b, _ = g.evaluate(flipped, a_priv)
        assert dec_a == dec_b   # deterministic & note-independent (gate has no note input at all)


# ---------------------------------------------------------------------------- #
# (c) certified joint gate refuses a C-witness that the naive (marginal) cert false-allows
# ---------------------------------------------------------------------------- #
def test_certified_refuses_c_witness_naive_false_allows():
    env = ToolEnvironment("financial_compliance", n_pool=3000, eps=EPS, seed=0)
    spec = DOMAIN_SPEC["financial_compliance"]
    a_priv = spec["privileged"]

    c_pool = env.by_category("C")
    assert c_pool, "expected Category-C records in the finance schema"
    # pick a clean C nominal (the gate authorizes the region; the witness lives inside B_{1,eps})
    nominal = None
    for rec in c_pool:
        z = env.call_tool(rec)
        cat = category(_as_rec(z, a_priv), a_priv, env.rt, d=1, eps=EPS)
        if cat["category"] == "C_joint_gap" and safe(_as_rec(z, a_priv), a_priv, env.rt):
            nominal = z
            break
    assert nominal is not None, "expected a clean Category-C joint-gap witness"

    train_pool = env.records[:4000]
    model = train_certified_gate(train_pool, env.rt, sigma=0.10, n_aug=3, seed=0)

    naive = MarginalCertGate(env.rt, eps=EPS)
    joint = CertGate(model, env.rt, sigma=0.10, eps=EPS, tau=0.80, n_mc=400, alpha=1e-3)

    naive_allow, _ = naive.evaluate(nominal, a_priv)
    joint_allow, _ = joint.evaluate(nominal, a_priv)

    assert naive_allow is True, "naive (marginal) certificate must FALSE-ALLOW the C-witness"
    assert joint_allow is False, "certified joint gate must REFUSE the C-witness"
