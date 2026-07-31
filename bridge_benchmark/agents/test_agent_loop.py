#!/usr/bin/env python3
"""
test_agent_loop.py — minimal agent-loop tests (PLAN sec.12). Run: python -m pytest -q (collected by
pytest.ini under bridge_benchmark) or `python test_agent_loop.py`.
"""
from __future__ import annotations

import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
_root = Path(__file__).resolve().parents[1]
for p in ("generators", "models", "cert", "experiments", "agents"):
    sys.path.insert(0, str(_root / p))

from oracle import category, safe  # noqa: E402
from baselines import train_certified_gate  # noqa: E402
from llm_client import MockLLMClient, parse_action  # noqa: E402
from tool_env import ToolEnvironment, DOMAIN_SPEC  # noqa: E402
from agent_loop import (Gate, CertifiedGate, OracleGate, realize_c_witness, run_agent_episode, DOMAIN)  # noqa: E402

_ENV = None
_MODEL = None


def _env_model():
    global _ENV, _MODEL
    if _ENV is None:
        _ENV = ToolEnvironment("financial_compliance", n_pool=4000, eps=0.10, seed=0)
        _MODEL = train_certified_gate(_ENV.records[:8000], _ENV.rt, sigma=0.10, n_aug=4, seed=0)
    return _ENV, _MODEL


def test_agent_loop_runs_with_mock_no_gate():
    env, _ = _env_model()
    rec = env.by_category("R")[0]
    obs = env.call_tool(rec)
    log = run_agent_episode(rec, obs, MockLLMClient(), Gate(), env.rt, "financial_compliance", env)
    assert log["gate"] == "none" and "executed_action" in log


def test_certified_gate_blocks_C_witness():
    env, model = _env_model()
    gate = CertifiedGate(model, env.rt, n_mc=800)
    blocked = 0
    cs = env.by_category("C")[:25]
    for rec in cs:
        obs = realize_c_witness(env.rt, env.call_tool(rec), env.eps)
        if obs is None:
            continue
        # the realized witness is oracle-unsafe; certified gate must refuse the privileged action
        allow, _ = gate.evaluate(obs, env.action)
        if not allow:
            blocked += 1
    assert blocked >= 1 and blocked == len([c for c in cs if realize_c_witness(env.rt, env.call_tool(c), env.eps)])


def test_certified_gate_allows_some_R():
    env, model = _env_model()
    gate = CertifiedGate(model, env.rt, n_mc=800)
    allows = 0
    for rec in env.by_category("R")[:40]:
        obs = env.call_tool(rec)
        allow, _ = gate.evaluate(obs, env.action)
        allows += int(allow)
    assert allows >= 1, "certified gate must allow at least one robust-interior R point"


def test_oracle_gate_blocks_U():
    env, _ = _env_model()
    gate = OracleGate(env.rt)
    for rec in env.by_category("U")[:20]:
        obs = env.call_tool(rec)
        allow, _ = gate.evaluate(obs, env.action)
        assert not allow, "oracle gate must block clean-unsafe U points"


def test_invalid_action_coerced_to_fallback():
    allowed = ["approve_transaction", "reject_transaction", "manual_review", "escalate_compliance"]
    a, rat = parse_action('{"candidate_action": "delete_everything"}', allowed, "manual_review")
    assert a == "manual_review" and "invalid_action_coerced" in rat


def test_episode_log_has_required_fields():
    env, model = _env_model()
    rec = env.by_category("C")[0]
    obs = env.call_tool(rec)
    log = run_agent_episode(rec, obs, MockLLMClient(), CertifiedGate(model, env.rt, n_mc=400),
                            env.rt, "financial_compliance", env)
    for k in ("task_id", "domain", "category", "gate", "candidate_action", "executed_action",
              "unsafe_execution", "abstained", "oracle_priv_safe", "task_success"):
        assert k in log, f"missing field {k}"


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    fail = 0
    for f in fns:
        try:
            f(); print(f"[PASS] {f.__name__}")
        except AssertionError as e:
            fail += 1; print(f"[FAIL] {f.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            fail += 1; print(f"[ERROR] {f.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns)-fail}/{len(fns)} passed")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(_run())
