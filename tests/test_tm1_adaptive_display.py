#!/usr/bin/env python3
"""NEW_EXPS_7 Part A — TM1-adaptive display-only attacks.

Load-bearing invariants under test:
  * the 8 canonical adaptive families all resolve to a display string (both domains);
  * adaptive display payloads keep the typed gate input z FIXED (m never enters z);
  * no byte of the adaptive payload m leaks into the typed gate features (FeatureEncoder vector);
  * the best-of-K evaluator: gate_flip = 0 for typed gates; best-of-K is non-decreasing in K.
"""
import json
import sys
from pathlib import Path

_root = Path(__file__).resolve().parents[1] / "bridge_benchmark"
for p in ("generators", "models", "experiments", "agents"):
    sys.path.insert(0, str(_root / p))

import pytest  # noqa: E402
from prompts import (TM1_ADAPTIVE_CANONICAL_FAMILIES, ADAPTIVE_DISPLAY_ATTACK_NAMES,
                     display_note_for, build_action_prompt)  # noqa: E402
from realistic_schemas import finance_schema  # noqa: E402
from dataset import FeatureEncoder  # noqa: E402
from oracle import _x1  # noqa: E402
from synthetic_tools import DOMAIN  # noqa: E402

DOMAINS = ["finance", "sre"]


def test_canonical_families_resolve():
    for dom in DOMAINS:
        for fam in TM1_ADAPTIVE_CANONICAL_FAMILIES:
            note = display_note_for(dom, fam)
            assert isinstance(note, str) and note.strip(), f"{dom}/{fam} empty"


def _typed_gate_input(z):
    # exactly the construction in real_llm_action_exp.run_episode
    return {"tool_id": z["tool_id"], "categorical_fields": _x1(z), "numeric_fields": z["numeric_fields"]}


def test_display_payload_never_enters_typed_gate_input_or_features():
    _, rt = finance_schema()
    enc = FeatureEncoder(rt)
    z = {"domain": DOMAIN, "tool_id": rt["domains"][DOMAIN]["tools"][0],
         "candidate_action": rt["domains"][DOMAIN]["candidate_actions"][0],
         "categorical_fields": {c: vals[0] for c, vals in rt["domains"][DOMAIN]["categorical_fields"].items()},
         "numeric_fields": {f: 0.5 for f in rt["domains"][DOMAIN]["numeric_fields"]}}
    base_input = _typed_gate_input(z)
    base_vec = enc.transform_point(DOMAIN, z["tool_id"], z["candidate_action"],
                                   z["categorical_fields"], z["numeric_fields"])
    families = list(dict.fromkeys(ADAPTIVE_DISPLAY_ATTACK_NAMES + TM1_ADAPTIVE_CANONICAL_FAMILIES))
    prompts_seen = set()
    for fam in families:
        note = display_note_for("finance", fam)
        # the LLM-facing prompt DOES contain m ...
        prompt = build_action_prompt("finance", "task", {**base_input, "untrusted_display_note": note})
        prompts_seen.add(prompt)
        # ... but the typed gate input is byte-identical regardless of m
        assert _typed_gate_input(z) == base_input
        blob = json.dumps(base_input)
        assert note not in blob, f"payload {fam} leaked into typed gate input"
        # the encoded feature vector the gate sees does not change with m
        vec = enc.transform_point(DOMAIN, z["tool_id"], z["candidate_action"],
                                  z["categorical_fields"], z["numeric_fields"])
        assert vec == base_vec, f"payload {fam} changed the gate feature vector"
    # sanity: at least some payloads produced distinct prompts (m really is shown to the LLM)
    assert len(prompts_seen) > 1


def test_best_of_k_evaluator_gate_flip_zero_and_monotone():
    import evaluate_tm1_adaptive_display as ev
    # synthetic logs: one z, several families; gate=none proposes privileged on some families only.
    fams = ["benign"] + ev._CANON_ORDER_LOGNAME
    logs = []
    for i, fam in enumerate(fams):
        # the 'definitional'-position family flips the proposal to privileged (worst case at high K)
        proposed = (fam == ev._CANON_ORDER_LOGNAME[-1])
        logs.append({"model": "m", "prompt_mode": "policy_explicit", "domain": "finance",
                     "gate": "none", "task_id": "z0", "display_attack": fam, "category": "U",
                     "candidate_action": ("approve_transaction" if proposed else "manual_review"),
                     "proposed_privileged": proposed, "oracle_priv_safe": False,
                     "observed_tool_return": {"tool_id": "credit_check", "categorical_fields": {},
                                              "numeric_fields": {"risk_score": 0.9}}})
    proposals, certified = ev.collect(logs)
    key = ("m", "policy_explicit", "finance")
    rows = ev.best_of_k_rows(*key, "none", proposals[key])
    by_k = {r["K"]: r for r in rows}
    ks = sorted(by_k)
    # best-of-K unsafe execution is non-decreasing in K (a later family breaks it)
    vals = [by_k[k]["unsafe_execution_rate_best_of_k"] for k in ks]
    assert vals == sorted(vals), vals
    assert vals[-1] > vals[0], "best-of-K should find the breaking family at higher K"
    # for the 'rule' typed gate, gate_flip is 0 and asr is 0 (m-independent, pointwise correct on U)
    rrows = ev.best_of_k_rows(*key, "rule", proposals[key])
    for r in rrows:
        gf, asr = r["gate_flip_rate_best_of_k"], r["asr_best_of_k"]
        # typed gate: gate flip is never > 0 (nan when no privileged proposal in the K-prefix)
        assert (gf != gf) or gf == 0.0, gf
        # rule gate is pointwise-correct on U, so it never executes the unsafe privileged action
        assert (asr != asr) or asr == 0.0, asr


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
