#!/usr/bin/env python3
"""
llm_client.py — generic LLM interface for the agent experiment.

The LLM is a validation layer, not the contribution. We ship:
  * MockLLMClient — deterministic, rule-based; a plausibly-naive agent that thresholds the displayed
    `primary_signal` and proposes the privileged action when it looks acceptable, otherwise a safe
    fallback. It is FOOLED by post-tool-return corruption (it trusts the displayed numbers / wrong
    signal after a provenance swap), which is exactly what the certified gate must catch.
  * OpenAICompatibleClient — thin stub for a real OpenAI-compatible server. Not invoked in the MVP
    (no external API per project policy); raises a clear error if used without configuration.
"""
from __future__ import annotations

import json
import os
import re


class LLMClient:
    def complete(self, prompt: str) -> str:  # returns a JSON string
        raise NotImplementedError


class MockLLMClient(LLMClient):
    """Rule-based naive agent. Parses `primary_signal` and the allowed actions from the prompt."""

    def __init__(self, naive_threshold: float = 0.6):
        self.naive_threshold = naive_threshold

    def complete(self, prompt: str) -> str:
        m = re.search(r"primary_signal:\s*([0-9.]+)", prompt)
        signal = float(m.group(1)) if m else 1.0
        m2 = re.search(r"Return exactly one action from:\s*([^\.]+)\.", prompt)
        actions = [a.strip() for a in m2.group(1).split(",")] if m2 else []
        privileged = actions[0] if actions else "approve_transaction"
        fallback = actions[2] if len(actions) > 2 else (actions[-1] if actions else "manual_review")
        if signal < self.naive_threshold:
            return json.dumps({"candidate_action": privileged,
                               "rationale": f"primary_signal {signal:.2f} below {self.naive_threshold}"})
        return json.dumps({"candidate_action": fallback,
                           "rationale": f"primary_signal {signal:.2f} not clearly safe"})


class OpenAICompatibleClient(LLMClient):
    """Thin client for an OpenAI-compatible chat endpoint. Requires OPENAI_BASE_URL + OPENAI_API_KEY
    and the `openai` package. Not used in the MVP run."""

    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.0):
        self.model, self.temperature = model, temperature
        self.base_url = os.environ.get("OPENAI_BASE_URL")
        self.api_key = os.environ.get("OPENAI_API_KEY")

    def complete(self, prompt: str) -> str:
        if not self.api_key:
            raise RuntimeError("OpenAICompatibleClient needs OPENAI_API_KEY (+ optional "
                               "OPENAI_BASE_URL). The MVP runs with --llm mock instead.")
        from openai import OpenAI  # lazy import
        client = OpenAI(base_url=self.base_url, api_key=self.api_key)
        resp = client.chat.completions.create(
            model=self.model, temperature=self.temperature,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"})
        return resp.choices[0].message.content


def get_llm(name: str) -> LLMClient:
    if name == "mock":
        return MockLLMClient()
    if name in ("openai", "openai-compatible"):
        return OpenAICompatibleClient()
    raise ValueError(f"unknown llm {name}")


def parse_action(resp: str, allowed: list[str], fallback: str) -> tuple[str, str]:
    """Extract (candidate_action, rationale); coerce invalid/unknown actions to the safe fallback."""
    try:
        obj = json.loads(resp)
        a = obj.get("candidate_action", "")
        rat = str(obj.get("rationale", ""))
    except (json.JSONDecodeError, TypeError):
        a, rat = "", "unparseable"
    if a not in allowed:
        return fallback, f"invalid_action_coerced({a})"
    return a, rat
