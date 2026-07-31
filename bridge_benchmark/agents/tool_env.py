#!/usr/bin/env python3
"""
tool_env.py — deterministic tool environment for the LLM-agent experiment.

No live external API. A "tool call" returns a pre-generated, oracle-labelled benchmark record (the
typed tool return z). Records come from the realistic finance / monitoring schemas. Each domain has a
privileged action (the one the certified gate guards) and a safe fallback action.
"""
from __future__ import annotations

import sys
from pathlib import Path

_root = Path(__file__).resolve().parents[1]
for p in ("generators", "experiments"):
    sys.path.insert(0, str(_root / p))

from synthetic_tools import sample_records, DOMAIN  # noqa: E402
from realistic_schemas import finance_schema, monitoring_schema, ops_security_schema  # noqa: E402

# privileged action (gated) and safe fallback per domain
DOMAIN_SPEC = {
    "financial_compliance": {"privileged": "approve_transaction", "fallback": "manual_review",
                             "other_safe": ["reject_transaction", "escalate_compliance"]},
    "sre_monitoring": {"privileged": "suppress_alert", "fallback": "page_on_call",
                       "other_safe": ["create_ticket", "escalate_incident"]},
    # ops/deployment-security domain (EXP-HARNESS third domain). Privileged action `allow_login`
    # (the schema's gated action); safe fallback `require_mfa_step_up`. Backward-compatible: existing
    # callers (end_to_end_exploit / agent_loop) only iterate the first two domains.
    "ops_security": {"privileged": "allow_login", "fallback": "require_mfa_step_up",
                     "other_safe": ["deny_login", "escalate_secops"]},
}


class ToolEnvironment:
    def __init__(self, domain: str, n_pool: int = 6000, eps: float = 0.10, seed: int = 0):
        if domain == "financial_compliance":
            _, self.rt = finance_schema()
        elif domain == "sre_monitoring":
            _, self.rt = monitoring_schema()
        elif domain == "ops_security":
            _, self.rt = ops_security_schema()
        else:
            raise ValueError(f"unknown domain {domain}")
        self.domain = domain
        self.eps = eps
        self.dc = self.rt["domains"][DOMAIN]
        self.action = self.dc["candidate_actions"][0]            # the single privileged action
        self.action_field = self.dc["_action_field"][self.action]
        self.records = sample_records(self.rt, n_pool, eps=eps, seed=seed)

    def by_category(self, cat: str):
        return [r for r in self.records if r["category"] == cat]

    def call_tool(self, record: dict) -> dict:
        """Return the typed tool return z for an episode (here: the record's clean return)."""
        return {"tool_id": record["tool_id"], "candidate_action": self.action,
                "categorical_fields": dict(record["categorical_fields"]),
                "numeric_fields": dict(record["numeric_fields"]), "domain": DOMAIN}

    def primary_signal(self, observed: dict) -> float:
        return float(observed["numeric_fields"].get(self.action_field, 0.0))
