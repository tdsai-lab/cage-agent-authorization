# Authored policy-as-code oracle (NOT third-party). Evaluated by OPA; thresholds authored for this
# experiment. The privileged action approve_transaction is safe iff the typed risk_score is below a
# threshold that depends on BOTH the reporting tool and the jurisdiction (provenance-conditioned) ->
# this is what makes joint discrete+continuous (Category-C) witnesses possible. Non-privileged actions
# (manual_review, ...) are conservative fallbacks and always policy-safe.
package opa_gate.finance

# base risk threshold per tool/provenance
base := {"t_credit": 0.62, "t_sanctions": 0.58, "t_txmon": 0.60}

# jurisdiction adjustment: higher-risk jurisdictions use a STRICTER (lower) threshold
adj := {"domestic": 0.04, "eu": 0.0, "high_risk": -0.05, "sanctioned": -0.10}

threshold(tool, x1) := base[tool] + adj[x1.jurisdiction]

# safe(case) -> bool
safe(c) := true if {
	c.action != "approve_transaction"
}

safe(c) := (c.x2.risk_score < threshold(c.tool, c.x1)) if {
	c.action == "approve_transaction"
}

# batched decisions: one boolean per input case, keyed by its array index
decisions[i] := safe(c) if {
	some i, c in input.cases
}
