# PLAN #9b — executable continuous policy-as-code for the REAL IEEE-CIS fraud setting, evaluated by the
# OPA engine (not our analytic oracle). The privileged action approve_transaction is safe iff the REAL
# held-out risk_score is below a threshold that depends on the reporting PROVENANCE (loose tools trust
# the surfaced state more -> a higher threshold theta+delta; strict tools use theta). This is the
# continuous-conditioned-on-discrete idiom  risk_score < theta(provenance)  that makes joint
# discrete+continuous (Category-C) witnesses possible. Thresholds are the real generation constants of
# the IEEE-CIS boundary-balanced set (theta_base=0.488808, delta=0.08), so OPA reproduces the same
# policy the data was built against -- but as EXECUTABLE Rego, engine-labeled.
package opa_gate.ieee_fraud

theta_base := 0.488808
delta := 0.08

loose := {"payment_gateway_loose", "manual_screen_loose"}

threshold(tool) := theta_base + delta if loose[tool]

threshold(tool) := theta_base if not loose[tool]

# non-privileged actions are conservative fallbacks: always policy-safe
safe(c) := true if {
	c.action != "approve_transaction"
}

# privileged: safe iff the real risk_score is under the provenance-conditioned threshold
safe(c) := (c.x2.risk_score < threshold(c.tool)) if {
	c.action == "approve_transaction"
}

# batched decisions: one boolean per input case, keyed by its array index. An object COMPREHENSION
# (evaluated once over the iteration) keeps this O(n); a partial rule `decisions[i] := ... if some i,c`
# is O(n^2) because OPA re-scans input.cases per output key (bites at 10^4 varied probe points).
decisions := {i: safe(c) | some i, c in input.cases}
