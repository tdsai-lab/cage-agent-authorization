# Authored policy-as-code oracle (NOT third-party). suppress_alert is safe iff the typed signal is
# below a threshold that depends on the monitoring tool AND the service tier (production is stricter).
package opa_gate.sre

base := {"t_latency": 0.62, "t_errbudget": 0.58, "t_saturation": 0.60}

# service tier adjustment: production uses a STRICTER (lower) suppression threshold
adj := {"tier3": 0.04, "tier2": 0.0, "tier1": -0.05, "prod": -0.10}

threshold(tool, x1) := base[tool] + adj[x1.service_tier]

safe(c) := true if {
	c.action != "suppress_alert"
}

safe(c) := (c.x2.signal < threshold(c.tool, c.x1)) if {
	c.action == "suppress_alert"
}

decisions[i] := safe(c) if {
	some i, c in input.cases
}
