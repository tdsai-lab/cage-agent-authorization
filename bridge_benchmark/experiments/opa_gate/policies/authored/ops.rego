# Authored policy-as-code oracle (NOT third-party). allow_login is safe iff the typed login_risk is
# below a threshold that depends on the auth tool AND the network provenance (tor_exit is strictest).
package opa_gate.ops

base := {"t_authn": 0.62, "t_geoip": 0.58, "t_device": 0.60}

adj := {"trusted": 0.04, "normal": 0.0, "new_device": -0.05, "tor_exit": -0.10}

threshold(tool, x1) := base[tool] + adj[x1.network]

safe(c) := true if {
	c.action != "allow_login"
}

safe(c) := (c.x2.login_risk < threshold(c.tool, c.x1)) if {
	c.action == "allow_login"
}

decisions[i] := safe(c) if {
	some i, c in input.cases
}
