# Calibration NEGATIVE control for the idiom detector (PLAN_2 P1 Task A). The threshold is a CONSTANT
# scalar, not selected by any discrete/provenance key, so a provenance swap cannot reposition the
# boundary -> no Category-C joint-gap idiom. The detector must be SILENT on this policy.
package opa_gate.constant_control

threshold := 0.5

safe(c) := true if {
	c.action != "approve_transaction"
}

safe(c) := (c.x2.risk_score < threshold) if {
	c.action == "approve_transaction"
}

decisions := {i: safe(c) | some i, c in input.cases}
