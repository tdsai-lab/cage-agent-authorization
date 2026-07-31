# AUTHORED batch aggregation glue (NOT a policy). Evaluates the UNMODIFIED vendored Gatekeeper packages
# for a whole array of cases in ONE `opa eval`, using `with input as case` to rebind the global input
# per case. Contains no authorization logic of its own. Rego v0 (matches the vendored templates).
package track_a_batch

viol_total(case) = n {
	a := count(data.k8sallowedrepos.violation) with input as case
	b := count(data.k8srequiredlabels.violation) with input as case
	c := count(data.k8scontainerlimits.violation) with input as case
	d := count(data.k8spsphostnetworkingports.violation) with input as case
	e := count(data.k8spspprivileged.violation) with input as case
	n := a + b + c + d + e
}

# results[i] = true iff case i is SAFE under the whole policy set (zero violations)
results[i] = s {
	case := input.cases[i]
	s := viol_total(case) == 0
}
