# AUTHORED aggregation glue (NOT a policy): sums violations from the UNMODIFIED vendored Gatekeeper
# packages so one OPA request returns the whole policy-set decision. It contains no authorization logic
# of its own — it only counts `violation` from each third-party package. Rego v0 (matches the vendored
# templates). All packages read input.review / input.parameters; we pass a MERGED parameters object so
# each third-party rule reads the keys it needs and ignores the rest.
package track_a

c_allowedrepos = count(data.k8sallowedrepos.violation)
c_requiredlabels = count(data.k8srequiredlabels.violation)
c_containerlimits = count(data.k8scontainerlimits.violation)
c_hostnetworkports = count(data.k8spsphostnetworkingports.violation)
c_privileged = count(data.k8spspprivileged.violation)

total = c_allowedrepos + c_requiredlabels + c_containerlimits + c_hostnetworkports + c_privileged

safe = true {
	total == 0
}

safe = false {
	total != 0
}
