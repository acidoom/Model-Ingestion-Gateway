# MIG reference promotion policy (OPA / Rego v1).
#
# Mirrors the stdlib EmbeddedPromotionGate. Because promotion uses DENY-OVERRIDES
# (allow = embedded.allow AND opa.allow), this policy can only ever further
# restrict — a too-permissive edit here is masked by the embedded floor and can
# never loosen what gets promoted. Default-deny.
#
# Evaluate with:
#   opa eval --format json --stdin-input --data policies/promotion.rego \
#     'data.mig.promotion.decision'
#
# Output contract: decision == {"allow": bool, "reasons": [string]}.

package mig.promotion

import rego.v1

# --- denial reasons (each independent; any one denies) ---------------------- #

deny contains msg if {
	input.verification.ok != true
	msg := "attestation verification did not pass"
}

deny contains msg if {
	some check in ["signature", "digest_rebind", "attribution", "keyid"]
	input.verification.checks[check] != true
	msg := sprintf("verification check %q not satisfied", [check])
}

deny contains msg if {
	input.decision != "approve"
	msg := sprintf("signed decision is %q, not 'approve'", [input.decision])
}

# Fail closed: a missing/non-false is_executable_type is treated as executable
# (object.get defaults to true), so a mistyped flag never skips the rigor check.
deny contains msg if {
	object.get(input, "is_executable_type", true) != false
	input.overall_rigor != "behavioral"
	msg := "executable type needs behavioral rigor"
}

deny contains msg if {
	object.get(input, "is_executable_type", true) != false
	not input.confinement_level in {"docker", "gvisor"}
	msg := "executable type needs docker/gvisor confinement"
}

deny contains msg if {
	not input.policy.id
	msg := "attestation carries no policy id"
}

# --- the decision the gate reads ------------------------------------------- #

decision := {
	"allow": count(deny) == 0,
	"reasons": sort([m | some m in deny]),
}
