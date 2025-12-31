# Save this as policy.rego and load into OPA (or compile to WASM for local evaluation). 

# demonstrates PBAC: central policies that evaluate attributes (user, resource, action, environment).

# (OPA policy example — PBAC / ABAC)

# data.role_permissions should be populated when loading OPA (can be exported from roles.enhanced mapping).

# This policy is intentionally simple to demonstrate combining RBAC / ABAC / PBAC. Real policies should handle errors, logging, and explicit deny rules.

package authz

# Input shape:
# {
#   "user": {"id": "...", "roles": ["..."], "attributes": {"department":"finance", "trust_score": 0.8}},
#   "resource": {"type": "payment", "owner": "user-id-123", "sensitivity": "high"},
#   "action": "approve",
#   "env": {"ip": "...", "geo": "KE", "time": "2025-12-11T12:00:00Z"}
# }

default allow = false

# Simple RBAC: if any role has static permission for action, allow
rbac_allow {
  some r
  r := input.user.roles[_]
  role_permissions := data.role_permissions[r]
  role_permissions[_] == input.action
}

# ABAC: user attributes + resource attributes + environment
abac_allow {
  input.action == "approve" 
  input.resource.type == "payment"
  input.user.attributes.department == "finance"
  input.user.attributes.trust_score >= 0.75
  input.env.geo == "KE"                  # example contextual attribute
  input.resource.sensitivity == "high"
}

# PBAC example: privileged sessions only if time window and approval present
privileged_allow {
  input.action == "start_privileged_session"
  input.user.attributes.is_admin == true
  input.env.time >= "2025-01-01T00:00:00Z"
  input.user.attributes.mfa == true
}

# Combine rules: allow if any allow rule is true
allow {
  rbac_allow
} else = true {
  abac_allow
} else = true {
  privileged_allow
}
