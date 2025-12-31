//

/**
Purpose

        Enforce OAuth-style scopes

        Combine RBAC + ABAC + explicit consent

        Stateless, auditable decisions
*/


package authz.entitlements

default allow = false

allow {
  input.subject.authenticated == true
  entitlement := input.entitlements[_]

  entitlement.resource == input.resource
  entitlement.scopes[_] == input.action

  not expired(entitlement)
}

expired(e) {
  e.validUntil != null
  time.now_ns() > time.parse_rfc3339_ns(e.validUntil)
}
