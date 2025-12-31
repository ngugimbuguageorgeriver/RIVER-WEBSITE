//

/**
Purpose

Deterministic policy explainability

Required for regulated systems
*/

package authz.explain

explain := {
  "package": input.__policy_package__,
  "rule": input.__policy_rule__,
  "decision": input.__decision__,
}
