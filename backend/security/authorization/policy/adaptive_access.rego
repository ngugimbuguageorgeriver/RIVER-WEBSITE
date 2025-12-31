package authz.adaptive

default allow = false

allow {
  input.risk.riskLevel == "LOW"
}

allow {
  input.risk.riskLevel == "MEDIUM"
  input.subject.mfa_verified == true
}

deny {
  input.risk.riskLevel == "HIGH"
}

deny {
  input.risk.riskLevel == "CRITICAL"
}
