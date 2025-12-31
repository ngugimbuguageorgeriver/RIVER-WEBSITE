// RIVER WEBSITE/backend/authorization/audit/middleware/authz-audit.middleware.ts

/**
 * Purpose
        * Capture decision after OPA evaluation
        * Bind decision → policy → context
        * Enforce traceability
 */


/**
 * Authorization Audit Middleware
 *
 * Must run AFTER policy evaluation.
 */

import { AuthzAuditService } from "../../audit/authz-audit.service.ts";
import { randomUUID } from "crypto";

export async function authzAuditMiddleware(req, decision, policyMeta) {
  await AuthzAuditService.record({
    id: randomUUID(),
    subjectId: req.user.id,
    sessionId: req.session.id,

    action: req.authz.action,
    resource: req.authz.resource,

    decision,

    policyPackage: policyMeta.package,
    policyRule: policyMeta.rule,

    roles: req.user.roles,
    entitlements: req.entitlements.map(
      (e) => `${e.resource}:${e.scopes.join(",")}`
    ),

    riskLevel: req.risk?.riskLevel ?? "UNKNOWN",
    mfaVerified: req.user.mfaVerified,

    ipAddress: req.ip,
    userAgent: req.headers["user-agent"],

    evaluatedAt: new Date(),
  });
}
