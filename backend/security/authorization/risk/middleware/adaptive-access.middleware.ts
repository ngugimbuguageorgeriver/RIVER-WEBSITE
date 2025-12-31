// RIVER WEBSITE/backend/authorization/risk/middleware/adaptive-access.middleware.ts

/**
 * Purpose
        * Enforce risk decisions on every request
        * Mid-session revocation
        * Step-up MFA triggers
        * OPA-compatible input injection
 */


/**
 * Adaptive Access Middleware
 *
 * Runs AFTER authentication but BEFORE authorization.
 * Evaluates live risk and injects it into policy input.
 */

import { RiskService } from "../../risk/risk.service.ts";

export async function adaptiveAccess(req, reply) {
  const signals = [];

  if (req.ip !== req.session.ip) {
    signals.push({
      type: "IP_ANOMALY",
      severity: 7,
      evidence: `IP changed from ${req.session.ip} to ${req.ip}`,
    });
  }

  if (req.headers["user-agent"] !== req.session.userAgent) {
    signals.push({
      type: "DEVICE_MISMATCH",
      severity: 6,
      evidence: "User-Agent mismatch",
    });
  }

  const risk = await RiskService.assessSession({
    sessionId: req.session.id,
    subjectId: req.user.id,
    signals,
  });

  /**
   * Attach risk to request context for OPA
   */
  req.risk = risk;

  if (risk.riskLevel === "HIGH") {
    reply.header("X-Auth-Challenge", "MFA_REQUIRED");
  }
}
