// RIVER WEBSITE/backend/authorization/middleware/authorization.middleware.ts

/**
 * 
 *
 * Single middleware that enforces RBAC, ABAC, PBAC.
 * - Verifies the user is authenticated (assumes earlier auth middleware)
 * - Computes role-based permissions as a quick path
 * - Delegates to OPA for complex policy evaluation (PBAC/ABAC)
 * - Logs decisions to audit logger
 * 
 * This middleware uses a fast RBAC check first (low latency) and falls back to OPA for complex context-based decisions.
 * request.user must include roles, id, and contextual attributes (deviceTrustScore, department, mfa, etc.). Populate these in the auth middleware.
 * Audit logs include mechanism and details for later forensics.
 * 
 */

import { FastifyReply, FastifyRequest } from "fastify";
import { computeEffectivePermissions } from "../roles/auth.roles.ts";
import { evaluatePolicy, makePolicyInput } from "../policy/policy.service.ts";
import { auditLog } from "./audit.logger";

/**
 * Quick RBAC permission check.
 * If allowed by RBAC, grant immediately (fast path).
 */
function checkRBAC(user: any, action: string): boolean {
  if (!user || !user.roles) return false;
  for (const r of user.roles) {
    const perms = computeEffectivePermissions(r);
    if (perms.includes(action as any)) return true;
  }
  return false;
}

/**
 * Middleware generator to enforce an action (string).
 * Example: preHandler: enforce("APPROVE_PAYMENTS")
 */
export function enforce(action: string) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;

    // If not authenticated, deny
    if (!user) {
      await auditLog({ user: null, action, resource: null, decision: "DENY", reason: "Unauthenticated", request });
      return reply.code(401).send({ error: "Unauthenticated" });
    }

    // Fast path: RBAC static permissions
    if (checkRBAC(user, action)) {
      await auditLog({ user: user.id, action, resource: request.url, decision: "ALLOW", mechanism: "RBAC" , request});
      return;
    }

    // Compose ABAC/PBAC input for OPA
    const resource = (request as any).resource || { type: request.routerPath || request.url, owner: null };
    const env = {
      ip: request.ip,
      geo: request.headers["x-geo"] || null,
      time: new Date().toISOString(),
      device_trust_score: user.deviceTrustScore || 0,
    };

    const input = makePolicyInput({ user, resource, action, env });

    // Evaluate via OPA
    const result = await evaluatePolicy(input);

    if (result.allow) {
      await auditLog({ user: user.id, action, resource, decision: "ALLOW", mechanism: "PBAC/OPA", details: result.details, request });
      return;
    }

    // Deny by default; log details for investigation
    await auditLog({ user: user.id, action, resource, decision: "DENY", reason: "Policy evaluation failed", details: result.details, request });
    return reply.code(403).send({ error: "Forbidden" });
  };
}
