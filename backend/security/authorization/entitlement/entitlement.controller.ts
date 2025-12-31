// RIVER WEBSITE/backend/authorization/entitlement/entitlement.controller.ts

/**
 * Entitlement Controller -> Exposes HTTP endpoints, Accepts requests, Calls services, Returns responses(❌ It does NOT contain business logic)
 * 
 * This controller is for administrators to: Grant entitlements, Revoke entitlements.
 * 
 * Purpose
        * Secure API for granting/revoking entitlements
        * PAM-aware (admin-only, MFA-enforced)
        * Clean separation between transport and policy
 *
 * Administrative interface for consent and entitlement management.
 * All routes MUST be protected by:
 * - Authentication
 * - MFA
 * - RBAC / PAM approval
 */

import { FastifyInstance } from "fastify";
import { EntitlementService } from "./entitlement.service";


// Below is a function that registers routes on the Fastify app -> Called once during app startup -> Think of it as: “When the server starts, add these entitlement endpoints.”

export async function entitlementController(app: FastifyInstance) { 
  /**
   * Grant entitlement
   */
  app.post("/admin/entitlements/grant", {
    preHandler: [          // ➡️ If any of these fail → request is rejected

      app.authenticate,                     // ✔ Ensures the user is logged in & Attaches req.user
      app.requireMFA,                       // ✔ Ensures MFA was completed & Prevents token theft attacks
      app.authorize("ENTITLEMENT_GRANT"),   // ✔ Checks RBAC / PAM & Only users with this permission can grant entitlements
    ],

    handler: async (req, reply) => {
      const entitlement = await EntitlementService.grant({   // Pass request data to the service layer.
        subjectType: req.body.subjectType,
        subjectId: req.body.subjectId,
        resourceType: req.body.resourceType,
        resourceId: req.body.resourceId,
        scopes: req.body.scopes,
        grantedBy: req.user.id,
        grantReason: req.body.reason,
        validUntil: req.body.validUntil,
      });

      return reply.code(201).send(entitlement);         // HTTP 201 Created & Returns the created entitlement record
    },
  });

  /**
   * Revoke entitlement
   */
  app.post("/admin/entitlements/:id/revoke", {
    preHandler: [
      app.authenticate,
      app.requireMFA,
      app.authorize("ENTITLEMENT_REVOKE"),
    ],
    handler: async (req, reply) => {              // ➡️ This is where logout / access kill happens.
      await EntitlementService.revoke(
        req.params.id,
        req.user.id,
        req.body.reason
      );

      return reply.code(204).send();             // HTTP 204 No Content, No body, Indicates success
    },
  });
}
