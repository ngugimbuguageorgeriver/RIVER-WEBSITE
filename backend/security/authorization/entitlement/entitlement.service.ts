// RIVER WEBSITE/backend/authorization/entitlement/entitlement.service.ts

/** 
 * Entitlement Service -> It creates, revokes, and packages entitlements — but it never decides access.
 * 
 * Purpose
        * Persist and manage entitlement lifecycle
        * Enforce revocation semantics
        * Emit audit events
        * Provide OPA-ready inputs
        * Invalidate sessions when entitlements change (least privilege)
 *
 * Authoritative lifecycle manager for entitlements.
 * This service NEVER decides authorization outcomes.
 * It prepares facts for the policy engine (OPA).
 */

import { Entitlement, createEntitlement, isEntitlementActive } from "./entitlement.model.ts";
import { prisma } from "../../infra/prisma";   // NOT EXISTENT
import { audit } from "../audit/audit.service";  // NOT EXISTENT
import { revokeSessionsForSubject } from "../sessions/session.revocation"; // NOT EXISTENT

export class EntitlementService {
  /**
   * Grant a new entitlement.
   * This is an explicit administrative action and must be audited.
   */
  static async grant(params: Parameters<typeof createEntitlement>[0]) {
    const entitlement = createEntitlement(params);

    await prisma.entitlement.create({
      data: {
        ...entitlement,
        scopes: JSON.stringify(entitlement.scopes),
      },
    });

    await audit.log({
      action: "ENTITLEMENT_GRANTED",
      actorId: params.grantedBy,
      targetId: entitlement.id,
      metadata: {
        subjectType: params.subjectType,
        subjectId: params.subjectId,
        scopes: params.scopes,
        resource: `${params.resourceType}:${params.resourceId}`,
      },
    });

    return entitlement;
  }

  /**
   * Revoke an entitlement immediately.
   * Used for consent withdrawal, security incidents, or offboarding.
   */
  static async revoke(entitlementId: string, revokedBy: string, reason: string) {
    const now = new Date();

    const entitlement = await prisma.entitlement.update({
      where: { id: entitlementId },
      data: {
        status: "REVOKED",
        revokedAt: now,
        updatedAt: now,
      },
    });

    /**
     * Force re-authorization:
     * Any active sessions tied to this subject must be invalidated.
     */
    await revokeSessionsForSubject(entitlement.subjectId);

    await audit.log({
      action: "ENTITLEMENT_REVOKED",
      actorId: revokedBy,
      targetId: entitlementId,
      metadata: { reason },
    });

    return entitlement;
  }

  /**
   * Fetch all active entitlements for a subject.
   * This output feeds directly into OPA input.
   */
  static async getActiveForSubject(subjectId: string): Promise<Entitlement[]> {
    const records = await prisma.entitlement.findMany({
      where: {
        subjectId,
        status: "ACTIVE",
      },
    });

    return records
      .map((r) => ({
        ...r,
        scopes: JSON.parse(r.scopes),
      }))
      .filter(isEntitlementActive);
  }

  /**
   * Convert entitlements into a compact OPA-friendly shape.
   * This avoids policy engines querying databases.
   */
  static async buildPolicyInput(subjectId: string) {
    const entitlements = await this.getActiveForSubject(subjectId);

    return entitlements.map((e) => ({
      resource: `${e.resourceType}:${e.resourceId}`,
      scopes: e.scopes,
      validUntil: e.validUntil,
    }));
  }
}
