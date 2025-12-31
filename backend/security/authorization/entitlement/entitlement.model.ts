// RIVER WEBSITE/backend/authorization/entitlement/entitlement.model.ts

/**
 * 
 * Purpose
        * Represent who can access what, how, and until when
        * First-class revocation
        * Compatible with OAuth-style scopes
        * Designed for policy evaluation, auditability, and least privilege

 * Entitlement & Consent Model -> An entitlement is a written permission slip that says
                                      who can do what to which resource, for how long, and why.
 *
 * This file defines the core authorization entitlement primitives.(zero-trust)
 * Entitlements represent explicit, revocable permissions granted
 * to a subject (user, service, or external app) over a resource.
 *
 * This model is intentionally explicit and auditable.
 * NOTHING here is implicit or inferred.
 */

import { randomUUID } from "crypto";

/**
 * Supported subject types that can hold entitlements.
 * - USER: Human users
 * - SERVICE: Internal service accounts
 * - THIRD_PARTY: OAuth / external integrations
 */
export type EntitlementSubjectType =     // This defines who can hold permissions.
  | "USER"                               // A human being
  | "SERVICE"
  | "THIRD_PARTY";

/**
 * OAuth-style scopes.
 * Examples:
 * - read:*
 * - write:payments
 * - admin:users
 *
 * Scopes are evaluated by policy (OPA),
 * not hardcoded business logic.
 */
export type EntitlementScope = string;             // Scopes represent allowed actions.

/**
 * Entitlement lifecycle states.
 * - ACTIVE: Enforced by policy engine
 * - REVOKED: Explicitly invalidated
 * - EXPIRED: Time-based expiration
 * - SUSPENDED: Temporarily disabled (risk-based, admin action)
 */
export type EntitlementStatus =                    // This defines state transitions, not deletion.
  | "ACTIVE"
  | "REVOKED"
  | "EXPIRED"
  | "SUSPENDED";

/**
 * Canonical entitlement record.
 *
 * This object MUST be immutable once persisted,
 * except for status transitions.
 */
export interface Entitlement {                  // This is the canonical permission record. Everything below defines what must exist for an entitlement to be valid.

  id: string;            // Unique identifierf of the Entitlement for auditing and references.

  /** Who holds this entitlement */
  subjectType: EntitlementSubjectType;
  subjectId: string;

  /** What resource is being accessed */
  resourceType: string;
  resourceId: string;

  /** Allowed scopes/ actions for this resource */
  scopes: EntitlementScope[];

  /** Lifecycle control */
  status: EntitlementStatus;

  /** Time-bound enforcement */
  validFrom: Date;
  validUntil?: Date;

  /** Justification & traceability -> compliance-grade traceability. */
  grantedBy: string; // admin or system actor
  grantReason: string;

  /** Audit metadata */
  createdAt: Date;
  updatedAt: Date;
  revokedAt?: Date;
}

/**
 * Factory function for creating new entitlements.
 * Enforces secure defaults.
 */
export function createEntitlement(params: {
  subjectType: EntitlementSubjectType;
  subjectId: string;
  resourceType: string;
  resourceId: string;
  scopes: EntitlementScope[];
  grantedBy: string;
  grantReason: string;
  validUntil?: Date;
}): Entitlement {
  const now = new Date();       // Single timestamp ensures consistency.

  return {
    id: randomUUID(),
    subjectType: params.subjectType,
    subjectId: params.subjectId,
    resourceType: params.resourceType,
    resourceId: params.resourceId,
    scopes: params.scopes,

    status: "ACTIVE",

    validFrom: now,
    validUntil: params.validUntil,

    grantedBy: params.grantedBy,
    grantReason: params.grantReason,

    createdAt: now,
    updatedAt: now,
  };
}

/**
 * Helper to determine if an entitlement is currently enforceable.
 * This is defensive logic only.
 * Final decision MUST be made by the policy engine.
 */
export function isEntitlementActive(entitlement: Entitlement): boolean {
  if (entitlement.status !== "ACTIVE") return false;

  const now = Date.now();

  if (entitlement.validFrom.getTime() > now) return false;              
  if (entitlement.validUntil && entitlement.validUntil.getTime() < now)
    return false;

  return true;
}
