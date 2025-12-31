// RIVER WEBSITE/backend/authorization/audit/authz-audit.model.ts

/**
 * Auditing & Monitoring - This layer makes every authorization decision explainable, immutable, and compliant.
                                                 Nothing here influences decisions; it records, correlates, and proves them.

 *Purpose
        Canonical, immutable authorization decision record
        Designed for forensics, compliance, and SIEM ingestion
        Append-only by design 
 */

/**
 * Authorization Audit Model
 *
 * Every authorization decision MUST generate one record.
 * This model is append-only and immutable.
 */

export type AuthzDecision = "ALLOW" | "DENY" | "CHALLENGE";

export interface AuthzAuditRecord {
  id: string;

  /** Who */
  subjectId: string;
  sessionId: string;

  /** What */
  action: string;
  resource: string;

  /** Decision */
  decision: AuthzDecision;

  /** Why (OPA explanation reference) */
  policyPackage: string;
  policyRule: string;

  /** Context */
  roles: string[];
  entitlements: string[];
  riskLevel: string;
  mfaVerified: boolean;

  /** Metadata */
  ipAddress: string;
  userAgent: string;

  /** Timing */
  evaluatedAt: Date;
}
