// RIVER WEBSITE/backend/authorization/risk/risk.model.ts

// This layer ensures that authorization is not static;
//               Access can be downgraded, challenged, or revoked mid-session based on real-time risk signals.

/**
 * Purpose
        * Canonical risk representation
        * Deterministic, explainable scoring
        * Policy-consumable (OPA-friendly)
        * SIEM-compatible
 */

/**
 * Risk Model -> Continuous Access Evaluation & Adaptive Access
 *
 * Represents continuously evaluated session risk.
 * Risk is NEVER binary; it is scored, categorized, and explainable.
 */

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface RiskSignal {
  type:
    | "IP_ANOMALY"
    | "GEO_ANOMALY"
    | "DEVICE_MISMATCH"
    | "IMPOSSIBLE_TRAVEL"
    | "BEHAVIOR_ANOMALY"
    | "THREAT_INTEL"
    | "SESSION_REUSE";

  severity: number; // 1–10
  evidence: string;
}

export interface SessionRiskProfile {
  sessionId: string;
  subjectId: string;

  riskScore: number; // 0–100
  riskLevel: RiskLevel;

  signals: RiskSignal[];

  evaluatedAt: Date;
}
