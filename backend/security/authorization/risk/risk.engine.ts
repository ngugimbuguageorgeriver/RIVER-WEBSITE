// RIVER WEBSITE/backend/authorization/risk/risk.engine.ts

/**
 * Purpose
        * Central risk scoring engine
        * Deterministic (no ML black boxes)
        * Auditable and explainable
        * Inputs from device, session, SIEM, network
 */


/**
 * Risk Engine
 *
 * Aggregates multiple signals into a normalized risk score.
 * Designed for:
 * - Explainability
 * - Deterministic enforcement
 * - Policy-driven responses
 */

import { RiskSignal, SessionRiskProfile, RiskLevel } from "./risk.model.ts";

function classify(score: number): RiskLevel {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 30) return "MEDIUM";
  return "LOW";
}

export class RiskEngine {
  static evaluate(params: {
    sessionId: string;
    subjectId: string;
    signals: RiskSignal[];
  }): SessionRiskProfile {
    const score = params.signals.reduce(
      (sum, s) => sum + s.severity * 5,
      0
    );

    const normalized = Math.min(score, 100);

    return {
      sessionId: params.sessionId,
      subjectId: params.subjectId,
      riskScore: normalized,
      riskLevel: classify(normalized),
      signals: params.signals,
      evaluatedAt: new Date(),
    };
  }
}
