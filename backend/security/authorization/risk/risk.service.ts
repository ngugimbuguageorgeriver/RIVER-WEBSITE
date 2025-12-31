// RIVER WEBSITE/backend/authorization/risk/risk.service.ts

/**
 * Purpose
        * Persist session risk
        * Trigger adaptive enforcement
        * Feed OPA inputs
        * Invalidate or step-up sessions
 */


/**
 * Risk Service
 *
 * Binds risk evaluation to enforcement actions.
 * THIS is where Zero Trust becomes real.
 */

import { RiskEngine } from "./risk.engine.ts";
import { revokeSession } from "../sessions/session.revocation.ts";
import { audit } from "../audit/audit.service";

export class RiskService {
  static async assessSession(params: {
    sessionId: string;
    subjectId: string;
    signals: any[];
  }) {
    const profile = RiskEngine.evaluate(params);

    /**
     * Persist risk snapshot (AUDIT ONLY, optional)
     */

    /**
     * Adaptive enforcement
     */
    if (profile.riskLevel === "CRITICAL") {
      await revokeSession(profile.sessionId);

      await audit.log({
        action: "SESSION_TERMINATED_HIGH_RISK",
        actorId: profile.subjectId,
        metadata: {
          riskScore: profile.riskScore,
          signals: profile.signals,
        },
      });
    }

    return profile;
  }
}
