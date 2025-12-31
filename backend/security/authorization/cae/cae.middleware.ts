// RIVER WEBSITE/backend/authorization/cae/cae.middleware.ts

/**
 * CAE - ContinuousAccessEvaluation - THIS RUNS ON EVERY REQUEST.
 * app.use(requireSession, continuousAccessEvaluation);
 */


import { RiskService } from "../risk/risk.service.ts";
import { SessionService } from "../../authentication/session/session.service.ts";
import { collectRiskSignals } from "../risk/risk.signals.ts";

export async function continuousAccessEvaluation(request, reply) {
  const session = request.session;

  // Collect signals per request
  const signals = collectRiskSignals(request, session);

  const profile = await RiskService.assessSession({
    sessionId: session.id,
    subjectId: session.subjectId,
    signals,
  });

  // Persist risk into Redis
  await SessionService.updateRisk({
    sessionId: session.id,
    riskLevel: profile.riskLevel,
    lastEvaluatedAt: Date.now(),
  });

  // Mutate Request Context
  request.risk = profile;
  request.session.riskLevel = profile.riskLevel;
  

  if (profile.riskLevel === "CRITICAL") {
    await SessionService.revoke(session.id);
    return reply.code(403).send({ message: "Session terminated" });
  }
}
