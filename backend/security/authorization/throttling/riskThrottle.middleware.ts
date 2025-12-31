// RIVER WEBSITE/backend/authorization/throttling/riskThrottle.middleware.ts

/**
 * RISK-BASED THROTTLING (ADAPTIVE CONTROL)
 * 
 * Attach after CAE -> app.use(riskThrottle);
 */

import { enforceRateLimit } from "./rateLimit.service.ts";

const LIMITS = {
    LOW: 1000,          // LOW → normal traffic
    MEDIUM: 200,        // MEDIUM → reduced throughput 
    HIGH: 20,           // HIGH → near-lockdown
  };
  
  export async function riskThrottle(request, reply) {
    const { riskLevel } = request.session;
  
    if (riskLevel === "CRITICAL") {
      return reply.status(403).json({ message: "Session terminated" });
    }
  
    const limit = LIMITS[riskLevel] ?? 10;
  
    await enforceRateLimit(request.session.id, limit);
    
  }
  