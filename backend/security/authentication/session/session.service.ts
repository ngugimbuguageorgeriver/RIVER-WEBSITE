// RIVER WEBSITE/backend/authentication/session/session.service.ts


/**
 * Redis decides if that session is alive
 * JWT will carry only sessionId
 * 🔥 This is your kill-switch layer
 * INDEX SESSIONS ON CREATE - Why this matters;
                                        * Every session is now discoverable in O(1)
                                        * No scans, no parsing JSON, no loops
 */



import { randomUUID } from "crypto";
import Redis from "ioredis";
import { audit } from "../../authorization/audit/audit.service";
import { RiskLevel } from "../../authorization/risk/risk.model";

const redis = new Redis(process.env.REDIS_URL!);

const SESSION_TTL_SECONDS = 60 * 60 * 8; // 8 hours sliding

export interface Session {
  id: string;
  subjectId: string;
  deviceId?: string;
  tenantId:  string;
  createdAt: number;
  expiresAt: number;
  revokedAt?: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  mfaVerified: boolean;
  lastEvaluatedAt: number;
}

export class SessionService {
  static async create(params: {
    subjectId: string;
    deviceId?: string;
    mfaVerified: boolean;
  }): Promise<Session> {
    const now = Date.now();

    const session: Session = {
      id: randomUUID(),
      subjectId: params.subjectId,
      deviceId: params.deviceId,
      createdAt: now,
      expiresAt: now + SESSION_TTL_SECONDS * 1000,
      riskLevel: "LOW",
      mfaVerified: params.mfaVerified,
      lastEvaluatedAt: now,
    };
     
    // 1️⃣ Store session
    await redis.set(
      `session:${session.id}`,
      JSON.stringify(session),
      "EX",
      SESSION_TTL_SECONDS
    );

    // 2️⃣ Index session under subject
    await redis.sadd(`subject:sessions:${session.subjectId}`, session.id);

    // 3️⃣ Ensure index expires slightly AFTER sessions
    await redis.expire(
      `subject:sessions:${session.subjectId}`,
     SESSION_TTL_SECONDS + 60
    );

    return session;
  }


  // Updating Risk Level -> Redis is now your real-time risk state(OPA can consume it, Throttling can react, Enforcement is instant )
  static async updateRisk(params: {
    sessionId: string;
    riskLevel: RiskLevel;
    lastEvaluatedAt: number;
  }) {
    const raw = await redis.get(`session:${params.sessionId}`);
    if (!raw) return;
  
    const session = JSON.parse(raw) as Session;
  
    session.riskLevel = params.riskLevel;
    session.lastEvaluatedAt = params.lastEvaluatedAt;
  
    await redis.set(
      `session:${session.id}`,
      JSON.stringify(session),
      "KEEPTTL"
    );
  }



  static async get(sessionId: string): Promise<Session | null> {
    const raw = await redis.get(`session:${sessionId}`);
    return raw ? (JSON.parse(raw) as Session) : null;
  }

  /** Kill a single session instantly */
  static async revoke(sessionId: string) {
    const raw = await redis.get(`session:${sessionId}`);
    if (!raw) return;
  
    const session = JSON.parse(raw) as Session;
  
    // 1️⃣ Kill the session
    await redis.del(`session:${sessionId}`);
  
    // 2️⃣ Remove from subject index
    await redis.srem(`subject:sessions:${session.subjectId}`, sessionId);
  
    // 3️⃣ Audit
    await audit.log({
      action: "SESSION_REVOKED",
      actorId: session.subjectId,
      metadata: { sessionId },
    });
  }

  


  // Kill ALL sessions for a subject instantly 

  static async revokeAllForSubject(subjectId: string) {
    const indexKey = `subject:sessions:${subjectId}`;
  
    // 1️⃣ Get all session IDs for this subject
    const sessionIds = await redis.smembers(indexKey);
  
    if (sessionIds.length === 0) {
      return;
    }
  
    // 2️⃣ Delete all session keys
    const sessionKeys = sessionIds.map(id => `session:${id}`);
    await redis.del(...sessionKeys);
  
    // 3️⃣ Delete the index itself
    await redis.del(indexKey);
  
    // 4️⃣ Audit
    await audit.log({
      action: "SESSIONS_REVOKED_SUBJECT",
      actorId: subjectId,
      metadata: {
        revokedCount: sessionIds.length,
      },
    });
  }
  
}

