// RIVER WEBSITE/backend/authorization/throttling/riskThrottle.middleware.ts

/** */

import Redis from "ioredis";
const redis = new Redis(process.env.REDIS_URL!);

export async function enforceRateLimit(
  sessionId: string,
  limit: number
) {
  const key = `rate:${sessionId}`;
  const count = await redis.incr(key);

  if (count === 1) {
    await redis.expire(key, 60); // per-minute window
  }

  if (count > limit) {
    throw new Error("RATE_LIMIT_EXCEEDED");
  }
}
