// RIVER WEBSITE/backend/middleware/rateLimiter.middleware.ts

/**
 *
 * Production-grade IP-based and user-based rate limiter for login and sensitive endpoints.
 * 
 * Prevents brute-force attacks per IP.
 * TTL and max attempts can be tuned.
 * Can extend to per-account rate limiting.
 * 
 * 
 */

import { FastifyReply, FastifyRequest } from "fastify";
import LRU from "lru-cache";

const loginAttempts = new LRU<string, number>({ max: 5000, ttl: 15 * 60 * 1000 }); // 15 min window

export async function rateLimiter(request: FastifyRequest, reply: FastifyReply) {
    const ip = request.ip;
    const key = `login_${ip}`;

    const attempts = loginAttempts.get(key) || 0;

    if (attempts >= 5) {
        return reply.code(429).send({ error: "Too many requests, try again later" });
    }

    loginAttempts.set(key, attempts + 1);

    return;
}
