// RIVER WEBSITE/backend/authorization/opa/opa.cache.ts

/**
 * OPA DECISION CACHING - ✅ Cache OPA Decisions (SHORT TTL)
 * 
 * 📌 Why safe?
            * Risk updates invalidate sessions anyway
            * TTL is tiny
            * Huge performance win
 */

const CACHE_TTL = 5; // seconds

export async function authorizeWithCache(input) {
  const key = `opa:${hash(input)}`;

  const cached = await redis.get(key);
  if (cached) return JSON.parse(cached);

  const decision = await opa.evaluate(input);

  await redis.set(key, JSON.stringify(decision), "EX", CACHE_TTL);
  return decision;
}
