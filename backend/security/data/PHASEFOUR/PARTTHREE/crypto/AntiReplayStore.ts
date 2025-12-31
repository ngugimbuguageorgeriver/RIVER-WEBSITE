// RIVER WEBSITE/backend/security/data/security/PHASEFOUR/PARTTHREE/crypto/AntiReplayStore.ts



/**
 * AntiReplayStore.ts - (Cluster-Safe Nonce + Timestamp Enforcement) - This file eliminates 
 *                replay attacks across distributed systems, not just within a single process.
                                    This is where many “secure” systems fail in production.
 *
 * ZERO → HERO OVERVIEW
 * -------------------
 * Encryption without replay protection is incomplete.
 *
 * Attackers do NOT need to break crypto if they can:
 * - Capture a valid encrypted request
 * - Replay it later
 *
 * This service provides:
 * - Distributed, cluster-safe anti-replay protection
 * - Time-bound nonce enforcement
 * - Cross-instance consistency
 *
 * Designed for:
 * - APIs
 * - Payment systems
 * - Signed webhooks
 * - Secure messaging
 * 
 * 🔐 Why this is non-optional in real systems
        Without this:
                Encrypted requests can be replayed
                Payments can be duplicated
                Signed actions can be repeated
        With this:
                Every encrypted message is single-use
                Distributed systems behave securely
                Attacks fail silently and safely
 */

import { createHash } from 'crypto';
import { Redis } from 'ioredis';
import { CryptoPolicyRegistry } from '../../../PHASEONE/crypto/CryptoPolicyRegistry.ts';

export class AntiReplayStore {
  private readonly redis: Redis;
  private readonly namespace = 'anti-replay';

  constructor(redis: Redis) {
    this.redis = redis;
  }

  /**
   * Verify and store nonce
   *
   * Rules:
   * - Nonce must be unique
   * - Timestamp must be within allowed skew
   * - Storage must be atomic
   */
  async verifyAndStore(params: {
    nonce: string;
    timestamp: number;
    ttlSeconds?: number;
  }): Promise<void> {
    const policy = CryptoPolicyRegistry.active();
    const ttl = params.ttlSeconds ?? policy.replayWindowSeconds;

    /**
     * Timestamp validation
     *
     * Prevents:
     * - Delayed replay
     * - Time-shift attacks
     */
    const now = Date.now();
    const skewMs = policy.allowedClockSkewMs;

    if (Math.abs(now - params.timestamp) > skewMs) {
      throw new Error('Replay rejected: timestamp outside allowed window');
    }

    /**
     * Nonce normalization
     *
     * Hashing ensures:
     * - Fixed-length keys
     * - No raw nonce leakage in Redis
     */
    const nonceKey = createHash('sha256')
      .update(params.nonce)
      .digest('hex');

    const redisKey = `${this.namespace}:${nonceKey}`;

    /**
     * Atomic SETNX with TTL
     *
     * If the nonce already exists → replay detected
     */
    const result = await this.redis.set(
      redisKey,
      '1',
      'NX',
      'EX',
      ttl
    );

    if (result !== 'OK') {
      throw new Error('Replay detected: nonce already used');
    }
  }
}

/**
 * ---------------------------------------------
 * THREATS MITIGATED
 * ---------------------------------------------
 * - Replay attacks
 * - Delayed message injection
 * - Distributed race-condition replays
 *
 * WHY THIS IS PRODUCTION-GRADE
 * ----------------------------
 * - Cluster-safe (Redis-backed)
 * - Atomic enforcement (SETNX)
 * - Time-bound validity
 * - No plaintext nonce storage
 *
 * REAL-WORLD USE CASES
 * --------------------
 * - Payment APIs
 * - Signed webhooks
 * - Secure messaging
 * - OAuth token exchange
 *
 * COMPLIANCE
 * ----------
 * - PCI DSS (anti-replay for payments)
 * - OWASP ASVS L3
 * - Financial-grade API (FAPI)
 */
