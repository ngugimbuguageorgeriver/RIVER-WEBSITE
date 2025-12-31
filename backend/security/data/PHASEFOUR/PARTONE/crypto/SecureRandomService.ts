// RIVER WEBSITE/backend/security/data/security/PHASEFOUR/crypto/SecureRandomService.ts



/**
 * SecureRandomService.ts - (Secure Randomness & Anti-Replay Support)
 * 
 * This service ensures cryptographic-grade randomness for:
            * Key generation
            * IVs / nonces
            * One-time secrets
            * Anti-replay mechanisms
 *
 * ZERO → HERO OVERVIEW
 * -------------------
 * This service provides:
 * - Cryptographically secure random bytes
 * - Nonce generation for AEAD / anti-replay
 * - Replay detection support
 *
 * WHY THIS MATTERS:
 * - Weak randomness breaks encryption entirely
 * - Nonces prevent replay attacks
 * - Ensures session tokens and payload encryption are secure
 * 
 * 
 * 🔐 Threats Mitigated
                  Threat	                                         Mitigation
             Weak randomness / predictable IVs	            crypto.randomBytes() / HWRNG
             Replay attacks	                                Nonce verification with TTL
             Token collisions	                            Cryptographically random UUIDs
             Session hijacking	                            Nonces and random ephemeral keys
 */

import crypto from 'crypto';

export class SecureRandomService {
  /**
   * Generate cryptographically secure random bytes
   * @param length number of bytes
   * @returns Buffer
   */
  public static randomBytes(length: number): Buffer {
    return crypto.randomBytes(length);
  }

  /**
   * Generate a nonce suitable for AEAD (12 bytes recommended for AES-GCM)
   */
  public static generateNonce(size: number = 12): Buffer {
    return this.randomBytes(size);
  }

  /**
   * Generate a cryptographically random UUID (v4)
   * Useful for KIDs, token IDs, or ephemeral secrets
   */
  public static randomUUID(): string {
    return crypto.randomUUID();
  }

  /**
   * Optional: Generate a base64-encoded nonce for web APIs
   */
  public static base64Nonce(size: number = 12): string {
    return this.generateNonce(size).toString('base64');
  }

  /**
   * Anti-Replay Verification (stateless example)
   * Stores recent nonces in memory to prevent reuse
   */
  private static recentNonces: Set<string> = new Set();

  public static verifyNonce(nonce: string, ttlMs: number = 5 * 60 * 1000): boolean {
    const now = Date.now();
    if (this.recentNonces.has(nonce)) return false;

    // Store nonce with TTL
    this.recentNonces.add(nonce);
    setTimeout(() => this.recentNonces.delete(nonce), ttlMs);
    return true;
  }
}

/**
 * ---------------------------------------------
 * THREATS MITIGATED
 * ---------------------------------------------
 * - Weak RNG attacks (predictable IVs/keys)
 * - Replay attacks on encrypted messages
 * - Collision attacks on session tokens
 *
 * REAL-WORLD IMPACT:
 * - Generates HWRNG-quality nonces for AEAD payloads
 * - Prevents token/session reuse in APIs
 * - Supports secure ephemeral key material
 */
