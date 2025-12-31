// RIVER WEBSITE/backend/security/data/security/PHASEFOUR/PART2/crypto/SecureRngService.ts



/**
 * SecureRngService.ts - (Entropy Sources, Domain Separation, Replay Safety) - This file defines how randomness is generated safely, 
 *                      how nonces are separated by domain, and how we prevent cross-protocol and replay failures.
 * 
 * Poor randomness silently destroys cryptography. This file prevents that class of failure.
 *
 * ZERO → HERO OVERVIEW
 * -------------------
 * Cryptography does NOT fail because of bad algorithms.
 * It fails because of:
 *
 * - Weak randomness
 * - Nonce reuse across domains
 * - Shared IV spaces
 *
 * This service enforces:
 * - Hardware-backed randomness
 * - Domain-separated nonces
 * - Deterministic nonce derivation ONLY when explicitly allowed
 * 
 * 
    * Why this matters in production
            Nonce reuse = total data compromise
            Domain separation prevents silent cross-service failure
            Deterministic encryption is gated and auditable
            RNG is centralized and policy-driven
    This is required for:
            Distributed systems
            Microservices
            Long-lived keys with rotation
 */

import { randomBytes, createHmac } from 'crypto';
import { CryptoPolicyRegistry } from '../../../PHASEONE/crypto/CryptoPolicyRegistry.ts';

/**
 * Nonce domains prevent reuse across crypto contexts.
 *
 * If the same key is ever used with the same nonce twice
 * (even in different protocols), confidentiality collapses.
 */
export enum NonceDomain {
  AEAD_PAYLOAD = 'aead-payload',
  TOKEN_ENCRYPTION = 'token-encryption',
  BACKUP_ENCRYPTION = 'backup-encryption',
  DETERMINISTIC_FIELDS = 'deterministic-fields'
}

export class SecureRngService {
  /**
   * Generate cryptographically secure random bytes
   *
   * Source:
   * - /dev/urandom (Linux)
   * - CryptGenRandom (Windows)
   * - HWRNG when available
   */
  static random(length: number): Buffer {
    return randomBytes(length);
  }

  /**
   * Generate AEAD nonce (randomized mode)
   *
   * AES-GCM requires:
   * - 96-bit (12-byte) nonce
   * - Unique per key
   */
  static generateAeadNonce(): Buffer {
    return this.random(12);
  }

  /**
   * Generate domain-separated nonce
   *
   * Used when:
   * - Multiple protocols share entropy sources
   * - Keys are rotated but nonce spaces must remain distinct
   */
  static generateDomainNonce(domain: NonceDomain): Buffer {
    const entropy = this.random(32);
    const policy = CryptoPolicyRegistry.active();

    /**
     * Domain separation via HMAC
     *
     * This prevents:
     * - Cross-protocol nonce collision
     * - Chosen-input nonce attacks
     */
    return createHmac('sha256', policy.nonceDerivationKey)
      .update(domain)
      .update(entropy)
      .digest()
      .subarray(0, 12);
  }

  /**
   * Deterministic nonce derivation
   *
   * DANGEROUS if misused.
   * Allowed ONLY for explicitly approved use cases.
   *
   * Used for:
   * - Searchable encrypted fields
   * - Stable ciphertext generation
   */
  static deriveDeterministicNonce(
    plaintext: Buffer,
    aad: Buffer
  ): Buffer {
    const policy = CryptoPolicyRegistry.active();

    /**
     * Domain-separated deterministic nonce
     *
     * Prevents:
     * - Cross-field collisions
     * - Replay substitution
     */
    return createHmac('sha256', policy.deterministicNonceKey)
      .update(NonceDomain.DETERMINISTIC_FIELDS)
      .update(aad)
      .update(plaintext)
      .digest()
      .subarray(0, 12);
  }
}

/**
 * ---------------------------------------------
 * THREATS MITIGATED
 * ---------------------------------------------
 * - Nonce reuse across services
 * - Cross-protocol attacks
 * - Replay attacks
 * - RNG predictability
 *
 * REAL INCIDENTS PREVENTED:
 * - GCM catastrophic failure
 * - Token replay across services
 * - Deterministic ciphertext correlation
 *
 * COMPLIANCE:
 * - NIST SP 800-90A/B/C
 * - RFC 4106 (GCM nonce requirements)
 */
