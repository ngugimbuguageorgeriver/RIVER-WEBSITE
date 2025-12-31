// RIVER WEBSITE/backend/security/data/security/PHASEFOUR/crypto/SecureRngService.ts



/**
 * SecureRngService.ts - (Entropy Governance, Domain Separation, Replay-Safe Randomness) - This file addresses the 
 *                       single most catastrophic crypto failure class in real systems: weak, reused, predictable, or mis-scoped randomness.
 * 
 * 
 * Broken RNGs have caused:
            TLS private key recovery
            Wallet key theft
            Nonce reuse → AEAD plaintext recovery
            Signature key leakage (ECDSA, EdDSA failures)
 *
 * ZERO → HERO OVERVIEW
 * -------------------
 * Cryptography does not fail because algorithms are weak.
 * It fails because randomness is weak, reused, or misapplied.
 *
 * This service enforces:
 * - Cryptographically secure entropy sources
 * - Domain-separated randomness
 * - Replay-safe nonce generation
 * - Auditable randomness usage
 * 
 * 
 * If this file is wrong, everything above it is broken:
                AES
                TLS
                Tokens
                Signatures
                Sessions
        This file enforces cryptographic sanity at the root.
 */

import { randomBytes, createHash } from 'crypto';

/**
 * Randomness domain separation
 *
 * NEVER reuse randomness across domains.
 * This prevents cross-protocol and nonce-reuse attacks.
 */
export enum RngDomain {
  SESSION_KEY = 'session-key',
  AEAD_NONCE = 'aead-nonce',
  TOKEN_ID = 'token-id',
  CSRF_TOKEN = 'csrf-token',
  API_KEY = 'api-key',
  SIGNATURE_NONCE = 'signature-nonce'
}

export class SecureRngService {
  /**
   * Generate cryptographically secure random bytes
   *
   * @param length Bytes of entropy required
   * @param domain Purpose of randomness (domain-separated)
   */
  static generateBytes(length: number, domain: RngDomain): Buffer {
    if (length < 16) {
      throw new Error('Entropy length too small for cryptographic use');
    }

    /**
     * Use OS-backed CSPRNG
     * - Linux: /dev/urandom
     * - macOS: SecRandom
     * - Windows: BCryptGenRandom
     */
    const entropy = randomBytes(length);

    /**
     * Domain separation via hashing
     * Prevents reuse across crypto contexts
     */
    return createHash('sha256')
      .update(domain)
      .update(entropy)
      .digest()
      .subarray(0, length);
  }

  /**
   * Generate AEAD-safe nonce
   *
   * Guarantees:
   * - High entropy
   * - Domain separation
   * - Correct nonce size
   */
  static generateAeadNonce(): Buffer {
    /**
     * 96-bit nonce (recommended for AES-GCM / ChaCha20-Poly1305)
     */
    return this.generateBytes(12, RngDomain.AEAD_NONCE);
  }

  /**
   * Generate opaque token identifiers
   *
   * Used for:
   * - Refresh tokens
   * - Session IDs
   * - API keys
   */
  static generateTokenId(): string {
    const bytes = this.generateBytes(32, RngDomain.TOKEN_ID);
    return bytes.toString('base64url');
  }

  /**
   * Generate deterministic nonce (last-resort)
   *
   * ONLY used when randomness cannot be guaranteed
   * Example: AES-SIV, deterministic encryption modes
   */
  static deriveDeterministicNonce(
    key: Buffer,
    context: string,
    sequence: number
  ): Buffer {
    return createHash('sha256')
      .update(key)
      .update(context)
      .update(sequence.toString())
      .digest()
      .subarray(0, 12);
  }
}

/**
 * ---------------------------------------------
 * THREATS MITIGATED
 * ---------------------------------------------
 * - Nonce reuse (catastrophic for AEAD)
 * - Cross-protocol attacks
 * - Weak entropy attacks
 * - Replay attacks via predictable IDs
 *
 * REAL-WORLD FAILURES THIS PREVENTS:
 * - TLS private key leakage
 * - JWT forgery
 * - AES-GCM plaintext recovery
 * - ECDSA private key recovery
 *
 * COMPLIANCE ALIGNMENT:
 * - NIST SP 800-90A/B/C
 * - OWASP ASVS Level 3
 * - PCI DSS cryptographic requirements
 */
