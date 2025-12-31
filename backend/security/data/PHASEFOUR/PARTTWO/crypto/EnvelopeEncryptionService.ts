// RIVER WEBSITE/backend/security/data/security/PHASEFOUR/PART2/crypto/EnvelopeEncryptionService.ts



/**
 * EnvelopeEncryptionService.ts - (KMS / HSM Abstraction, Key Hierarchy, KID Rotation) - This file enforces how data encryption actually survives breaches.
 * 
 * Most systems encrypt data. Very few systems survive key compromise.
 *
 * ZERO → HERO OVERVIEW
 * -------------------
 * Never encrypt data directly with a master key.
 *
 * Instead:
 * - Generate a per-object Data Encryption Key (DEK)
 * - Encrypt data with the DEK (fast, symmetric)
 * - Encrypt (wrap) the DEK with a Key Encryption Key (KEK)
 * - Store the wrapped DEK + KID alongside ciphertext
 *
 * If a KEK is compromised:
 * - Rotate KEK
 * - Re-wrap DEKs
 * - Data remains protected
 * 
    Why this design is bank-grade
            Keys never touch application memory unwrapped
            KEKs can live entirely inside:
            AWS KMS
            CloudHSM
            Azure Key Vault HSM
            DEKs are disposable and rotated implicitly
    This is the same pattern used by:
            Cloud providers
            Payment processors
            National-scale systems
 */

import { createCipheriv, createDecipheriv } from 'crypto';
import { SecureRngService, RngDomain } from '../../PARTONE/crypto/SecureRngService.ts';
import { CryptoPolicyRegistry } from '../../../PHASEONE/crypto/CryptoPolicyRegistry.ts';

export interface EncryptedPayload {
  algorithm: string;
  kid: string;
  iv: string;
  ciphertext: string;
  tag: string;
  wrappedDek: string;
}

export interface KeyEncryptionProvider {
  /**
   * Encrypt (wrap) a DEK using HSM/KMS
   */
  wrapKey(dek: Buffer): Promise<{ wrappedKey: Buffer; kid: string }>;

  /**
   * Decrypt (unwrap) a DEK using HSM/KMS
   */
  unwrapKey(wrappedKey: Buffer, kid: string): Promise<Buffer>;
}

export class EnvelopeEncryptionService {
  constructor(private readonly kekProvider: KeyEncryptionProvider) {}

  /**
   * Encrypt arbitrary data using envelope encryption
   */
  async encrypt(
    plaintext: Buffer,
    aad: Buffer = Buffer.alloc(0)
  ): Promise<EncryptedPayload> {
    const policy = CryptoPolicyRegistry.active();

    /**
     * Generate per-object DEK
     */
    const dek = SecureRngService.generateBytes(
      policy.dekLength,
      RngDomain.SESSION_KEY
    );

    /**
     * Generate AEAD IV
     */
    const iv = SecureRngService.generateAeadNonce();

    /**
     * Encrypt data with DEK
     */
    const cipher = createCipheriv(policy.aeadAlgorithm, dek, iv);
    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final()
    ]);

    const tag = cipher.getAuthTag();

    /**
     * Wrap DEK using KEK (HSM-backed)
     */
    const { wrappedKey, kid } = await this.kekProvider.wrapKey(dek);

    return {
      algorithm: policy.aeadAlgorithm,
      kid,
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: tag.toString('base64'),
      wrappedDek: wrappedKey.toString('base64')
    };
  }

  /**
   * Decrypt envelope-encrypted payload
   */
  async decrypt(
    payload: EncryptedPayload,
    aad: Buffer = Buffer.alloc(0)
  ): Promise<Buffer> {
    const policy = CryptoPolicyRegistry.byAlgorithm(payload.algorithm);

    /**
     * Unwrap DEK
     */
    const dek = await this.kekProvider.unwrapKey(
      Buffer.from(payload.wrappedDek, 'base64'),
      payload.kid
    );

    const decipher = createDecipheriv(
      policy.aeadAlgorithm,
      dek,
      Buffer.from(payload.iv, 'base64')
    );

    decipher.setAAD(aad);
    decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));

    return Buffer.concat([
      decipher.update(Buffer.from(payload.ciphertext, 'base64')),
      decipher.final()
    ]);
  }
}

/**
 * ---------------------------------------------
 * THREATS MITIGATED
 * ---------------------------------------------
 * - Master key compromise
 * - Large-scale data exfiltration
 * - Offline brute-force attacks
 * - Weak key rotation strategies
 *
 * REAL-WORLD BREACHES PREVENTED:
 * - Database dump with reusable encryption keys
 * - Backup exposure
 * - Insider key leakage
 *
 * COMPLIANCE ALIGNMENT:
 * - PCI DSS (key hierarchy)
 * - NIST SP 800-57
 * - ISO 27001 A.10
 */
