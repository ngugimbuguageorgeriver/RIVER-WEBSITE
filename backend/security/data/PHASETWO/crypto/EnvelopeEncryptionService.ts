// RIVER WEBSITE/backend/security/data/security/PHASETWO/crypto/EnvelopeEncryptionService.ts


/**
 * EnvelopeEncryptionService.ts - This file is the cryptographic heart of the system.
 *
 * ZERO → HERO OVERVIEW
 * -------------------
 * Envelope encryption is the industry-standard pattern used by:
 * - AWS KMS
 * - Google Cloud KMS
 * - Azure Key Vault
 * - Payment processors
 * - Financial institutions
 *
 * Principle:
 *   - Data is encrypted with a short-lived symmetric key (DEK)
 *   - The DEK is encrypted ("wrapped") with a long-lived master key (KEK)
 *
 * This minimizes blast radius and enables safe key rotation.
 * 
 * 🔒 What This Unlocks
        * With envelope encryption in place, you can now safely:
                * Encrypt databases
                * Encrypt backups
                * Encrypt tokens
                * Encrypt payloads
                * Rotate keys without re-encrypting data

        This is non-negotiable for regulated or high-value systems.
 */

import crypto from "node:crypto";
import assert from "node:assert";

import { DataClassification } from "../../PHASEONE/data/DataClassification.ts";
import { CRYPTO_POLICY } from "../../PHASEONE/policy/CryptoPolicyRegistry.ts";
import { assertPlaintextAllowed, TrustZone } from "../../PHASEONE/trust/TrustBoundaries.ts";

/**
 * ---------------------------------------------
 * 1. CRYPTOGRAPHIC CONSTANTS
 * ---------------------------------------------
 * Centralized to enforce algorithm governance.
 */
const AEAD_ALGO = "aes-256-gcm";
const KEY_SIZE_BYTES = 32; // 256-bit
const IV_SIZE_BYTES = 12;  // NIST-recommended for GCM
const AUTH_TAG_BYTES = 16;

/**
 * ---------------------------------------------
 * 2. KEY IDENTIFIER (KID) STRUCTURE
 * ---------------------------------------------
 *
 * KIDs allow:
 * - Key rotation
 * - Backward compatibility
 * - Auditability
 */
export interface KeyDescriptor {
  readonly kid: string;
  readonly algorithm: string;
  readonly createdAt: string;
}

/**
 * ---------------------------------------------
 * 3. ENCRYPTED PAYLOAD FORMAT
 * ---------------------------------------------
 *
 * This is intentionally verbose.
 * Explicit metadata prevents misuse and downgrade attacks.
 */
export interface EncryptedEnvelope {
  readonly classification: DataClassification;
  readonly key: {
    readonly encryptedDek: Buffer;
    readonly dekKID: string;
  };
  readonly crypto: {
    readonly algorithm: string;
    readonly iv: Buffer;
    readonly authTag: Buffer;
  };
  readonly ciphertext: Buffer;
}

/**
 * ---------------------------------------------
 * 4. KMS / HSM ABSTRACTION
 * ---------------------------------------------
 *
 * This allows seamless transition from:
 * - Local dev keys
 * - Cloud KMS
 * - On-prem HSM
 *
 * WITHOUT changing application code.
 */
export interface KeyManagementProvider {
  wrapKey(params: {
    dek: Buffer;
    classification: DataClassification;
  }): Promise<{ encryptedDek: Buffer; dekKID: string }>;

  unwrapKey(params: {
    encryptedDek: Buffer;
    dekKID: string;
  }): Promise<Buffer>;
}

/**
 * ---------------------------------------------
 * 5. ENVELOPE ENCRYPTION SERVICE
 * ---------------------------------------------
 */
export class EnvelopeEncryptionService {
  constructor(private readonly kms: KeyManagementProvider) {}

  /**
   * ---------------------------------------------
   * ENCRYPT
   * ---------------------------------------------
   *
   * Steps:
   * 1. Enforce trust boundary
   * 2. Generate cryptographically secure DEK
   * 3. Encrypt payload with AEAD
   * 4. Wrap DEK using KMS/HSM
   */
  async encrypt(params: {
    plaintext: Buffer;
    classification: DataClassification;
    aad?: Buffer;
  }): Promise<EncryptedEnvelope> {
    assertPlaintextAllowed({
      zone: TrustZone.APPLICATION,
      operation: "PROCESS",
    });

    CRYPTO_POLICY.assertAllowed(AEAD_ALGO);

    const dek = crypto.randomBytes(KEY_SIZE_BYTES);

    const iv = crypto.randomBytes(IV_SIZE_BYTES);

    const cipher = crypto.createCipheriv(AEAD_ALGO, dek, iv);
    if (params.aad) cipher.setAAD(params.aad);

    const ciphertext = Buffer.concat([
      cipher.update(params.plaintext),
      cipher.final(),
    ]);

    const authTag = cipher.getAuthTag();

    const { encryptedDek, dekKID } = await this.kms.wrapKey({
      dek,
      classification: params.classification,
    });

    // ZEROIZATION — remove DEK from memory ASAP
    dek.fill(0);

    return {
      classification: params.classification,
      key: { encryptedDek, dekKID },
      crypto: {
        algorithm: AEAD_ALGO,
        iv,
        authTag,
      },
      ciphertext,
    };
  }

  /**
   * ---------------------------------------------
   * DECRYPT
   * ---------------------------------------------
   *
   * Steps:
   * 1. Enforce trust boundary
   * 2. Unwrap DEK
   * 3. Authenticate + decrypt
   */
  async decrypt(params: {
    envelope: EncryptedEnvelope;
    aad?: Buffer;
  }): Promise<Buffer> {
    assertPlaintextAllowed({
      zone: TrustZone.APPLICATION,
      operation: "DECRYPT",
    });

    CRYPTO_POLICY.assertAllowed(params.envelope.crypto.algorithm);

    const dek = await this.kms.unwrapKey({
      encryptedDek: params.envelope.key.encryptedDek,
      dekKID: params.envelope.key.dekKID,
    });

    const decipher = crypto.createDecipheriv(
      params.envelope.crypto.algorithm,
      dek,
      params.envelope.crypto.iv
    );

    if (params.aad) decipher.setAAD(params.aad);
    decipher.setAuthTag(params.envelope.crypto.authTag);

    const plaintext = Buffer.concat([
      decipher.update(params.envelope.ciphertext),
      decipher.final(),
    ]);

    // ZEROIZATION
    dek.fill(0);

    return plaintext;
  }
}

/**
 * ---------------------------------------------
 * 6. WHY THIS IS PRODUCTION-GRADE
 * ---------------------------------------------
 *
 * ✔ Enforces cryptographic policy
 * ✔ Supports key rotation via KID
 * ✔ Limits plaintext lifetime
 * ✔ HSM/KMS compatible
 * ✔ AEAD prevents tampering
 *
 * REAL-WORLD USE:
 * - Encrypt DB fields
 * - Secure backups
 * - Protect PII / PCI data
 * - Cloud secrets storage
 */



