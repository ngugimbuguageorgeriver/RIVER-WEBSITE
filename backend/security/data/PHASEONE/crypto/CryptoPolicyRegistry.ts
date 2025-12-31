// RIVER WEBSITE/backend/security/data/security/PHASEONE/crypto/CryptoPolicyRegistry.ts

/**
 * CryptoPolicyRegistry.ts -> Purpose: Algorithm governance, cryptographic agility, emergency deprecation
 *
 * ZERO → HERO OVERVIEW
 * -------------------
 * This file defines the cryptographic "constitution" of the system.
 *
 * Instead of scattering cryptographic choices across the codebase
 * (which leads to silent insecurity over time),
 * we centralize ALL algorithm decisions here.
 *
 * This is how banks, HSM-backed systems, and regulated environments
 * maintain cryptographic agility.
 *
 * If an algorithm breaks tomorrow, THIS FILE is your kill switch.
 * 

✅ What We Have Achieved So Far
            This single file already gives you:
            Cryptographic governance
            Algorithm kill-switch
            Audit-friendly enforcement
            Future-proof crypto rotation
            Downgrade attack prevention

            This is not optional in serious systems. Most breaches happen because this layer does not exist.
*/

import assert from "node:assert";

/**
 * ---------------------------------------------
 * 1. ENUMERATE SUPPORTED CRYPTO PRIMITIVES
 * ---------------------------------------------
 *
 * WHY THIS EXISTS:
 * - Prevents ad-hoc crypto usage
 * - Eliminates downgrade attacks
 * - Enables formal audits (SOC2 / ISO / PCI)
 *
 * REAL INCIDENT PREVENTED:
 * - Silent fallback to SHA-1 or AES-CBC
 */

/**
 * Symmetric encryption algorithms
 */
export enum SymmetricAlgorithm {
  AES_256_GCM = "AES-256-GCM",
  AES_256_SIV = "AES-256-SIV", // misuse-resistant
  CHACHA20_POLY1305 = "CHACHA20-POLY1305",
}

/**
 * Asymmetric / key exchange algorithms
 */
export enum AsymmetricAlgorithm {
  X25519 = "X25519",
  P256 = "P-256",
}

/**
 * Digital signature algorithms
 */
export enum SignatureAlgorithm {
  ED25519 = "Ed25519",
  RSA_PSS_3072 = "RSA-PSS-3072",
}

/**
 * Hash / MAC algorithms
 */
export enum HashAlgorithm {
  SHA_256 = "SHA-256",
  SHA_512 = "SHA-512",
}

/**
 * Key derivation functions
 */
export enum KDFAlgorithm {
  HKDF_SHA256 = "HKDF-SHA256",
  ARGON2ID = "ARGON2id",
}

/**
 * ---------------------------------------------
 * 2. CRYPTO PROFILE DEFINITION
 * ---------------------------------------------
 *
 * A "crypto profile" is a VERSIONED bundle of
 * allowed algorithms for a given environment.
 *
 * Example:
 * - prod-strict-v1
 * - test-relaxed-v1
 *
 * This is how you rotate crypto WITHOUT breaking data.
 */

export interface CryptoProfile {
  readonly id: string;
  readonly symmetric: ReadonlySet<SymmetricAlgorithm>;
  readonly asymmetric: ReadonlySet<AsymmetricAlgorithm>;
  readonly signatures: ReadonlySet<SignatureAlgorithm>;
  readonly hashes: ReadonlySet<HashAlgorithm>;
  readonly kdfs: ReadonlySet<KDFAlgorithm>;
  readonly deprecated: boolean;
}

/**
 * ---------------------------------------------
 * 3. CRYPTO POLICY REGISTRY (SINGLE SOURCE OF TRUTH)
 * ---------------------------------------------
 *
 * WHY THIS IS CRITICAL:
 * - Prevents "crypto drift"
 * - Enables emergency deprecation
 * - Makes audits trivial
 *
 * THIS IS NOT CONFIG.
 * THIS IS SECURITY POLICY.
 */

export class CryptoPolicyRegistry {
  /**
   * Immutable registry of all crypto profiles
   */
  private static readonly profiles: Map<string, CryptoProfile> = new Map([
    [
      "prod-strict-v1",
      {
        id: "prod-strict-v1",
        symmetric: new Set([
          SymmetricAlgorithm.AES_256_GCM,
          SymmetricAlgorithm.AES_256_SIV,
          SymmetricAlgorithm.CHACHA20_POLY1305,
        ]),
        asymmetric: new Set([
          AsymmetricAlgorithm.X25519,
          AsymmetricAlgorithm.P256,
        ]),
        signatures: new Set([
          SignatureAlgorithm.ED25519,
          SignatureAlgorithm.RSA_PSS_3072,
        ]),
        hashes: new Set([
          HashAlgorithm.SHA_256,
          HashAlgorithm.SHA_512,
        ]),
        kdfs: new Set([
          KDFAlgorithm.HKDF_SHA256,
          KDFAlgorithm.ARGON2ID,
        ]),
        deprecated: false,
      },
    ],
  ]);

  /**
   * ---------------------------------------------
   * 4. PROFILE RETRIEVAL WITH HARD FAIL
   * ---------------------------------------------
   *
   * SECURITY PRINCIPLE:
   * - Fail CLOSED, never open
   *
   * If a profile does not exist,
   * the system MUST refuse to operate.
   */
  static getProfile(profileId: string): CryptoProfile {
    const profile = this.profiles.get(profileId);

    assert(
      profile,
      `CRITICAL: Crypto profile '${profileId}' is not defined`
    );

    assert(
      !profile.deprecated,
      `CRITICAL: Crypto profile '${profileId}' is deprecated`
    );

    return profile;
  }

  /**
   * ---------------------------------------------
   * 5. ALGORITHM ENFORCEMENT GUARDS
   * ---------------------------------------------
   *
   * These functions are called by encryption,
   * signing, and KDF services BEFORE usage.
   *
   * This prevents:
   * - Downgrade attacks
   * - Accidental insecure defaults
   */

  static assertSymmetricAllowed(
    profile: CryptoProfile,
    algorithm: SymmetricAlgorithm
  ): void {
    assert(
      profile.symmetric.has(algorithm),
      `DISALLOWED symmetric algorithm: ${algorithm}`
    );
  }

  static assertSignatureAllowed(
    profile: CryptoProfile,
    algorithm: SignatureAlgorithm
  ): void {
    assert(
      profile.signatures.has(algorithm),
      `DISALLOWED signature algorithm: ${algorithm}`
    );
  }

  static assertKDFAllowed(
    profile: CryptoProfile,
    algorithm: KDFAlgorithm
  ): void {
    assert(
      profile.kdfs.has(algorithm),
      `DISALLOWED KDF algorithm: ${algorithm}`
    );
  }
}

/**
 * ---------------------------------------------
 * 6. REAL-WORLD APPLICATION
 * ---------------------------------------------
 *
 * Every crypto operation MUST:
 * 1. Load a crypto profile
 * 2. Assert algorithm is allowed
 * 3. Proceed
 *
 * This mirrors:
 * - AWS KMS policy enforcement
 * - Google Tink key templates
 * - HSM algorithm whitelisting
 *
 * RESULT:
 * - Cryptographic agility
 * - Emergency response capability
 * - Audit-ready system
 */
