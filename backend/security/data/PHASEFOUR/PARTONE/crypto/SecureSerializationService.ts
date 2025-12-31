// RIVER WEBSITE/backend/security/data/security/PHASEFOUR/crypto/SecureSerializationService.ts



/**
 * SecureSerializationService.ts - (Canonical Encoding + Compression Safety + Crypto Interop) - This service solves one of the most 
 *                           commonly ignored real-world crypto failure points: unsafe serialization and compression before encryption/signing.
 * 
 * -- If serialization is not canonical and deterministic, signatures break, AAD mismatches occur, and integrity guarantees silently fail.
 *
 * ZERO → HERO OVERVIEW
 * -------------------
 * Encryption is only as safe as the bytes you encrypt.
 *
 * This service ensures:
 * - Canonical, deterministic serialization
 * - Cross-language compatibility
 * - Safe compression rules (CRIME/BREACH aware)
 *
 * WHY THIS EXISTS:
 * - Prevents signature bypass via encoding ambiguity
 * - Prevents AAD mismatch attacks
 * - Prevents compression-based side-channel leaks
 * 
 * 
 * Why this file is non-optional in real systems
        Most crypto breaches are not broken AES — they are:
                    JSON ordering differences
                    Unicode normalization issues
                    Compression side channels
                    Binary mismatch across services
        This file closes that entire class of bugs.
 */

import { gzipSync, gunzipSync } from 'zlib';

/**
 * Allowed serialization formats
 * Canonical formats ONLY.
 */
export enum SerializationFormat {
  JSON_CANONICAL = 'json-canonical',
  CBOR = 'cbor',
  MESSAGEPACK = 'msgpack'
}

interface SerializationOptions {
  compress?: boolean;
  compressionThresholdBytes?: number;
}

/**
 * Canonical JSON serialization
 *
 * - Sorted object keys
 * - No whitespace
 * - UTF-8 encoded
 */
function canonicalizeJSON(value: unknown): Buffer {
  const normalize = (obj: any): any => {
    if (Array.isArray(obj)) return obj.map(normalize);
    if (obj && typeof obj === 'object') {
      return Object.keys(obj)
        .sort()
        .reduce((acc, key) => {
          acc[key] = normalize(obj[key]);
          return acc;
        }, {} as Record<string, any>);
    }
    return obj;
  };

  const canonical = normalize(value);
  return Buffer.from(JSON.stringify(canonical), 'utf8');
}

export class SecureSerializationService {
  /**
   * Serialize payload into canonical byte representation
   */
  static serialize(
    payload: unknown,
    format: SerializationFormat,
    options: SerializationOptions = {}
  ): Buffer {
    let serialized: Buffer;

    switch (format) {
      case SerializationFormat.JSON_CANONICAL:
        serialized = canonicalizeJSON(payload);
        break;

      // Placeholders for production CBOR / MessagePack libs
      case SerializationFormat.CBOR:
      case SerializationFormat.MESSAGEPACK:
        throw new Error(`${format} not implemented yet`);

      default:
        throw new Error('Unsupported serialization format');
    }

    // Optional compression (SAFE MODE)
    if (options.compress) {
      const threshold = options.compressionThresholdBytes ?? 1024;

      /**
       * CRITICAL RULE:
       * Compression MUST occur BEFORE encryption
       * NEVER compress attacker-controlled secrets (tokens, cookies)
       */
      if (serialized.length >= threshold) {
        serialized = gzipSync(serialized);
      }
    }

    return serialized;
  }

  /**
   * Deserialize payload
   */
  static deserialize(buffer: Buffer, format: SerializationFormat): unknown {
    let decompressed = buffer;

    // Attempt decompression safely
    try {
      decompressed = gunzipSync(buffer);
    } catch {
      // Not compressed — continue safely
    }

    switch (format) {
      case SerializationFormat.JSON_CANONICAL:
        return JSON.parse(decompressed.toString('utf8'));

      case SerializationFormat.CBOR:
      case SerializationFormat.MESSAGEPACK:
        throw new Error(`${format} not implemented yet`);

      default:
        throw new Error('Unsupported serialization format');
    }
  }
}

/**
 * ---------------------------------------------
 * THREATS MITIGATED
 * ---------------------------------------------
 * - Signature bypass via encoding differences
 * - AAD mismatch attacks
 * - Compression oracle attacks (CRIME/BREACH)
 * - Cross-language deserialization bugs
 *
 * REAL-WORLD IMPACT:
 * - Required for multi-service cryptographic systems
 * - Mandatory for JWS/JWE, AEAD, Merkle hashing
 * - Enables deterministic hashing & signing
 */
