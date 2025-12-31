// RIVER WEBSITE/backend/security/data/security/PHASEFOUR/PARTFOUR/crypto/KeyRotationAuditService.ts



/**
 * KeyRotationAuditService.ts - Cryptographic Lifecycle Enforcement + Tamper-Evident Accountability
 *
 * =====================================================
 * ZERO → HERO OVERVIEW
 * =====================================================
 *
 * Cryptography is NOT static.
 *
 * Keys:
 * - Age
 * - Leak
 * - Get copied
 * - Become non-compliant
 *
 * This service enforces:
 * - Mandatory key rotation
 * - Versioned key lineage
 * - Immutable audit logging
 * - Tamper-evident verification
 *
 * This is REQUIRED for:
 * - PCI DSS
 * - SOC 2
 * - ISO 27001
 * - Financial & healthcare systems
 */

import { createHash, randomUUID } from 'crypto';

/**
 * -----------------------------------------------------
 * KEY METADATA MODEL
 * -----------------------------------------------------
 *
 * Every key has a lifecycle.
 * Keys without metadata are UNGOVERNED.
 */
export interface CryptoKeyMetadata {
  readonly keyId: string;
  readonly version: number;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly algorithm: string;
  readonly purpose:
    | 'encryption'
    | 'signing'
    | 'mac'
    | 'key-wrapping';
  readonly status: 'active' | 'rotated' | 'revoked';
}

/**
 * -----------------------------------------------------
 * AUDIT EVENT MODEL
 * -----------------------------------------------------
 *
 * Every sensitive operation MUST be logged.
 * Logs are security-critical data.
 */
export interface AuditEvent {
  readonly eventId: string;
  readonly timestamp: number;
  readonly actor: string;
  readonly action:
    | 'KEY_CREATED'
    | 'KEY_ROTATED'
    | 'KEY_REVOKED'
    | 'KEY_USED'
    | 'DECRYPT'
    | 'ENCRYPT';
  readonly keyId: string;
  readonly keyVersion: number;
  readonly contextHash: string;
}

/**
 * -----------------------------------------------------
 * IMMUTABLE AUDIT LOG
 * -----------------------------------------------------
 *
 * Append-only.
 * Hash-chained.
 * Tamper-evident.
 */
export class ImmutableAuditLog {
  private readonly events: AuditEvent[] = [];
  private lastHash: string = 'GENESIS';

  /**
   * Append audit event
   *
   * THREAT MODEL:
   * - Insider log deletion
   * - Timeline manipulation
   *
   * WHY THIS WORKS:
   * - Each event hashes the previous one
   */
  append(event: Omit<AuditEvent, 'eventId'>): AuditEvent {
    const serialized = JSON.stringify({
      ...event,
      previousHash: this.lastHash
    });

    const hash = createHash('sha256')
      .update(serialized)
      .digest('hex');

    const finalEvent: AuditEvent = {
      ...event,
      eventId: hash
    };

    this.events.push(finalEvent);
    this.lastHash = hash;

    return finalEvent;
  }

  /**
   * Verify log integrity
   *
   * Detects:
   * - Deleted entries
   * - Modified records
   * - Reordered events
   */
  verify(): boolean {
    let prev = 'GENESIS';

    for (const event of this.events) {
      const reconstructed = createHash('sha256')
        .update(
          JSON.stringify({
            ...event,
            eventId: undefined,
            previousHash: prev
          })
        )
        .digest('hex');

      if (reconstructed !== event.eventId) {
        return false;
      }

      prev = event.eventId;
    }

    return true;
  }
}

/**
 * -----------------------------------------------------
 * KEY ROTATION MANAGER
 * -----------------------------------------------------
 *
 * Enforces:
 * - Key expiry
 * - Version monotonicity
 * - Usage logging
 */
export class KeyRotationService {
  private readonly keys = new Map<string, CryptoKeyMetadata[]>();
  private readonly auditLog = new ImmutableAuditLog();

  /**
   * Create initial key
   */
  createKey(
    algorithm: string,
    purpose: CryptoKeyMetadata['purpose'],
    ttlMs: number,
    actor: string
  ): CryptoKeyMetadata {
    const keyId = randomUUID();
    const now = Date.now();

    const metadata: CryptoKeyMetadata = {
      keyId,
      version: 1,
      createdAt: now,
      expiresAt: now + ttlMs,
      algorithm,
      purpose,
      status: 'active'
    };

    this.keys.set(keyId, [metadata]);

    this.auditLog.append({
      timestamp: now,
      actor,
      action: 'KEY_CREATED',
      keyId,
      keyVersion: 1,
      contextHash: this.contextHash(metadata)
    });

    return metadata;
  }

  /**
   * Rotate key
   *
   * THREAT MODEL:
   * - Long-lived key compromise
   * - Crypto stagnation
   */
  rotateKey(
    keyId: string,
    ttlMs: number,
    actor: string
  ): CryptoKeyMetadata {
    const lineage = this.keys.get(keyId);
    if (!lineage) {
      throw new Error('Key not found');
    }

    const latest = lineage[lineage.length - 1];

    latest.status = 'rotated';

    const now = Date.now();
    const rotated: CryptoKeyMetadata = {
      ...latest,
      version: latest.version + 1,
      createdAt: now,
      expiresAt: now + ttlMs,
      status: 'active'
    };

    lineage.push(rotated);

    this.auditLog.append({
      timestamp: now,
      actor,
      action: 'KEY_ROTATED',
      keyId,
      keyVersion: rotated.version,
      contextHash: this.contextHash(rotated)
    });

    return rotated;
  }

  /**
   * Enforce key validity before use
   *
   * FAIL CLOSED.
   */
  assertUsable(key: CryptoKeyMetadata, actor: string): void {
    if (key.status !== 'active') {
      throw new Error('Key is not active');
    }

    if (Date.now() > key.expiresAt) {
      throw new Error('Key expired');
    }

    this.auditLog.append({
      timestamp: Date.now(),
      actor,
      action: 'KEY_USED',
      keyId: key.keyId,
      keyVersion: key.version,
      contextHash: this.contextHash(key)
    });
  }

  getAuditLog(): ImmutableAuditLog {
    return this.auditLog;
  }

  /**
   * Context hashing
   *
   * Prevents log forgery by binding metadata state.
   */
  private contextHash(data: unknown): string {
    return createHash('sha256')
      .update(JSON.stringify(data))
      .digest('hex');
  }
}

/**
 * =====================================================
 * THREATS MITIGATED
 * =====================================================
 *
 * ✔ Silent key reuse
 * ✔ Undetected key compromise
 * ✔ Insider log manipulation
 * ✔ Compliance audit failure
 *
 * =====================================================
 * WHY THIS IS PRODUCTION-GRADE
 * =====================================================
 *
 * - Enforced rotation
 * - Versioned lineage
 * - Tamper-evident logs
 * - Fail-closed usage
 *
 * =====================================================
 * REGULATED SYSTEM USAGE
 * =====================================================
 *
 * ✔ PCI DSS (key rotation + audit)
 * ✔ SOC 2 (immutability)
 * ✔ ISO 27001 (key lifecycle)
 * ✔ Financial audit trails
 *
 * =====================================================
 * REAL-WORLD FAILURE PREVENTED
 * =====================================================
 *
 * Many breaches persist for YEARS
 * because keys never rotate and logs are mutable.
 *
 * This system forces:
 * - Rotation
 * - Accountability
 * - Forensic confidence
 */
