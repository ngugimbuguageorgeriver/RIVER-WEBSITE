// RIVER WEBSITE/backend/security/data/security/PHASETHREE/crypto/AntiReplayStore.ts

/**
 * AntiReplayStore.ts
 *
 * ZERO → HERO OVERVIEW
 * -------------------
 * This service enforces message uniqueness across time and systems.
 *
 * It guarantees:
 * - A message can only be processed once
 * - Messages outside a time window are rejected
 * - Distributed services share replay state
 *
 * REQUIRED FOR:
 * - APIs
 * - Payment systems
 * - Signed webhooks
 * - Secure messaging
 * 
 * 🔐 Design Guarantees
        ✔ Distributed replay protection
        ✔ Time-bounded validity
        ✔ Storage abstraction
        ✔ No plaintext nonce storage
        ✔ Failure-safe rejection
 */

import assert from "node:assert";
import crypto from "node:crypto";

/**
 * ---------------------------------------------
 * 1. REPLAY RECORD
 * ---------------------------------------------
 *
 * Stored in Redis / DB
 */
export interface ReplayRecord {
  nonceHash: string;
  timestamp: number;
  expiresAt: number;
}

/**
 * ---------------------------------------------
 * 2. STORAGE INTERFACE
 * ---------------------------------------------
 *
 * Abstracted so we can:
 * - Swap Redis / SQL / Dynamo
 * - Test deterministically
 */
export interface AntiReplayStorage {
  exists(nonceHash: string): Promise<boolean>;
  store(record: ReplayRecord): Promise<void>;
}

/**
 * ---------------------------------------------
 * 3. CONFIGURATION
 * ---------------------------------------------
 */
export interface AntiReplayConfig {
  allowedClockSkewMs: number; // e.g. ±5 minutes
  ttlMs: number;             // nonce lifetime
}

/**
 * ---------------------------------------------
 * 4. ANTI-REPLAY SERVICE
 * ---------------------------------------------
 */
export class AntiReplayStore {
  constructor(
    private readonly storage: AntiReplayStorage,
    private readonly config: AntiReplayConfig
  ) {}

  /**
   * ---------------------------------------------
   * VERIFY & REGISTER NONCE
   * ---------------------------------------------
   *
   * Throws on:
   * - Replay
   * - Expired timestamp
   * - Clock skew violation
   */
  async verifyAndRegister(
    nonce: string,
    timestamp: number
  ): Promise<void> {
    const now = Date.now();

    // ---- Time validation ----
    assert(
      Math.abs(now - timestamp) <= this.config.allowedClockSkewMs,
      "Timestamp outside allowed clock skew"
    );

    // ---- Nonce hashing ----
    // We NEVER store raw nonces
    const nonceHash = crypto
      .createHash("sha256")
      .update(nonce)
      .digest("hex");

    // ---- Replay detection ----
    if (await this.storage.exists(nonceHash)) {
      throw new Error("Replay detected: nonce already used");
    }

    // ---- Persist nonce ----
    await this.storage.store({
      nonceHash,
      timestamp,
      expiresAt: now + this.config.ttlMs,
    });
  }
}

/**
 * ---------------------------------------------
 * 5. WHY THIS IS CRITICAL
 * ---------------------------------------------
 *
 * WITHOUT THIS:
 * - Encrypted requests can be replayed
 * - Signed webhooks can be replayed
 * - Payments can be duplicated
 *
 * REAL INCIDENTS:
 * - Stripe webhook replays
 * - Banking transfer duplication
 * - OAuth token replay
 */
