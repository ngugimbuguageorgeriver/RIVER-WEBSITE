// RIVER WEBSITE/backend/security/data/security/PHASEONE/trust/TrustBoundaries.ts


/**
 * TrustBoundaries.ts - ANSWERS THE QUESTION - “Where is plaintext allowed to exist, who owns it, and where must cryptography terminate?”
 * This file answers a question that must be answered explicitly in any Zero Trust system:
 *
 * ZERO → HERO OVERVIEW
 * -------------------
 * This file defines CRYPTOGRAPHIC TRUST BOUNDARIES.
 *
 * A trust boundary is a location where:
 * - Plaintext MAY legally exist, OR
 * - Cryptography MUST be applied or terminated
 *
 * If this is undefined, plaintext leaks WILL occur.
 */

import assert from "node:assert";

/**
 * ---------------------------------------------
 * 1. TRUST ZONES
 * ---------------------------------------------
 *
 * These represent SECURITY DOMAINS.
 *
 * Each zone has different assumptions:
 * - Network trust
 * - Process trust
 * - Operator trust
 */
export enum TrustZone {
  CLIENT_DEVICE = "CLIENT_DEVICE",
  EDGE = "EDGE",
  APPLICATION = "APPLICATION",
  INTERNAL_SERVICE = "INTERNAL_SERVICE",
  DATA_STORE = "DATA_STORE",
  BACKUP = "BACKUP",
}

/**
 * ---------------------------------------------
 * 2. PLAINTEXT PERMISSION MODEL
 * ---------------------------------------------
 *
 * This explicitly defines:
 * - Whether plaintext is allowed
 * - Who owns the plaintext
 * - Whether secrets may be persisted
 *
 * THIS IS THE MOST IMPORTANT TABLE
 * IN THE ENTIRE SYSTEM.
 */
export interface PlaintextPolicy {
  readonly plaintextAllowed: boolean;
  readonly owner: "USER" | "SERVICE" | "NONE";
  readonly persistenceAllowed: boolean;
}

/**
 * ---------------------------------------------
 * 3. TRUST BOUNDARY POLICY MAP
 * ---------------------------------------------
 *
 * SECURITY PHILOSOPHY:
 * - Plaintext should exist for the SHORTEST time
 * - In the FEWEST places
 * - With CLEAR ownership
 */
const TRUST_BOUNDARY_POLICY: Record<TrustZone, PlaintextPolicy> = {
  [TrustZone.CLIENT_DEVICE]: {
    plaintextAllowed: true,
    owner: "USER",
    persistenceAllowed: false,
  },

  [TrustZone.EDGE]: {
    plaintextAllowed: false,
    owner: "NONE",
    persistenceAllowed: false,
  },

  [TrustZone.APPLICATION]: {
    plaintextAllowed: true,
    owner: "SERVICE",
    persistenceAllowed: false,
  },

  [TrustZone.INTERNAL_SERVICE]: {
    plaintextAllowed: false,
    owner: "NONE",
    persistenceAllowed: false,
  },

  [TrustZone.DATA_STORE]: {
    plaintextAllowed: false,
    owner: "NONE",
    persistenceAllowed: true, // encrypted persistence ONLY
  },

  [TrustZone.BACKUP]: {
    plaintextAllowed: false,
    owner: "NONE",
    persistenceAllowed: true, // encrypted, offline keys
  },
};

/**
 * ---------------------------------------------
 * 4. TRUST BOUNDARY ENFORCEMENT
 * ---------------------------------------------
 *
 * This function is called:
 * - Before decrypting
 * - Before storing
 * - Before transmitting
 *
 * If this fails, it is a BUG, not an exception.
 */
export function assertPlaintextAllowed(params: {
  zone: TrustZone;
  operation: "DECRYPT" | "STORE" | "PROCESS";
}): PlaintextPolicy {
  const { zone } = params;

  const policy = TRUST_BOUNDARY_POLICY[zone];

  assert(policy, `No trust policy defined for zone ${zone}`);

  assert(
    policy.plaintextAllowed,
    `Plaintext is NOT allowed in trust zone ${zone}`
  );

  return policy;
}

/**
 * ---------------------------------------------
 * 5. WHY THIS DESIGN IS NON-NEGOTIABLE
 * ---------------------------------------------
 *
 * REAL BREACH PATTERNS THIS STOPS:
 *
 * ❌ Decrypting data inside reverse proxies
 * ❌ Logging decrypted payloads
 * ❌ Passing plaintext between microservices
 * ❌ Storing secrets in caches
 *
 * ✔ Forces explicit crypto termination points
 * ✔ Enables formal threat modeling
 * ✔ Makes Zero Trust enforceable, not aspirational
 *
 * SYSTEMS THAT REQUIRE THIS:
 * - Financial infrastructure
 * - Identity platforms
 * - Healthcare systems
 * - National-scale platforms
 */
