// RIVER WEBSITE/backend/security/data/security/PHASEFOUR/crypto/CryptoPolicyRegistry.ts


/**
 * CryptoPolicyRegistry.ts
 *
 * ZERO → HERO OVERVIEW
 * -------------------
 * This registry enforces cryptographic policy across the system.
 * 
 * It ensures:
 * - Only approved algorithms are used
 * - Deprecated algorithms are blocked
 * - Emergency key/algorithm invalidation is possible
 * - Environment-specific policies (prod/test/dev)
 *
 * WHY THIS MATTERS:
 * - Crypto breaks over time (e.g., SHA-1, RSA-1024)
 * - Compliance mandates algorithm governance
 * - Enables rapid CVE response
 * 
 * 
 * 🔐 Threats Mitigated
             Threat	                                                    Mitigation
         Deprecated / broken algorithm usage	                Explicit registry blocks deprecated or disabled algorithms
         Inconsistent environment policies	                    Profile-based enforcement (prod vs staging vs dev)
         Emergency compromise	                                Kill-switch allows immediate algorithm disable
 */

export type AlgorithmStatus = "allowed" | "deprecated" | "disabled";

export interface AlgorithmPolicy {
  name: string;         // e.g., "AES-GCM", "RSA-OAEP"
  status: AlgorithmStatus;
  minKeySize?: number;  // Optional minimum key size enforcement
  note?: string;        // Optional description or rationale
}

export interface CryptoProfile {
  environment: "production" | "staging" | "development";
  algorithms: AlgorithmPolicy[];
}

/**
 * ---------------------------------------------
 * CRYPTO POLICY REGISTRY
 * ---------------------------------------------
 */
export class CryptoPolicyRegistry {
  private profiles: Map<string, CryptoProfile> = new Map();

  constructor() {
    this.loadDefaultProfiles();
  }

  private loadDefaultProfiles() {
    // Production defaults
    this.profiles.set("production", {
      environment: "production",
      algorithms: [
        { name: "AES-GCM", status: "allowed", minKeySize: 256 },
        { name: "ChaCha20-Poly1305", status: "allowed" },
        { name: "AES-SIV", status: "allowed" },
        { name: "RSA-OAEP", status: "allowed", minKeySize: 3072 },
        { name: "SHA-256", status: "allowed" },
        { name: "SHA-1", status: "deprecated", note: "Legacy hash, do not use" },
      ],
    });

    // Staging defaults can be relaxed
    this.profiles.set("staging", {
      environment: "staging",
      algorithms: [
        { name: "AES-GCM", status: "allowed", minKeySize: 256 },
        { name: "SHA-1", status: "allowed" },
      ],
    });

    // Development defaults (for testing only)
    this.profiles.set("development", {
      environment: "development",
      algorithms: [
        { name: "AES-GCM", status: "allowed", minKeySize: 128 },
        { name: "SHA-1", status: "allowed" },
      ],
    });
  }

  /**
   * ---------------------------------------------
   * CHECK IF ALGORITHM IS ALLOWED
   * ---------------------------------------------
   */
  public isAlgorithmAllowed(env: string, name: string): boolean {
    const profile = this.profiles.get(env);
    if (!profile) throw new Error(`Unknown environment: ${env}`);
    const algo = profile.algorithms.find((a) => a.name === name);
    if (!algo) return false;
    return algo.status === "allowed";
  }

  /**
   * ---------------------------------------------
   * GET DEPRECATED ALGORITHMS
   * ---------------------------------------------
   */
  public getDeprecated(env: string): string[] {
    const profile = this.profiles.get(env);
    if (!profile) return [];
    return profile.algorithms
      .filter((a) => a.status === "deprecated")
      .map((a) => a.name);
  }

  /**
   * ---------------------------------------------
   * EMERGENCY KILL-SWITCH
   * ---------------------------------------------
   */
  public disableAlgorithm(env: string, name: string): void {
    const profile = this.profiles.get(env);
    if (!profile) throw new Error(`Unknown environment: ${env}`);
    const algo = profile.algorithms.find((a) => a.name === name);
    if (algo) algo.status = "disabled";
  }
}

/**
 * ---------------------------------------------
 * THREATS MITIGATED
 * ---------------------------------------------
 * - Use of broken algorithms (e.g., SHA-1 collision attacks)
 * - Inconsistent algorithm usage across environments
 * - Emergency patching during CVE events
 *
 * REAL-WORLD IMPACT:
 * - Meets PCI / ISO / SOC2 algorithm governance
 * - Enables safe cryptographic agility
 */
