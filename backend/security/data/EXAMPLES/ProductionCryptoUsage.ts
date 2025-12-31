// RIVER WEBSITE/backend/security/data/security/EXAMPLES/ProductionCryptoUsage.ts



/**
 * ProductionCryptoUsage.ts
 *
 * =====================================================
 * ZERO → HERO OVERVIEW
 * =====================================================
 *
 * Objective:
 * - Demonstrate how a real service uses CryptoOrchestrator
 * - Show encryption, decryption, token handling, backups, and Merkle verification
 * - Highlight how cryptography protects real-world workflows
 *
 * Threats mitigated:
 * - Plaintext exposure in storage or logs
 * - Replay attacks
 * - Key misuse or accidental leakage
 * - Tampering with payloads or backups
 * - Improper crypto usage per data classification
 *
 * Usage:
 * - User data storage
 * - API payload encryption
 * - Backup and recovery operations
 * - Auditable cryptographic operations
 */

import { CryptoOrchestrator } from '../security/crypto/CryptoOrchestrator';
import { Buffer } from 'buffer';

const crypto = new CryptoOrchestrator();

async function main() {
  // ============================
  // STEP 1: Encrypt sensitive user data
  // ============================
  const userData = Buffer.from(JSON.stringify({
    userId: 'user_123',
    ssn: '123-45-6789',
    creditCard: '4111-1111-1111-1111',
    email: 'user@example.com'
  }));

  // Choose classification: public, internal, confidential, restricted
  const classification = 'restricted';

  // Encrypt data using orchestrator
  const { ciphertext, metadata } = crypto.encryptData(userData, classification);
  console.log('Encrypted user data:', ciphertext.toString('hex'));
  console.log('Encryption metadata:', metadata);

  // ============================
  // STEP 2: Decrypt user data safely
  // ============================
  const plaintext = crypto.decryptData(ciphertext, metadata, classification);
  console.log('Decrypted user data:', plaintext.toString());

  // ============================
  // STEP 3: Generate session token with nonce
  // ============================
  const sessionNonce = crypto.generateNonce();
  const sessionKey = crypto.generateEphemeralKey();
  console.log('Session nonce:', sessionNonce);
  console.log('Ephemeral session key (hex):', sessionKey.toString('hex'));

  // ============================
  // STEP 4: Anti-replay and payload integrity
  // ============================
  const payload = Buffer.from('Important API payload');
  const { ciphertext: payloadCipher, metadata: payloadMeta } = crypto.encryptData(payload, 'confidential');

  // Verify anti-replay when decrypting
  const decryptedPayload = crypto.decryptData(payloadCipher, payloadMeta, 'confidential');
  console.log('Decrypted payload:', decryptedPayload.toString());

  // ============================
  // STEP 5: Merkle root for audit / tamper-evidence
  // ============================
  const logEntries = [ciphertext, payloadCipher];
  const merkleRoot = crypto.createMerkleRoot(logEntries);
  console.log('Merkle root for audit logs:', merkleRoot);

  // ============================
  // STEP 6: Encrypt and handle backups securely
  // ============================
  const backupData = Buffer.from(JSON.stringify({
    users: [{ userId: 'user_123', data: '...encrypted...' }]
  }));

  const backup = crypto.encryptBackup(backupData);
  console.log('Encrypted backup:', backup.ciphertext.toString('hex'));
  console.log('Backup key shares (Shamir secret):', backup.keyShares);

  // After use, ephemeral keys and sensitive buffers are automatically zeroized
}

main().catch(err => {
  console.error('Crypto usage demo failed:', err);
});

/**
 * =====================================================
 * THREATS MITIGATED
 * =====================================================
 *
 * - Data exfiltration in databases or logs
 * - Replay attacks on API payloads
 * - Session key leakage
 * - Backup compromise without key shares
 * - Tampering with logs/audit data
 *
 * =====================================================
 * WHY PRODUCTION-GRADE
 * =====================================================
 *
 * - Classifies data and enforces correct crypto per sensitivity
 * - Uses ephemeral keys, nonces, and anti-replay
 * - Provides auditable encryption/decryption events
 * - Integrates Merkle root for tamper-evidence
 * - Implements Shamir Secret Sharing for secure backup recovery
 *
 * =====================================================
 * REGULATED SYSTEM USAGE
 * =====================================================
 *
 * - PCI DSS: Encrypt cardholder data, secure backups
 * - HIPAA: PHI encryption with classification mapping
 * - SOC2 / ISO 27001: Audit trails, key rotation, crypto governance
 */


