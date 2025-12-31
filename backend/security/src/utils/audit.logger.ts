// RIVER WEBSITE/backend/src/utils/audit.logger.ts

/**
 *
 * Structured audit logging for access decisions and privileged activity.
 * Writes to stdout (JSON) for collection by SIEM/Log aggregator or to an append-only store.
 *
 * Recommendation: forward logs to a write-once object store or SIEM with WORM support
 * for immutable audit trails (S3 with object lock, or a dedicated audit database).
 * 
 * 
 * Keep audit logs separate from regular logs and ensure strict retention and tamper-resistance.
 * Consider pushing logs to a WORM-enabled bucket or an immutable ledger if high compliance is required.
 * 
 */

import pino from "pino";

const auditLogger = pino({ level: process.env.AUDIT_LOG_LEVEL || "info", base: { service: "authz-audit" } });

export async function auditLog(entry: {
  user?: string | null;
  action: string;
  resource?: any;
  decision: "ALLOW" | "DENY" | "GRANTED" | "REVOKED";
  mechanism?: string;
  reason?: string;
  details?: any;
  request?: any; // optional Fastify request object; avoid logging sensitive headers
}) {
  // Normalize entry: drop sensitive attributes (e.g., tokens, full headers)
  const safeEntry = {
    ts: new Date().toISOString(),
    user: entry.user || null,
    action: entry.action,
    resource: entry.resource || null,
    decision: entry.decision,
    mechanism: entry.mechanism || null,
    reason: entry.reason || null,
    details: entry.details || null,
    request: entry.request ? {
      ip: entry.request.ip,
      url: entry.request.url,
      method: entry.request.method,
    } : null,
  };

  // Write as JSON structured log
  auditLogger.info(safeEntry);

  // Optionally forward to SIEM or persist to append-only storage
  // e.g., await forwardToSIEM(safeEntry);
}
