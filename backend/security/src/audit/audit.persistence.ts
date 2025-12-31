// RIVER WEBSITE/backend/src/audit/audit.persistence.ts

/**
 * This adapter writes audit entries to the AuditLog Prisma model and emits structured Pino logs. 
 * It provides a single persistAudit function you can call from your middleware.
 *
 * Persist structured audit logs into Prisma's AuditLog table and also emit pino logs.
 * Ensures append-only writes and indexes for searching by actorId.
 *
 * Use this inside your `audit.logger.auditLog` or call directly from middlewares.
 */

import pino from "pino";
import { PrismaClient } from "@prisma/client";
import { enqueueAudit } from "./audit.queue";

const auditLogger = pino({ level: process.env.AUDIT_LOG_LEVEL || "info", base: { service: "audit-persistence" } });
const prisma = new PrismaClient();

/**
 * Persist an audit log entry.
 *
 * The function writes a structured log record to:
 *  1) Prisma AuditLog table (append-only semantics at DB level)
 *  2) Pino structured logger (stdout) for immediate collection by SIEM/log aggregator
 *
 * The DB write is kept compact; heavy `details` should be stored in an object store and a reference kept in the DB.
 */
export async function persistAudit(entry: {
  actorId?: string | null;
  action: string;
  resource?: any;
  decision: "ALLOW" | "DENY" | "GRANTED" | "REVOKED";
  details?: any;
}) {
  try {
    // Normalize small details to store in DB (avoid storing huge blobs)
    const dbDetails = entry.details && JSON.stringify(entry.details).length < 10000 ? entry.details : { note: "details truncated or stored externally" };

    // Emit structured log for SIEM
    auditLogger.info({
      ts: new Date().toISOString(),
      actorId: entry.actorId || null,
      action: entry.action,
      resource: entry.resource || null,
      decision: entry.decision,
      details: entry.details || null,
    }, "audit_event");

    // Persist to DB
    await prisma.auditLog.create({
      data: {
        actorId: entry.actorId || null,
        action: entry.action,
        resource: entry.resource ? entry.resource as any : null,
        decision: entry.decision,
        details: dbDetails as any,
      },
    });

  } catch (err) {
    // If DB persistence fails, still emit a pino error for operator attention.
    auditLogger.error({ err, actorId: entry.actorId, action: entry.action }, "Failed to persist audit entry");
    // Note: Do not throw — auditing must not block the request path in prod. Consider a dead-letter queue for retries.
  }
}
