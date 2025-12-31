// RIVER WEBSITE/backend/authorization/audit/authz-audit.service.ts

/**
 * Purpose
        * Persist authorization decisions
        * Guarantee write-once semantics
        * Emit SIEM-ready events
        * Never throw (auditing must not break prod traffic)
 */


/**
 * Authorization Audit Service
 *
 * Fail-safe, non-blocking audit logging.
 * Authorization MUST continue even if audit sinks fail.
 */

import { prisma } from "../../infra/prisma";                        //🎁
import { AuthzAuditRecord } from "./authz-audit.model.ts";

export class AuthzAuditService {
  static async record(record: AuthzAuditRecord): Promise<void> {
    try {
      await prisma.authzAudit.create({
        data: {
          ...record,
          roles: JSON.stringify(record.roles),
          entitlements: JSON.stringify(record.entitlements),
        },
      });
    } catch (err) {
      /**
       * ABSOLUTE RULE:
       * Auditing failures MUST NEVER block authorization.
       *
       * Errors should be surfaced via metrics/logs only.
       */
      console.error("AUTHZ_AUDIT_FAILURE", err);
    }
  }
}
