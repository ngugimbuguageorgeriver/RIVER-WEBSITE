// RIVER WEBSITE/backend/authorization/sessions/session.revocation.ts

/** */

/**
 * Session Revocation Service -> Revoking sessions does not magically kill HTTP connections.
 *
 * Purpose:
 * - Force logout
 * - Invalidate active sessions
 * - Enforce least privilege after entitlement or risk changes
 *
 * This layer NEVER decides authorization.
 * It enforces termination only.
 */

import { SessionService } from "../../authentication/session/session.service.ts";
import { audit } from "../audit/audit.service";           //🎁

/**
 * Revoke ALL sessions for a subject (user/service). -> (instant kill)
 * Used when:
 * - Entitlements revoked
 * - Account compromised
 * - Offboarding
*/

export async function revokeSessionsForSubject(subjectId: string) {
    await SessionService.revokeAllForSubject(subjectId);

    await audit.log({
        action: "SESSIONS_REVOKED_SUBJECT",
        actorId: subjectId,
        metadata: {
          subjectId,
        },
      });



}


/**
 * Revoke a single session (used by Risk Engine) -> Used for high-risk termination
 */

export async function revokeSession(sessionId: string) {
    await SessionService.revoke(sessionId);
}


