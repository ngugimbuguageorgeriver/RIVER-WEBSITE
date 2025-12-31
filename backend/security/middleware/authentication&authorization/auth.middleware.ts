// RIVER WEBSITE/backend/middleware/authentication&authorization/auth.middleware.ts


/**
 * auth.middleware.ts
 *
 * Middleware to enforce authentication and authorization.
 * - Validates JWT and session
 * - Checks role and permission
 * - Prevents unauthorized access
 * 
 * 
 * isAuthenticated - verifies JWT access token.
 * hasPermission - checks the user’s role against permissions.
 * Both can be used in Fastify routes with preHandler hooks.
 * 
 * 
 */

import { FastifyReply, FastifyRequest } from "fastify";
import { verifyToken } from "../../authentication/general/auth.utils.ts";
import { RolePermissions } from "../../authorization/roles/auth.roles.ts";
import { IUser } from "../../authentication/general/auth.types.ts";
import { SessionService } from "../../authentication/session/session.service.ts";

/**
 * Middleware to check if user is authenticated -> JWT + SESSION CHECK
 */
export async function isAuthenticated(request: FastifyRequest, reply: FastifyReply) {
    const token = request.cookies.accessToken;
    if (!token) return reply.code(401).send({ error: "Access token missing" });

    const payload = verifyToken(token, "access");
    if (!payload) return reply.code(401).send({ error: "Invalid or expired access token" });

    // Session
    const session = await SessionService.get(payload.sessionId);
    if (!session) {
        return reply.code(401).send({ error: "Session expired" });
    }

    if (session.revokedAt) {              //  🔥 This is force re-authentication
        return reply.code(401).send({ error: "Session revoked. Re-authenticate." });
    }

    // Attach full context
    (request as any).user = payload;
    (request as any).session = session;

    return;
}

/**
 * Middleware to check if user has required permission
 * @param permission Required permission string
 */
export function hasPermission(permission: string) {
    return async (request: FastifyRequest, reply: FastifyReply) => {
        const user = (request as any).user as IUser & { role: string };
        if (!user) return reply.code(401).send({ error: "User not authenticated" });

        const allowed = RolePermissions[user.role as keyof typeof RolePermissions] || [];
        if (!allowed.includes(permission)) {
            return reply.code(403).send({ error: "Forbidden: insufficient permissions" });
        }

        return;
    };
}
