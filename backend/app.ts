// RIVER WEBSITE/backend/server.ts


/**
 * All failed login attempts are logged for monitoring.
 * Can later integrate ELK, Datadog, or Grafana.
 * Logs are structured JSON for SIEM ingestion.
 * 
 * 
 */


import Fastify from "fastify";
import { FastifyInstance } from "fastify";
import cookie from "@fastify/cookie";
import { authRoutes } from "./authentication/general/auth.controller.ts";
import { isAuthenticated, hasPermission } from "./middleware/authentication&authorization/auth.middleware.ts";
import pino from "pino";

import securityPlugin from "./plugins/security.plugin";

const logger = pino({ level: process.env.LOG_LEVEL || "info" });

const fastify = Fastify({ logger });

fastify.register(cookie);

// Register auth routes
fastify.register(authRoutes, { prefix: "/auth" });

// Authentication & Permission
/**
 * RBAC is fully declarative and easy to extend.
 * Per-route preHandler ensures authentication + authorization.
 * Can combine with rate-limiting, logging, and MFA checks for critical endpoints.
 */
export async function userRoutes(fastify: FastifyInstance) {

    // Read all users - only ADMIN or SUPER_ADMIN
    fastify.get("/users", { preHandler: [isAuthenticated, hasPermission("READ_USERS")] }, async (request, reply) => {
        // Fetch users from DB
        const users = await fastify.prisma.user.findMany();
        return users;
    });

    // Delete a user - only SUPER_ADMIN
    fastify.delete("/users/:id", { preHandler: [isAuthenticated, hasPermission("DELETE_USERS")] }, async (request, reply) => {
        const id = (request.params as any).id;
        await fastify.prisma.user.delete({ where: { id } });
        return { message: "User deleted successfully" };
    });
}


// Log suspicious login attempts
fastify.addHook("onResponse", async (request, reply) => {
    if (request.url.includes("/login") && reply.statusCode === 401) {
        logger.warn({ ip: request.ip, url: request.url }, "Failed login attempt detected");
    }
});

fastify.listen({ port: 3000 }, (err, address) => {
    if (err) {
        logger.error(err);
        process.exit(1);
    }
    logger.info(`Server running at ${address}`);
});



// continuousAccessEvaluation
app.use(requireSession, continuousAccessEvaluation);



const app = Fastify();

/**
 * PUBLIC ROUTES
 */
app.register(import("./routes/auth.routes"), {
  prefix: "/auth",
});

/**
 * 🔐 PROTECTED ROUTES - 🚨 Anything registered after securityPlugin is protected.
 */
app.register(securityPlugin);

app.register(import("./routes/users.routes"), {
  prefix: "/api/users",
});

app.register(import("./routes/admin.routes"), {
  prefix: "/api/admin",
});

export default app;

