// RIVER WEBSITE/backend/authentication/general/auth.controller.ts

/**
 * 
 *
 * Exposes authentication endpoints: registration, login, MFA, device trust.
 * Includes production-grade security: HttpOnly cookies, rate-limiting hooks, and secure error handling.
 * 
 * Registration
 * Login (with password and device binding)
 * MFA initiation and verification
 * Device trust management
 * Secure session handling via HttpOnly cookies
 * refresh token rotation and secure logout handling.
 * 
 * 
 */

import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { AuthService } from "./auth.service";
import { ILoginPayload, IRegisterPayload } from "./auth.types.ts";
import { rateLimiter } from "../../middleware/rateLimiter.middleware.ts";

export async function authRoutes(fastify: FastifyInstance) {

    /** -------------------------
     * User Registration Endpoint
     * ------------------------ */
    fastify.post<{ Body: IRegisterPayload }>("/register", async (request, reply) => {
        const { email, password } = request.body;

        try {
            const user = await AuthService.registerUser({ email, password });
            return reply.code(201).send({ message: "User registered successfully", userId: user.id });
        } catch (err: any) {
            return reply.code(400).send({ error: err.message });
        }
    });

    /** -------------------------
     * Login Endpoint
     * ------------------------ */
    fastify.post<{ Body: ILoginPayload }>("/login", { preHandler: rateLimiter }, async (request, reply) => {
        const { email, password, deviceId } = request.body;

        try {
            const tokens = await AuthService.loginUser({ email, password, deviceId });

            // Set HttpOnly, Secure, SameSite cookies for access and refresh tokens
            reply.setCookie("accessToken", tokens.accessToken, {
                httpOnly: true,
                secure: true,          // Only over HTTPS
                sameSite: "Strict",
                path: "/",
                maxAge: 15 * 60,       // 15 minutes
            });

            reply.setCookie("refreshToken", tokens.refreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: "Strict",
                path: "/auth/refresh",
                maxAge: 7 * 24 * 60 * 60, // 7 days
            });

            return reply.code(200).send({ message: "Login successful" });
        } catch (err: any) {
            return reply.code(401).send({ error: err.message });
        }
    });

    /** -------------------------
     * Initiate MFA (TOTP) Endpoint
     * ------------------------ */
    fastify.post<{ Body: { userId: string } }>("/mfa/setup", async (request, reply) => {
        const { userId } = request.body;

        try {
            const otpauthUrl = await AuthService.generateMFASecret(userId);
            return reply.code(200).send({ message: "MFA setup initiated", otpauthUrl });
        } catch (err: any) {
            return reply.code(400).send({ error: err.message });
        }
    });

    /** -------------------------
     * Verify MFA Endpoint
     * ------------------------ */
    fastify.post<{ Body: { userId: string, token: string } }>("/mfa/verify", async (request, reply) => {
        const { userId, token } = request.body;

        try {
            const result = await AuthService.verifyMFA(userId, token);
            if (!result.success) return reply.code(401).send({ error: result.error });

            return reply.code(200).send({ message: "MFA verified successfully" });
        } catch (err: any) {
            return reply.code(400).send({ error: err.message });
        }
    });

    /** -------------------------
     * Trust Device Endpoint
     * ------------------------ */
    fastify.post<{ Body: { userId: string, deviceId: string } }>("/device/trust", async (request, reply) => {
        const { userId, deviceId } = request.body;

        try {
            await AuthService.trustDevice(userId, deviceId);
            return reply.code(200).send({ message: "Device trusted successfully" });
        } catch (err: any) {
            return reply.code(400).send({ error: err.message });
        }
    });

    /** -------------------------
     * Check Device Trust Endpoint
     * ------------------------ */
    fastify.post<{ Body: { userId: string, deviceId: string } }>("/device/check", async (request, reply) => {
        const { userId, deviceId } = request.body;

        try {
            const trusted = await AuthService.isDeviceTrusted(userId, deviceId);
            return reply.code(200).send({ trusted });
        } catch (err: any) {
            return reply.code(400).send({ error: err.message });
        }
    });


    




    /** -------------------------
     * Refresh Token Endpoint
     * ------------------------ */
    fastify.post("/refresh", async (request: FastifyRequest, reply: FastifyReply) => {
        const refreshToken = request.cookies.refreshToken;

        if (!refreshToken) return reply.code(401).send({ error: "Refresh token missing" });

        try {
            const payload = AuthService.verifyRefreshToken(refreshToken);
            if (!payload) return reply.code(401).send({ error: "Invalid refresh token" });

            // Rotate refresh token
            const tokens = AuthService.generateNewTokens(payload);

            // Set rotated tokens as HttpOnly cookies
            reply.setCookie("accessToken", tokens.accessToken, {
                httpOnly: true,
                secure: true,
                sameSite: "Strict",
                path: "/",
                maxAge: 15 * 60,
            });
            reply.setCookie("refreshToken", tokens.refreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: "Strict",
                path: "/auth/refresh",
                maxAge: 7 * 24 * 60 * 60,
            });

            return reply.code(200).send({ message: "Token refreshed" });
        } catch (err: any) {
            return reply.code(401).send({ error: err.message });
        }
    });

    /** -------------------------
     * Logout Endpoint
     * ------------------------ */
    fastify.post("/logout", async (request: FastifyRequest, reply: FastifyReply) => {
        try {
            // Clear HttpOnly cookies
            reply.clearCookie("accessToken", { path: "/" });
            reply.clearCookie("refreshToken", { path: "/auth/refresh" });

            // Optional: revoke refresh token in DB / Redis if stored
            const refreshToken = request.cookies.refreshToken;
            if (refreshToken) await AuthService.revokeRefreshToken(refreshToken);

            return reply.code(200).send({ message: "Logged out successfully" });
        } catch (err: any) {
            return reply.code(400).send({ error: err.message });
        }
    });


}