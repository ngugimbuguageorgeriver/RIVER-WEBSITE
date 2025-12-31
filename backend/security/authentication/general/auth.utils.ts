// RIVER WEBSITE/backend/authentication/general/auth.utils.ts

/**
 * 
 * 
 * Authentication utility functions: password hashing, token generation, verification,
 * device fingerprint hashing, and secure random secret generation.
 * 
 * Argon2id configured with high memory and iteration for production-grade password hashing.
 * Tokens are short-lived (access) and long-lived (refresh) with rotation strategy.
 * Device fingerprint hashed before storing to protect user privacy.
 * All sensitive secrets rely on environment variables. Never hardcode.
 * 
 */

import argon2 from "argon2";
import { randomBytes } from "crypto";
import jwt from "jsonwebtoken";
import { ITokenPayload, ISessionTokens } from "./auth.types.ts";

/** ------------------------------
 * Password Hashing
 * -------------------------------
 */

/**
 * Hash a plaintext password using Argon2id.
 * Configured for production-grade memory and iterations.
 */
export async function hashPassword(password: string): Promise<string> {
    return await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 2 ** 16,     // 64 MB
        timeCost: 4,             // Iterations
        parallelism: 2,          // Parallel threads
    });
}

/**
 * Verify a plaintext password against an Argon2 hash.
 */
export async function verifyPassword(hash: string, password: string): Promise<boolean> {
    try {
        return await argon2.verify(hash, password);
    } catch (err) {
        // Do not leak internal errors; return false on failure
        return false;
    }
}

/** ------------------------------
 * JWT / Token Utilities
 * -------------------------------
 */

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET!;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET!;

/**
 * Generate access and refresh tokens for a user.
 * Tokens can optionally bind to deviceId.
 */
export function generateTokens(payload: ITokenPayload): ISessionTokens {
    const accessToken = jwt.sign(payload, ACCESS_TOKEN_SECRET, {
        expiresIn: "15m", // Short-lived access token
    });

    const refreshToken = jwt.sign(payload, REFRESH_TOKEN_SECRET, {
        expiresIn: "7d",  // Long-lived refresh token
    });

    return { accessToken, refreshToken };
}

/**
 * Verify JWT and return payload or null if invalid.
 */
export function verifyToken(token: string, type: "access" | "refresh" = "access"): ITokenPayload | null {
    try {
        const secret = type === "access" ? ACCESS_TOKEN_SECRET : REFRESH_TOKEN_SECRET;
        return jwt.verify(token, secret) as ITokenPayload;
    } catch (err) {
        return null;
    }
}

/** ------------------------------
 * Device & Misc Utilities
 * -------------------------------
 */

/**
 * Generate a cryptographically secure random string (for deviceId or MFA secrets)
 */
export function generateRandomSecret(length: number = 32): string {
    return randomBytes(length).toString("hex");
}

/**
 * Hash device fingerprint before storage (prevents plaintext device info leaks)
 */
import crypto from "crypto";

export function hashDeviceFingerprint(fingerprint: string): string {
    return crypto.createHash("sha256").update(fingerprint).digest("hex");
}
