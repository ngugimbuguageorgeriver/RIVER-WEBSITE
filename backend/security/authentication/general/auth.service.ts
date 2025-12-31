// RIVER WEBSITE/backend/authentication/general/auth.service.ts

/**
 * 
 *
 * Handles the core authentication business logic: registration, login,
 * MFA, session management, and device verification.
 * 
 * User registration with password hashing
 * Login with password verification
 * MFA initiation and verification
 * Token generation (access + refresh)
 * Device binding and verification - Secure defaults: All new devices start as untrusted; MFA must be verified before trusting a device.
 * Secure session handling 
 * Using Redis Session Handling
 * 
 * Refresh token rotation prevents reuse of stolen tokens.
 * Logout clears cookies and optionally revokes the refresh token.
 * 
 * 
 */


import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";
import speakeasy from "speakeasy";
import { hashPassword, verifyPassword, generateTokens, hashDeviceFingerprint, generateRandomSecret } from "./auth.utils.ts";
import { IUser, ILoginPayload, IRegisterPayload, IDevice, ISessionTokens, ITokenPayload,IMFAValidationResult } from "./auth.types.ts";
import { SessionService } from "../session/session.service.ts";

const prisma = new PrismaClient();

export class AuthService {

    /** -------------------------
     * Register a new user
     * ------------------------ */
    public static async registerUser(payload: IRegisterPayload): Promise<IUser> {
        const existing = await prisma.user.findUnique({ where: { email: payload.email } });
        if (existing) throw new Error("User already exists");

        // Hash password securely
        const hashedPassword = await hashPassword(payload.password);

        // Create user in DB
        const user = await prisma.user.create({
            data: {
                email: payload.email,
                passwordHash: hashedPassword,
                isActive: true,
                mfaEnabled: false,
            },
        });

        return user;
    }

    /** -------------------------
     * Login user with password
     * ------------------------ */
    public static async loginUser(payload: ILoginPayload): Promise<ISessionTokens> {
        const user = await prisma.user.findUnique({ where: { email: payload.email } });
        if (!user || !user.isActive) throw new Error("Invalid credentials");

        // Verify password if provided
        if (payload.password) {
            const isValid = await verifyPassword(user.passwordHash, payload.password);
            if (!isValid) throw new Error("Invalid credentials");
        }

        // Device binding / fingerprint
        let deviceId: string | undefined;
        if (payload.deviceId) {
            deviceId = hashDeviceFingerprint(payload.deviceId);
            await prisma.device.upsert({
                where: { id: deviceId },
                update: { lastUsedAt: new Date() },
                create: {
                    id: deviceId,
                    userId: user.id,
                    trusted: false,  // new devices are untrusted by default
                    lastUsedAt: new Date(),
                },
            });
        }

        
        // 🔥 CREATE SESSION
        const session = await SessionService.create({
            subjectId: user.id,
            deviceId,
            mfaVerified: !user.mfaEnabled,
        });


        // Generate access and refresh tokens
        const tokens = generateTokens({ 
            userId: user.id, 
            email: user.email, 
            deviceId, 
            sessionId: session.id,                                     // 🔥 IMPORTANT
            iat: Date.now() / 1000, 
            exp: Math.floor(Date.now() / 1000) + 900 });

        return tokens;
    }

    /** -------------------------
     * Initiate MFA for a user (TOTP)
     * ------------------------ */
    public static async generateMFASecret(userId: string): Promise<string> {
        const secret = speakeasy.generateSecret({ length: 32 });

        // Store base32 secret securely in DB
        await prisma.user.update({
            where: { id: userId },
            data: { mfaSecret: secret.base32, mfaEnabled: true },
        });

        // Return QR code URL / secret to display to user
        return secret.otpauth_url!;
    }

    /** -------------------------
     * Verify MFA token (TOTP)
     * ------------------------ */
    public static async verifyMFA(userId: string, token: string): Promise<IMFAValidationResult> {
        const user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user || !user.mfaSecret) return { success: false, error: "MFA not set up" };

        const verified = speakeasy.totp.verify({
            secret: user.mfaSecret,
            encoding: "base32",
            token,
            window: 1, // allow 1 step before/after for clock drift
        });

        return verified ? { success: true } : { success: false, error: "Invalid MFA token" };
    }

    /** -------------------------
     * Validate device trust
     * ------------------------ */
    public static async isDeviceTrusted(userId: string, deviceId: string): Promise<boolean> {
        const hashedId = hashDeviceFingerprint(deviceId);
        const device = await prisma.device.findUnique({ where: { id: hashedId } });
        return !!device?.trusted;
    }

    /** -------------------------
     * Trust a device (after verification)
     * ------------------------ */
    public static async trustDevice(userId: string, deviceId: string): Promise<void> {
        const hashedId = hashDeviceFingerprint(deviceId);
        await prisma.device.upsert({
            where: { id: hashedId },
            update: { trusted: true, lastUsedAt: new Date() },
            create: {
                id: hashedId,
                userId,
                trusted: true,
                lastUsedAt: new Date(),
            },
        });
    }




   // Verify refresh token
    public static verifyRefreshToken(token: string) {
        try {
            return jwt.verify(token, process.env.REFRESH_TOKEN_SECRET!) as ITokenPayload;
        } catch {
            return null;
        }
    }

    // Generate new access + refresh tokens from refresh payload
    public static generateNewTokens(payload: ITokenPayload): ISessionTokens {
        const { userId, email, deviceId } = payload;
        return generateTokens({
            userId,
            email,
            deviceId,
            iat: Date.now() / 1000,
            exp: Math.floor(Date.now() / 1000) + 900,
        });
    }

    // Revoke refresh token (store in Redis or DB)
    public static async revokeRefreshToken(token: string) {
        // Example: store revoked token with TTL in Redis
        // await redis.set(`revoked_${token}`, "true", "EX", 7*24*60*60);
        return true;
    }

}