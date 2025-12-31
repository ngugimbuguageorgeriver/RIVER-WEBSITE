// RIVER WEBSITE/backend/authentication/general/auth.types.ts

/**
 * 
 * 
 * Defines all TypeScript types and interfaces for authentication and identity.
 * Ensures type safety and clear contracts between controllers, services, and utils.
 * 
 * All user-sensitive fields (passwordHash, mfaSecret) are never exposed to the client.
 * ITokenPayload binds tokens optionally to devices for anti-replay protection.
 * ISessionTokens separates access and refresh tokens, enforcing rotation.
 * 
 */

export interface IUser {
    id: string;                    // Unique user identifier (UUID)
    email: string;                  // User email (used for login)
    passwordHash: string;           // Argon2id hashed password
    isActive: boolean;              // Account active status
    mfaEnabled: boolean;            // Indicates if MFA is required
    mfaSecret?: string;             // Base32 TOTP secret (optional)
    createdAt: Date;                // Account creation timestamp
    updatedAt: Date;                // Last profile update timestamp
}

export interface ILoginPayload {
    email: string;
    password?: string;              // Optional for passwordless login
    deviceId?: string;              // Optional device fingerprint
}

export interface IRegisterPayload {
    email: string;
    password: string;
}

export interface ITokenPayload {     // JWT will carry only sessionId
    userId: string;
    email: string;
    deviceId?: string;              // Bind token to a device for extra security
    sessionId: string;              // 🔥 NEW
    iat: number;                    // Issued at timestamp
    exp: number;                    // Expiration timestamp
}



export interface ISessionTokens {
    accessToken: string;            // Short-lived token for API access
    refreshToken: string;           // Rotating long-lived refresh token
}

export interface IDevice {
    id: string;                     // Device unique ID or fingerprint hash
    userId: string;                  // Owner user ID
    lastUsedAt: Date;                // Last login timestamp
    trusted: boolean;                // Has the device been approved?
}

export interface IMFAValidationResult {
    success: boolean;
    error?: string;
}
