/**
 * roleLifecycle.service.ts
 *
 * Responsible for role lifecycle management:
 * - assign roles
 * - remove roles
 * - automatic deprovisioning (on user termination)
 * - role expiry/JIT (just-in-time) expiry and scheduled removal
 *
 * This file focuses on logic; persistence happens via Prisma (or your DB/ORM).
 */

import { PrismaClient } from "@prisma/client";
import { UserRole } from "../roles/auth.roles.ts";
import { validateRoleAssignment } from "../sod/sod.service.ts";

const prisma = new PrismaClient();

/**
 * Assign roles to a user with SoD checks.
 * Optionally accept an expiry timestamp for JIT temporary roles.
 */
export async function assignRoles(userId: string, roles: UserRole[], options?: { expiresAt?: Date | null, grantedBy?: string }) {
  // Fetch existing roles (assumes a user_roles table many-to-many)
  const existing = await prisma.userRole.findMany({ where: { userId } });
  const existingRoles = existing.map(r => r.role as UserRole);

  // Validate SoD
  const validation = validateRoleAssignment(existingRoles, roles);
  if (!validation.allowed) throw new Error(`SoD violation: ${validation.errors?.join("; ")}`);

  // Upsert role entries, set expiresAt if provided
  for (const role of roles) {
    await prisma.userRole.upsert({
      where: { userId_role: { userId, role } },
      update: { expiresAt: options?.expiresAt || null, grantedBy: options?.grantedBy || null },
      create: { userId, role, expiresAt: options?.expiresAt || null, grantedBy: options?.grantedBy || null },
    });
  }

  // Optionally emit audit event (not implemented here - call audit.logger)
}

/**
 * Revoke roles immediately.
 */
export async function revokeRoles(userId: string, roles: UserRole[], revokedBy?: string) {
  for (const role of roles) {
    await prisma.userRole.deleteMany({ where: { userId, role } });
  }
  // Optionally log audit event
}

/**
 * Deprovision lifecycle: called when user is terminated/departed.
 * Removes all roles and optionally locks account.
 */
export async function deprovisionUser(userId: string) {
  await prisma.userRole.deleteMany({ where: { userId } });
  await prisma.user.update({ where: { id: userId }, data: { isActive: false } });
  // Audit and notify IAM / HR systems via webhooks if necessary.
}

/**
 * Periodic job: scan for expired JIT roles and remove them.
 * Should be invoked by a scheduler (cron / worker).
 */
export async function expireJITRoles() {
  const now = new Date();
  const expired = await prisma.userRole.findMany({ where: { expiresAt: { lt: now } } });
  for (const entry of expired) {
    await prisma.userRole.delete({ where: { id: entry.id } });
    // Emit audit event for each removal
  }
}
