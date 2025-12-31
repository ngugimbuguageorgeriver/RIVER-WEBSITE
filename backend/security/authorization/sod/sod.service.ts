// RIVER WEBSITE/backend/authorization/sod/permissions.ts

/**
 * 
 *
 * Maps roles to allowed actions/resources.
 * Can be extended to per-resource or field-level permissions.
 * 
 * Each role maps to a set of permissions.
 * Can later extend to dynamic resource-based permissions.
 * 
 * 
 * Separation-of-Duties enforcement service.
 * Used at role assignment time to prevent giving users conflicting roles.
 */

import { UserRole, violatesSoD } from "../roles/auth.roles.ts";

/**
 * Validate role assignment against SoD rules.
 * - called whenever roles are changed/assigned
 * - returns clear errors for UI/automated workflows
 */
export function validateRoleAssignment(existingRoles: UserRole[], rolesToAdd: UserRole[]): { allowed: boolean; errors?: string[] } {
  const newRoles = Array.from(new Set([...existingRoles, ...rolesToAdd]));
  const sod = violatesSoD(newRoles);
  if (sod.violates) return { allowed: false, errors: sod.details };
  return { allowed: true };
}
