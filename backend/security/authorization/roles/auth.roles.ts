// RIVER WEBSITE/backend/authorization/roles/auth.roles.ts

/**
 * 
 *
 * Defines all user roles for RBAC (Role-Based Access Control).
 * Roles can be hierarchical or flat depending on system needs.
 * 
 * UserRole - defines all roles in the system.
 * RoleHierarchy - allows automatic inheritance if needed (optional).
 * 
 * Enhanced RBAC definitions: hierarchical roles, Separation of Duties (SoD) rules,
 * utility functions to compute effective permissions, and role metadata.
 *
 * Keep this file authoritative for role & permission definitions across the app.
 */

export enum UserRole {                // short for enumeration -> A fixed list of named values.
  SUPER_ADMIN = "SUPER_ADMIN",             // Full system control
  ADMIN = "ADMIN",                         // General administration
  SECURITY_ADMIN = "SECURITY_ADMIN",       // Security & access oversight
  FINANCE_ADMIN = "FINANCE_ADMIN",         // Financial operations
  OPERATOR = "OPERATOR",                   // Daily system operations
  DEVELOPER = "DEVELOPER",                 // Code deployment & development
  AUDITOR = "AUDITOR",                     // Read-only audit access
  USER = "USER",                           // Normal application user
  GUEST = "GUEST",                         // Unauthenticated or limited access
}

/**
 * Permissions used by the system.
 * Extend this union as features are added.
 */
export type Permission =
  | "READ_USERS"
  | "WRITE_USERS"
  | "DELETE_USERS"
  | "MANAGE_ROLES"
  | "READ_FINANCIALS"
  | "APPROVE_PAYMENTS"
  | "DEPLOY_CODE"
  | "READ_AUDIT_LOGS"
  | "START_PRIVILEGED_SESSION"
  | "END_PRIVILEGED_SESSION"
  | "READ_CONTENT"
  | "WRITE_CONTENT";

/**
 * Static mapping of role -> direct permissions.
 * Keep minimal and prefer policy evaluation for complex rules.
 */
export const RolePermissions: Record<UserRole, Permission[]> = {    

  // Record is a built-in TypeScript utility type -> Record<K, V>  ->  “An object where: every key is of type K, every value is of type V”
  // 

  SUPER_ADMIN: ["READ_USERS", "WRITE_USERS", "DELETE_USERS", "MANAGE_ROLES", "READ_FINANCIALS", "APPROVE_PAYMENTS", "DEPLOY_CODE", "READ_AUDIT_LOGS", "START_PRIVILEGED_SESSION", "END_PRIVILEGED_SESSION", "READ_CONTENT", "WRITE_CONTENT"],
  ADMIN: ["READ_USERS", "WRITE_USERS", "MANAGE_ROLES", "DEPLOY_CODE", "READ_CONTENT", "WRITE_CONTENT"],
  SECURITY_ADMIN: ["READ_USERS", "READ_AUDIT_LOGS", "START_PRIVILEGED_SESSION", "END_PRIVILEGED_SESSION"],
  FINANCE_ADMIN: ["READ_FINANCIALS", "APPROVE_PAYMENTS"],
  OPERATOR: ["READ_CONTENT", "WRITE_CONTENT"],
  DEVELOPER: ["DEPLOY_CODE", "READ_CONTENT", "WRITE_CONTENT"],
  AUDITOR: ["READ_AUDIT_LOGS", "READ_USERS"],
  USER: ["READ_CONTENT", "WRITE_CONTENT"],
  GUEST: ["READ_CONTENT"],
};

/**
 * Role hierarchy: each role inherits permissions from listed child roles.
 * Use to compute effective permissions without duplicating lists.
 */
export const RoleHierarchy: Record<UserRole, UserRole[]> = {
  SUPER_ADMIN: [UserRole.ADMIN, UserRole.SECURITY_ADMIN, UserRole.FINANCE_ADMIN, UserRole.DEVELOPER, UserRole.AUDITOR, UserRole.OPERATOR, UserRole.USER],
  ADMIN: [UserRole.DEVELOPER, UserRole.OPERATOR, UserRole.USER],
  SECURITY_ADMIN: [],
  FINANCE_ADMIN: [],
  OPERATOR: [UserRole.USER],
  DEVELOPER: [UserRole.USER],
  AUDITOR: [],
  USER: [],
  GUEST: [],
};

/**
 * Separation of Duties (SoD) rules -> Some roles are too powerful or dangerous when combined, so one person must not have both.
 * Each rule states incompatible role combinations; if a user has role A they cannot be assigned role B.
 * This is enforced at role assignment time (via sod.service.ts).
 * This code defines a strictly typed list of forbidden role combinations (Separation of Duties rules) to prevent conflicts of interest and privilege abuse at role assignment time.
 */
export const SoDRules: Array<{ role: UserRole; incompatibleWith: UserRole[]; reason?: string }> = [
  // Array<...> -> SoDRules is a list (array) of objects

  { role: UserRole.FINANCE_ADMIN, incompatibleWith: [UserRole.DEVELOPER], reason: "Finance admins cannot have code deployment privileges" },
  { role: UserRole.FINANCE_ADMIN, incompatibleWith: [UserRole.SECURITY_ADMIN], reason: "Separation between finance and security duties" },
  { role: UserRole.DEVELOPER, incompatibleWith: [UserRole.AUDITOR], reason: "Developer should not audit their own work" }, // classic compliance rule (SOX, ISO, SOC2)
  { role: UserRole.SUPER_ADMIN, incompatibleWith: [], reason: "Super admin has broad privileges" },
];

/**
 * Compute effective permissions for a role including hierarchically inherited permissions.
 */
export function computeEffectivePermissions(role: UserRole): Permission[] {
  const visited = new Set<UserRole>();  // Think of this as A notebook where we write down which roles we’ve already looked at.
  const results = new Set<Permission>();

  function walk(r: UserRole) {     // walk the role tree
    if (visited.has(r)) return;    // Rule 1 of REcursion: Stop condition (base case) -> Prevents infinite loops, duplicate work, against circular inheritance
    visited.add(r);                // Rule 2: Do work for the current role
    const perms = RolePermissions[r] || [];
    perms.forEach(p => results.add(p));

    // Rule 3: Recursive step (this is the recursion)
    const children = RoleHierarchy[r] || [];    
    for (const c of children) walk(c);
  }

  walk(role);           // Recursion -> The moment recursion starts
  return Array.from(results);
}

/**
 * Utility: check if a set of roles violates SoD rules.
 */

export function violatesSoD(roles: UserRole[]): { violates: boolean; details: string[] } {
  const details: string[] = [];

  for (const rule of SoDRules) {
    if (roles.includes(rule.role)) {
      for (const incompatible of rule.incompatibleWith) {
        if (roles.includes(incompatible)) {
          details.push(`Role ${rule.role} incompatible with ${incompatible}${rule.reason ? `: ${rule.reason}` : ""}`);
        }
      }
    }
  }

  return { violates: details.length > 0, details };
}
