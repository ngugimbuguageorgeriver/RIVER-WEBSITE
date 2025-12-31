//

/**
 * prisma/seed.ts
 *
 * Seed script for initial data:
 * - creates a SUPER_ADMIN user (email, hashed password)
 * - assigns SUPER_ADMIN role in UserRole table
 *
 * Run with: `ts-node --project tsconfig.json prisma/seed.ts` (or compile + node)
 *
 * IMPORTANT: ensure you already ran prisma migrate to create the tables:
 *   npx prisma migrate deploy
 * 
 * Run this only on a trusted environment. If you used a generated admin password, store it safely in your secret manager and rotate it after first login.
 * If you want the seed script to create additional roles / test users, extend as needed.
 * Ensure prisma models (User, UserRole) exist and migrations have been applied before running.
 *
 * Required env:
 *  - DATABASE_URL
 *  - ADMIN_EMAIL (optional override)
 *  - ADMIN_PASSWORD (optional override; if not provided will generate a secure random password and print it)
 */

import { PrismaClient } from "@prisma/client";
import { randomBytes } from "crypto";
import { hashPassword } from "../authentication/general/auth.utils.ts"; // adjust path if needed

const prisma = new PrismaClient();

async function main() {
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "superadmin@example.com";
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || randomBytes(12).toString("base64").slice(0, 16);

  console.log("Seeding SUPER_ADMIN account:");
  console.log("  email:", ADMIN_EMAIL);
  console.log("  generated_password (store this safely):", ADMIN_PASSWORD);

  // Check if user exists
  let user = await prisma.user.findUnique({ where: { email: ADMIN_EMAIL } });
  if (!user) {
    const passwordHash = await hashPassword(ADMIN_PASSWORD);

    user = await prisma.user.create({
      data: {
        email: ADMIN_EMAIL,
        passwordHash,
        isActive: true,
        mfaEnabled: false,
      },
    });

    console.log("Created user id:", user.id);
  } else {
    console.log("User already exists, id:", user.id);
  }

  // Upsert SUPER_ADMIN role record
  await prisma.userRole.upsert({
    where: { userId_role: { userId: user.id, role: "SUPER_ADMIN" } },
    update: {},
    create: {
      userId: user.id,
      role: "SUPER_ADMIN",
      grantedBy: "seed-script",
    },
  });

  console.log("Assigned SUPER_ADMIN role to user:", user.id);

  // Optionally return created user id for downstream actions
  return user;
}

main()
  .then(async (u) => {
    console.log("Seed completed.");
    await prisma.$disconnect();
  })
  .catch(async (err) => {
    console.error("Seed failed:", err);
    await prisma.$disconnect();
    process.exit(1);
  });
