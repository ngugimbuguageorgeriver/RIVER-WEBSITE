// RIVER WEBSITE/backend/src/tests/intergration/approve_payment.test.ts

/**
 * tests/integration/approve_payment.test.ts
 *
 * Simple integration test that exercises the APPROVE_PAYMENTS flow.
 * It expects:
 *  - Fastify server running at http://localhost:3000
 *  - OPA server running at http://localhost:8181 with policy loaded
 *
 * Run: `node --experimental-fetch tests/integration/approve_payment.test.ts`
 */

const BASE = process.env.BASE_URL || "http://localhost:3000";
const fetch = globalThis.fetch;

async function main() {
  // 1) Login with seeded SUPER_ADMIN credentials
  const loginRes = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: process.env.TEST_ADMIN_EMAIL || "superadmin@example.com", password: process.env.TEST_ADMIN_PASSWORD || "password" }),
    credentials: "include",
  });

  console.log("Login status:", loginRes.status);
  if (loginRes.status !== 200) {
    console.error(await loginRes.text());
    process.exit(1);
  }

  // Cookie handling in Node: extract Set-Cookie from response and include in subsequent requests
  const cookies = loginRes.headers.get('set-cookie');

  // 2) Attempt to approve a payment
  const paymentId = "test-payment-123";
  const approveRes = await fetch(`${BASE}/payments/${paymentId}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Cookie": cookies || "" },
  });

  console.log("Approve status:", approveRes.status);
  console.log(await approveRes.text());
}

main().catch(err => { console.error(err); process.exit(1); });