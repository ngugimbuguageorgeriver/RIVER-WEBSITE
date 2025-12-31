Quick integration checklist (what to wire next)

Ensure request.user produced by your auth middleware contains:

            id, roles: string[], attributes (department, mfa, deviceTrustScore), and any context required by OPA.

            Deploy OPA server (or compile Rego to WASM) and load policy.rego. Set OPA_URL env var.

            Add Prisma UserRole model and run migration.

            Use enforce("ACTION_NAME") as preHandler on routes that need PBAC/ABAC evaluation.

            Hook roleLifecycle.expireJITRoles() to a scheduler (cron/worker).

            Integrate pam.service.requestJITElevation() into admin console flows, approval flows, or CLI tool.

            Forward audit.logger outputs to your SIEM or append-only store.





### How to compile Rego to WASM (commands & notes)

1. Install OPA ([https://www.openpolicyagent.org/docs/latest/#running-opa](https://www.openpolicyagent.org/docs/latest/#running-opa)).
2. Compile the policy to wasm:

```bash
opa build -t wasm -e authz/allow policy.rego
# This produces bundle.tar.gz and a wasm policy under ./bundle/policy.wasm (or similar path)
```

3. Copy the `.wasm` file into your service (e.g. `policies/authz.wasm`).
4. Load it at startup using `loadWasmPolicy(path.join(__dirname, '../../policies/authz.wasm'))`.

> Security note: keep the policy bundle and data under control and ensure integrity (signed bundles or run OPA as a trusted sidecar).

---

## 3) `protected.route.ts` (sample protected route demonstrating full flow)

```ts
// src/routes/protected.route.ts

import { FastifyInstance } from "fastify";
import { enforce } from "../authz/authorization.middleware";
import { requestJITElevation } from "../authz/pam.service";

export async function protectedRoutes(fastify: FastifyInstance) {
  // Example: endpoint to approve a payment. This requires PBAC enforcement for "APPROVE_PAYMENTS".
  fastify.post("/payments/:id/approve", { preHandler: [fastify.authenticate, enforce("APPROVE_PAYMENTS")] }, async (request, reply) => {
    const user = (request as any).user;
    const paymentId = (request.params as any).id;

    // At this point, enforce() either allowed via RBAC fast-path or OPA PBAC.
    // If this operation requires elevated session/JIT, you can trigger PAM flows here.

    // Example: request JIT elevation for higher privilege operations (if policy requires)
    if ((request as any).requiresJIT) {
      const { success, expiresAt } = await requestJITElevation(user.id, user.id, "FINANCE_ADMIN", 30);
      if (!success) return reply.code(500).send({ error: "Unable to obtain JIT elevation" });
      // Proceed with elevated operation and schedule revoke (expireJITRoles will also cleanup)
    }

    // Perform business logic: approve payment (placeholder)
    // await fastify.prisma.payment.update({ where: { id: paymentId }, data: { status: 'approved', approvedBy: user.id } });

    return reply.code(200).send({ message: `Payment ${paymentId} approved by ${user.id}` });
  });
}
```

---

## 4) Migration & Deployment Notes

1. **Prisma migration**: after adding models, run `npx prisma migrate dev --name add_userrole_audit` and verify generated SQL.
2. **Indexes**: ensure `userRole` queries are indexed on `userId` and `expiresAt` for TTL scans.
3. **OPA**: deploy OPA as a sidecar or central service. For low-latency path, use RBAC fast-path; only call OPA when necessary.
4. **WASM**: compiling policies to WASM reduces network calls and central dependency; however, updating policies requires redeploy or bundle hot-swap.
5. **Audit logs**: forward `AuditLog` model entries to your SIEM. Use append-only storage for compliance-critical logs (S3 with Object Lock or immutable DB).
6. **PAM**: integrate a real vault (HashiCorp Vault) and a session recording product if you require full session replay.

---

## Next Steps

1. Run migrations and seed a SUPER_ADMIN user and roles.
2. Deploy OPA (or compile WASM) and test the sample protected route.
3. Wire `request.user` population in your auth middleware to include `roles` and `attributes` used by OPA (department, deviceTrustScore, mfa, etc.).
4. Hook up `audit.logger.auditLog` to persist to `AuditLog` table (or push to SIEM).

If you want, I can now:

* implement the Prisma migration script and seed data file, or
* implement WASM runtime initialization example using `@open-policy-agent/opa-wasm` (note: requires installing the package), or
* implement the audit persistence adapter that writes `auditLog` entries into Prisma `AuditLog` model.

Which of those do you want next?
