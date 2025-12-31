Operational instructions (WASM)

Compile your policy.rego to WASM:
opa build -t wasm -e authz/allow policy.rego
This produces a bundle; extract policy.wasm and place under policies/authz.wasm.

Install an OPA WASM helper (recommended): if you prefer SDK, you can install @open-policy-agent/opa-wasm (or follow latest OPA docs) and replace the WASM loader/evaluator with the SDK calls — they will handle memory allocation, JSON marshalling, and evaluation.

For most teams: use HTTP OPA first (fast), then move to local WASM when you need zero-network decisions and low-latency.



npm install @open-policy-agent/opa-wasm bullmq ioredis
# already required: prisma @prisma/client pino node-fetch fastify argon2
```