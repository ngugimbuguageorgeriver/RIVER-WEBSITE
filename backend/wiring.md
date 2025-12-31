onRequest
  → JWT verify
  → requireSession
  → enforceDeviceBinding

preHandler
  → Continuous Access Evaluation (CAE)
  → Risk-based throttling
  → OPA input construction
  → OPA authorization

handler
  → Business logic


2️⃣ Where Each Piece Goes (Fastify-native)
Concern	Fastify Hook
JWT verification	onRequest
Redis session lookup	onRequest
Device binding	onRequest
CAE (risk calc)	preHandler
Throttling	preHandler
OPA input	preHandler
Authorization	preHandler

Why?

onRequest = cheap, early rejection

preHandler = context-aware enforcement

Hooks replace middleware
Plugins replace stacks
Order defines trust
Redis is authority
OPA is judge