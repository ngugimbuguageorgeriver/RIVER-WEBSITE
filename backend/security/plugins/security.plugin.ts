// 

/**
 * Registering the Security Pipeline (Plugin)
 */

import fp from "fastify-plugin";
import { requireSession } from "../authentication/session/requireSession.hook";
import { enforceDeviceBinding } from "../authentication/session/deviceBinding.hook";

import { continuousAccessEvaluation } from "../authorization/cae/cae.hook";
import { riskThrottle } from "../authorization/throttling/riskThrottle.hook";
import { buildOpaInput } from "../authorization/opa/opaInput.hook";
import { opaAuthorize } from "../authorization/opa/opaAuthorize.hook";

export default fp(async (fastify) => {
  /**
   * 🔐 EARLY GUARDS (cheap, deterministic)
   */
  fastify.addHook("onRequest", requireSession);
  fastify.addHook("onRequest", enforceDeviceBinding);

  /**
   * 🧠 CONTINUOUS EVALUATION + POLICY
   */
  fastify.addHook("preHandler", continuousAccessEvaluation);
  fastify.addHook("preHandler", riskThrottle);
  fastify.addHook("preHandler", buildOpaInput);
  fastify.addHook("preHandler", opaAuthorize);
});
