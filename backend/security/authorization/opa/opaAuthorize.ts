// // RIVER WEBSITE/backend/authorization/opa/opaAuthorize.ts

/** */

export async function opaAuthorize(request, reply) {
    const decision = await opaClient.decide({
      input: request.opaInput,
    });
  
    if (!decision.allow) {
      return reply.code(403).send({ message: "Access denied" });
    }
  }
  