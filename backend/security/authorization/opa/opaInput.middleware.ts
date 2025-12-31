// RIVER WEBSITE/backend/authorization/opa/opa.cache.ts

/**
 * OPA sees pure JSON — no Fastify coupling.
 * 
 * app.use(buildOpaInput);
   app.use(opaAuthorize);

 */

export function buildOpaInput(request, reply) {
    const session = request.session;
    const tenant = request.tenant; // loaded earlier (important)
  
    request.opaInput = {
      tenant: {
        id: request.session.tenantId,
        plan: tenant.plan,
        throttled: tenant.isThrottled,
      },
      subject: {
        id: request.session.subjectId,
        mfa_verified: request.session.mfaVerified,
      },
      risk: {
        riskLevel: request.session.riskLevel,
      },
      resource: request.resource,
      action: request.action,
    };
  
    
  }
  

