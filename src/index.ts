// The front desk Worker. Cloudflare calls the default export's fetch() for every
// request (entry point set by `main` in wrangler.jsonc). All state lives in one
// Durable Object, FrontDesk, so requests are handled one at a time against one
// store -- that is what makes "approve once, collect once" hold. Routes: routes.ts.
//
// Who is calling comes from ctx.access, which Cloudflare fills in only after its
// Access login passed; a request cannot set it. Ben is recognised by his email
// (routes.ts callerOf); the agent by its service-token ticket, whose signature we
// check (agent.ts). ctx.access is not passed on to a Durable Object, so the Worker
// works out the caller here and hands it over as an RPC argument (never a header
// a request could carry).

import { DurableObject } from "cloudflare:workers";
import { agentOf, type AgentConfig } from "./agent.ts";
import { callerOf, route, type Who } from "./routes.ts";

interface Env extends AgentConfig {
  DESK: DurableObjectNamespace<FrontDesk>;
  // Set by Ben in the dashboard (kept across deploys by keep_vars). Unset = nobody is the owner.
  OWNER_EMAIL?: string;
}

export class FrontDesk extends DurableObject {
  async handle(request: Request, who: Who): Promise<Response> {
    return route(request, this.ctx.storage, who);
  }
}

async function whoIs(request: Request, env: Env, ctx: ExecutionContext): Promise<Who> {
  if ((await callerOf(ctx.access, env.OWNER_EMAIL)) === "owner") return { caller: "owner" };
  const agent = await agentOf(request, ctx.access, env);
  return agent.ok ? { caller: "agent", requester: agent.requester } : { caller: "unknown", why: agent.why };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return env.DESK.get(env.DESK.idFromName("desk")).handle(request, await whoIs(request, env, ctx));
  },
};
