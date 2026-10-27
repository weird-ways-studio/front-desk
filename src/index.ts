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
import { Desk, approvalPush, headcountAlarm } from "./desk.ts";
import type { VaultApi } from "../vault/src/api.ts";

interface Env extends AgentConfig {
  DESK: DurableObjectNamespace<FrontDesk>;
  // Set by Ben in the dashboard (kept across deploys by keep_vars). Unset = nobody is the owner.
  OWNER_EMAIL?: string;
  // The nightly headcount's healthchecks.io ping URL, set by Ben in the dashboard as a secret. The
  // c-box never holds it, so the c-box cannot send the all-clear. Unset = every night logs a failed alarm.
  HC_HEADCOUNT_URL?: string;
  // ntfy topic URL (dashboard secret): the mismatch detail push, and one push per request (approvalPush).
  NTFY_TOPIC_URL?: string;
  // The vault Worker (vault/), reached only through this service binding (wrangler.jsonc "services").
  VAULT: Service & VaultApi;
}

export class FrontDesk extends DurableObject<Env> {
  async handle(request: Request, who: Who): Promise<Response> {
    return route(request, this.ctx.storage, who, Date.now(), this.env.VAULT, approvalPush(this.env.NTFY_TOPIC_URL));
  }
  // The nightly count runs in here too, so its log rows join the one log.
  async headcount(): Promise<void> {
    await new Desk(this.ctx.storage, { origin: "", rpID: "" }, { vault: this.env.VAULT }).headcount(headcountAlarm(this.env.HC_HEADCOUNT_URL, this.env.NTFY_TOPIC_URL), Date.now());
  }
}

/** Owner first (Ben's email), then the agent (verified service-token ticket), else unknown with the reason. */
async function whoIs(request: Request, env: Env, ctx: ExecutionContext): Promise<Who> {
  if ((await callerOf(ctx.access, env.OWNER_EMAIL)) === "owner") return { caller: "owner" };
  const agent = await agentOf(request, ctx.access, env);
  return agent.ok ? { caller: "agent", requester: agent.requester } : { caller: "unknown", why: agent.why };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return env.DESK.get(env.DESK.idFromName("desk")).handle(request, await whoIs(request, env, ctx));
  },
  // Cloudflare calls this on the schedule in wrangler.jsonc "triggers" (the nightly headcount).
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(env.DESK.get(env.DESK.idFromName("desk")).headcount());
  },
};
