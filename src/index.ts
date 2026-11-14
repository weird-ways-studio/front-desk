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
import { Desk, approvalPush, cronJob, headcountAlarm, phoneAlert } from "./desk.ts";
import type { VaultApi, VaultCardApi, VaultReachApi } from "../vault/src/api.ts";
import { recorderFrom } from "./recorder.ts";

interface Env extends AgentConfig {
  DESK: DurableObjectNamespace<FrontDesk>;
  // Set by Ben in the dashboard (kept across deploys by keep_vars). Unset = nobody is the owner.
  OWNER_EMAIL?: string;
  // The nightly headcount's healthchecks.io ping URL, set by Ben in the dashboard as a secret. The
  // c-box never holds it, so the c-box cannot send the all-clear. Unset = every night logs a failed alarm.
  HC_HEADCOUNT_URL?: string;
  // Pushover user key and app token (dashboard secrets, card a830d543): every push to Ben's phone -- one per
  // request (approvalPush), the headcount detail, and phone alerts. The only phone route (card W2 6d0acbc8).
  PUSHOVER_USER?: string;
  PUSHOVER_TOKEN?: string;
  // The Observatory's recorder (card 97a2e83d): its address is a dashboard variable (a live hostname,
  // kept out of this public repo); the service token's id and secret are dashboard secrets Ben pastes.
  // Any one unset = every request refused.
  RECORDER_URL?: string;
  RECORDER_CLIENT_ID?: string;
  RECORDER_CLIENT_SECRET?: string;
  // The vault Worker (vault/), reached only through this service binding (wrangler.jsonc "services").
  VAULT: Service & VaultApi & VaultCardApi & VaultReachApi;
}

export class FrontDesk extends DurableObject<Env> {
  async handle(request: Request, who: Who): Promise<Response> {
    const recorder = recorderFrom(this.env.RECORDER_URL, this.env.RECORDER_CLIENT_ID, this.env.RECORDER_CLIENT_SECRET);
    const phone = { user: this.env.PUSHOVER_USER, token: this.env.PUSHOVER_TOKEN };
    return route(request, this.ctx.storage, who, Date.now(), this.env.VAULT, approvalPush(phone), recorder, phoneAlert(phone));
  }
  // The nightly count runs in here too, so its log rows join the one log.
  async headcount(): Promise<void> {
    await new Desk(this.ctx.storage, { origin: "", rpID: "" }, { vault: this.env.VAULT }).headcount(headcountAlarm(this.env.HC_HEADCOUNT_URL, { user: this.env.PUSHOVER_USER, token: this.env.PUSHOVER_TOKEN }), Date.now());
  }
  // The nightly reach slice (card N2 5fdbf2ce), in here so its log line joins the one log.
  async reachNight(): Promise<void> {
    await new Desk(this.ctx.storage, { origin: "", rpID: "" }, { vault: this.env.VAULT, alert: phoneAlert({ user: this.env.PUSHOVER_USER, token: this.env.PUSHOVER_TOKEN }) }).reachNight(Date.now());
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
  // Cloudflare calls this on each schedule in wrangler.jsonc "triggers", with the expression that fired; cronJob
  // (src/desk.ts CRONS) picks the job: the reach slices at 03:47/03:52, the headcount at 04:17. Anything else runs nothing.
  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const job = cronJob(controller.cron);
    const desk = env.DESK.get(env.DESK.idFromName("desk"));
    if (job === "reach") ctx.waitUntil(desk.reachNight());
    else if (job === "headcount") ctx.waitUntil(desk.headcount());
  },
};
