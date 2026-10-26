// The front desk's HTTP routes, kept apart from the Durable Object (index.ts)
// so tests can drive them with an in-memory store.

import { Desk, DeskError, type Store } from "./desk.ts";
import { approvePage, enrollPage, logPage } from "./page.ts";

export const VERSION = "0.4.0-agent-identity";

// Who is calling, worked out by the Worker from Cloudflare Access (index.ts):
// owner from Ben's email (callerOf), agent from the service-token ticket (agent.ts).
export type Caller = "owner" | "agent" | "unknown";
// requester: who asked, from the verified identity (agent only). why: why the agent check failed, for the log.
export interface Who {
  caller: Caller;
  requester?: string;
  why?: string;
}

// Owner = the email Access signed in matches OWNER_EMAIL. Anything missing or failing = unknown.
export async function callerOf(access: ExecutionContext["access"], ownerEmail: string | undefined): Promise<Caller> {
  if (!access || !ownerEmail) return "unknown";
  // Promise.try-style wrap: a synchronous throw or odd return also ends as "unknown".
  const who = await Promise.resolve()
    .then(() => access.getIdentity())
    .catch(() => undefined);
  const email = typeof who?.email === "string" ? who.email.trim().toLowerCase() : "";
  return email && email === ownerEmail.trim().toLowerCase() ? "owner" : "unknown";
}

// Which caller each route needs. Ben enrolls, approves and reads the log; the agent asks and collects.
function needs(m: string, parts: string[]): Caller | null {
  if (parts[0] === "enroll" || parts[0] === "approve" || parts[0] === "log") return "owner";
  if ((m === "POST" && parts[0] === "request") || parts[0] === "collect") return "agent";
  return null;
}

export function securityHeaders(nonce = ""): Record<string, string> {
  return {
    "x-robots-tag": "noindex, nofollow",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "content-security-policy": `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`,
  };
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: securityHeaders() });
}

function html(body: string, nonce: string): Response {
  return new Response(body, { headers: { ...securityHeaders(nonce), "content-type": "text/html; charset=utf-8" } });
}

// A passkey answer that is not JSON is refused and logged, like any other failed tap.
async function body<T>(request: Request, desk: Desk, what: string, now: number): Promise<T> {
  try {
    return (await request.json()) as T;
  } catch {
    await desk.refuse(`${what}: bad_json`, now);
    throw new DeskError("bad_json", 400);
  }
}

// The routes, kept apart from the Durable Object so tests can drive them.
export async function route(request: Request, store: Store, who: Who, now = Date.now()): Promise<Response> {
  const { caller, requester = "" } = who;
  const url = new URL(request.url);
  const desk = new Desk(store, { origin: url.origin, rpID: url.hostname });
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const parts = url.pathname.split("/").filter(Boolean);
  const m = request.method;
  try {
    const needed = needs(m, parts);
    if (needed && caller !== needed) {
      await desk.refuseCaller(`${m} /${parts[0]} by ${caller}, needs ${needed}${who.why ? ` (${who.why})` : ""}`, now);
      return json({ error: needed === "owner" ? "not_owner" : "not_agent" }, 403);
    }
    if (m === "GET" && url.pathname === "/health") return json({ ok: true, version: VERSION });
    if (m === "POST" && url.pathname === "/request") {
      const g = await desk.request(await request.json().catch(() => null), requester, now);
      return json({ id: g.id, approve_url: `${url.origin}/approve/${g.id}`, expires_at: g.expires_at }, 201);
    }
    if (parts[0] === "approve" && parts.length === 2) {
      if (m === "GET") {
        const g = await desk.grant(parts[1]);
        return html(approvePage(g, await desk.approvalOptions(g.id, now), nonce), nonce);
      }
      if (m === "POST") {
        const g = await desk.approve(parts[1], await body(request, desk, "approve", now), now);
        return json({ ok: true, status: g.status });
      }
    }
    if (m === "POST" && parts[0] === "collect" && parts.length === 2) {
      const { result } = await desk.collect(parts[1], requester, now);
      return json({ ok: true, result });
    }
    if (url.pathname === "/enroll") {
      if (m === "GET") return html(enrollPage(await desk.enrollOptions(now), nonce), nonce);
      if (m === "POST") {
        await desk.enroll(await body(request, desk, "enroll", now), now);
        return json({ ok: true });
      }
    }
    if (m === "GET" && url.pathname === "/log") return html(logPage(await desk.readLog(), nonce), nonce);
    return json({ error: "not_found" }, 404);
  } catch (e) {
    if (e instanceof DeskError) return json({ error: e.code }, e.status);
    return json({ error: "server_error" }, 500);
  }
}
