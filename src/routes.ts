// The front desk's HTTP routes, kept apart from the Durable Object (index.ts)
// so tests can drive them with an in-memory store.

import { Desk, DeskError, type Store } from "./desk.ts";
import { approvePage, enrollPage, logPage } from "./page.ts";

export const VERSION = "0.2.0-approvals";

// Who asked. One agent identity until the Access token check lands (PR3b).
const REQUESTER = "c-box agent";

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

// The routes, kept apart from the Durable Object so tests can drive them.
export async function route(request: Request, store: Store, now = Date.now()): Promise<Response> {
  const url = new URL(request.url);
  const desk = new Desk(store, { origin: url.origin, rpID: url.hostname });
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const parts = url.pathname.split("/").filter(Boolean);
  const m = request.method;
  try {
    if (m === "GET" && url.pathname === "/health") return json({ ok: true, version: VERSION });
    if (m === "POST" && url.pathname === "/request") {
      const g = await desk.request(await request.json().catch(() => null), REQUESTER, now);
      return json({ id: g.id, approve_url: `${url.origin}/approve/${g.id}`, expires_at: g.expires_at }, 201);
    }
    if (parts[0] === "approve" && parts.length === 2) {
      if (m === "GET") {
        const g = await desk.grant(parts[1]);
        return html(approvePage(g, await desk.approvalOptions(g.id, now), nonce), nonce);
      }
      if (m === "POST") {
        const g = await desk.approve(parts[1], await request.json(), now);
        return json({ ok: true, status: g.status });
      }
    }
    if (m === "POST" && parts[0] === "collect" && parts.length === 2) {
      const { result } = await desk.collect(parts[1], REQUESTER, now);
      return json({ ok: true, result });
    }
    if (url.pathname === "/enroll") {
      if (m === "GET") return html(enrollPage(await desk.enrollOptions(now), nonce), nonce);
      if (m === "POST") {
        await desk.enroll(await request.json(), now);
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
