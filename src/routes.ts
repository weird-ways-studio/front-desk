// The front desk's HTTP routes, kept apart from the Durable Object (index.ts)
// so tests can drive them with an in-memory store.

import { DeskError, withoutSecret, type Alert, type DeskHooks, type Push, type Source, type Store } from "./desk.ts";
import { CardDesk } from "./carddesk.ts";
import { JOBS, menu } from "./jobs.ts";
import { checkSignature } from "./cboxkey.ts";
import type { VaultApi, VaultCardApi } from "../vault/src/api.ts";
import { approvePage, cardPage, cboxKeyPage, enrollPage, logPage, passkeysPage, prfCheckPage } from "./page.ts";
import type { Recorder } from "./recorder.ts";

export const VERSION = "0.13.0";

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
  if (parts[0] === "enroll" || parts[0] === "approve" || parts[0] === "log" || parts[0] === "passkeys" || parts[0] === "prf-check" || parts[0] === "cbox-key") return "owner";
  // /headcount (card build 5 6ab972c8): every method needs the agent, so Ben's login and unknown callers get 403.
  if ((m === "POST" && parts[0] === "request") || parts[0] === "collect" || parts[0] === "card" || parts[0] === "headcount" || (m === "GET" && parts[0] === "menu")) return "agent";
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
async function body<T>(request: Request, desk: CardDesk, what: string, now: number): Promise<T> {
  try {
    return (await request.json()) as T;
  } catch {
    await desk.refuse(`${what}: bad_json`, now);
    throw new DeskError("bad_json", 400);
  }
}

/** A push failure as fixed words only: a thrown fetch error could carry a key, which is a secret. */
function pushError(e: unknown): string {
  const m = e instanceof Error ? /^pushover (?:answered \d{3}|rejected|unreachable)$/.exec(e.message) : null;
  return m ? m[0] : "push failed";
}

// The routes, kept apart from the Durable Object so tests can drive them.
export async function route(request: Request, store: Store, who: Who, now = Date.now(), vault?: DeskHooks["vault"], push?: Push, recorder?: Recorder, alert?: Alert): Promise<Response> {
  const { caller, requester = "" } = who;
  const url = new URL(request.url);
  const desk = new CardDesk(store, { origin: url.origin, rpID: url.hostname }, { vault, recorder, alert });
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
    if (m === "GET" && url.pathname === "/menu") return json(menu());
    // The last headcount runs (src/headcountrun.ts); reading writes nothing and adds no log row.
    if (m === "GET" && url.pathname === "/headcount") return json(await desk.headcountRuns());
    // Agent calls: the raw body is kept so the c-box signature can be checked over it.
    const text = m === "POST" && (parts[0] === "request" || parts[0] === "collect" || parts[0] === "card") ? await request.text() : "";
    const source: Source = {
      checkSignature: () => checkSignature(store, m, url.pathname, request.headers, text, now),
    };
    if (m === "POST" && url.pathname === "/request") {
      const input = (() => { try { return JSON.parse(text); } catch { return null; } })();
      const g = await desk.request(input, requester, now, source);
      const approveUrl = `${url.origin}/approve/${g.id}`;
      // A failed push never fails the request: the agent sees pushed=false, and why, and sends Ben the link itself.
      const why = push ? await push(JOBS[g.job].explain(g.params).does, approveUrl).then(() => "", (e: Error) => pushError(e)) : "no phone push set";
      return json({ id: g.id, approve_url: approveUrl, expires_at: g.expires_at, pushed: !why, ...(why ? { push_error: why } : {}) }, 201);
    }
    // Cards (card 85818ab1; rules in carddesk.ts). The agent asks and collects (signed); Ben's page is /approve/card/<id>.
    if (m === "POST" && url.pathname === "/card") {
      const input = (() => { try { return JSON.parse(text); } catch { return null; } })();
      let made;
      try {
        made = await desk.requestCard(input, requester, now, source);
      } catch (e) {
        // Fixed words: nothing was sent to Ben and nothing ran.
        if (e instanceof DeskError) return json({ error: `card_refused: ${e.code}` }, e.status);
        throw e;
      }
      const approveUrl = `${url.origin}/approve/card/${made.card.id}`;
      const what = `${made.grants.length} job${made.grants.length === 1 ? "" : "s"} on one tap: ${made.grants.map((g, i) => `${i + 1}) ${JOBS[g.job].explain(g.params).does}`).join(" ")}`;
      const why = push ? await push(what, approveUrl).then(() => "", (e: Error) => pushError(e)) : "no phone push set";
      return json({ card: made.card.id, approve_url: approveUrl, expires_at: made.card.expires_at, deadline: made.card.manifest.deadline, entries: made.grants.map((g) => ({ grant: g.id, job: g.job })), pushed: !why, ...(why ? { push_error: why } : {}) }, 201);
    }
    if (m === "GET" && parts[0] === "card" && parts.length === 2) return json({ ok: true, report: await desk.collectCard(parts[1], requester, now, source) });
    if (parts[0] === "approve" && parts[1] === "card" && parts.length >= 3) {
      const id = parts[2];
      if (m === "GET" && parts.length === 3) {
        const c = await desk.card(id);
        const options = c.status === "pending" && now <= c.expires_at ? await desk.cardOptions(id, now) : null;
        const report = await desk.finish(id, now);
        const reasons = await Promise.all(c.grants.map(async (g) => (await desk.grant(g)).reason));
        return html(cardPage(report, reasons, options, nonce), nonce);
      }
      if (m === "POST" && parts.length === 3) return json({ ok: true, report: await desk.approveCard(id, await body(request, desk, "card", now), now) });
      // Stop only takes power away, so Ben's login is enough; the Origin check stops another site's form.
      if (m === "POST" && parts.length === 4 && parts[3] === "stop") {
        if (request.headers.get("origin") !== url.origin) return json({ error: "wrong_origin" }, 403);
        return json({ ok: true, report: await desk.stopCard(id, now) });
      }
    }
    if (parts[0] === "approve" && parts.length === 2) {
      if (m === "GET") {
        const g = await desk.grant(parts[1]);
        return html(approvePage(g, await desk.approvalOptions(g.id, now), nonce), nonce);
      }
      if (m === "POST") {
        const g = await desk.approve(parts[1], await body(request, desk, "approve", now), now);
        const summary = JOBS[g.job].done(g.result);
        const outcome = /^(Done|Approved)\b/.test(summary) ? "done" : "not_done";
        return json({ ok: true, status: g.status, outcome, summary, ...(g.result === undefined ? {} : { result: withoutSecret(g.result) }) });
      }
    }
    if (m === "POST" && parts[0] === "collect" && parts.length === 2) {
      const { result } = await desk.collect(parts[1], requester, now, source);
      return json({ ok: true, result });
    }
    if (url.pathname === "/enroll") {
      if (m === "GET") return html(enrollPage(await desk.enrollOptions(now), nonce), nonce);
      if (m === "POST") {
        await desk.enroll(await body(request, desk, "enroll", now), now);
        return json({ ok: true });
      }
    }
    if (url.pathname === "/prf-check") {
      if (m === "GET") return html(prfCheckPage(await desk.prfCheckOptions(now), nonce), nonce);
      if (m === "POST") return json({ ok: true, ...(await desk.prfCheck(await body(request, desk, "prf check", now), now)) });
    }
    if (url.pathname === "/cbox-key") {
      if (m === "GET") return html(cboxKeyPage(await desk.cboxKey(), nonce), nonce);
      // Removing only takes power away, so Ben's login is enough; the Origin check stops another site's form.
      if (m === "POST") {
        if (request.headers.get("origin") !== url.origin) return json({ error: "wrong_origin" }, 403);
        return json({ ok: true, removed: await desk.removeCboxKey(now) });
      }
    }
    if (m === "GET" && url.pathname === "/log") return html(logPage(await desk.readLog(), nonce), nonce);
    if (m === "GET" && url.pathname === "/passkeys") return html(passkeysPage(await desk.passkeyPins(), nonce), nonce);
    return json({ error: "not_found" }, 404);
  } catch (e) {
    if (e instanceof DeskError) return json({ error: e.code }, e.status);
    return json({ error: "server_error" }, 500);
  }
}
