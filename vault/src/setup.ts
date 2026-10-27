// The vault's one web page: /setup, where Ben pastes the Cloudflare master token once.
// It is a plain HTML form (no script), so the token goes from his phone straight to the
// vault and never through the front desk or any library. Once a key is stored (or waiting
// for his first Face ID tap), every address answers 404: the page switches itself off.
//
// Who may use it: the account-wide Cloudflare Access app guards every Worker in this account
// (members of the account -- only Ben -- plus the c-box agent's service token). The agent's
// ticket carries no email, so "has an email" means Ben. Read from ctx.access (runtime, no library).

import type { VaultLogic } from "./vault.ts";

const HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "x-robots-tag": "noindex, nofollow",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  // Not "no-referrer": under it Safari sends the form's Origin as "null", and the origin
  // check below refuses Ben's own Save (seen live 2026-10-26). same-origin still sends
  // nothing to other sites.
  "referrer-policy": "same-origin",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
};

const STYLE = `body{background:#111;color:#eee;font:17px/1.45 -apple-system,system-ui,sans-serif;margin:0;padding:16px;max-width:560px}
h1{font-size:26px}.big{font-size:28px;font-weight:700}.pass{color:#4ade80}.fail{color:#f87171}
textarea{width:100%;font-size:16px;box-sizing:border-box}button{width:100%;font-size:20px;padding:16px;border:0;border-radius:12px;background:#3b82f6;color:#fff;margin-top:16px}
.key{font:20px/1.6 ui-monospace,monospace;word-break:break-all}`;

const esc = (t: string) => t.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

function page(body: string, status = 200): Response {
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Store the master key</title><style>${STYLE}</style></head><body>${body}</body></html>`, { status, headers: HEADERS });
}

const notFound = () => new Response("not found", { status: 404, headers: { "x-robots-tag": "noindex, nofollow", "cache-control": "no-store" } });

/** Ben's email from the Access login, or "" for the agent, a failed lookup, or no login. */
export async function emailOf(access: ExecutionContext["access"]): Promise<string> {
  if (!access) return "";
  const who = await Promise.resolve()
    .then(() => access.getIdentity())
    .catch(() => undefined);
  return typeof who?.email === "string" ? who.email.trim() : "";
}

/** Handles every request to the vault's address. */
export async function handleSetup(request: Request, logic: VaultLogic, email: string): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname !== "/setup") return notFound();
  const status = await logic.status();
  if (status.stored || status.pending) return notFound();
  if (!email) return page(`<p class="big fail">FAIL: not_owner</p><p>Only Ben's own sign-in can store the master key.</p>`, 403);
  if (request.method === "GET") {
    return page(`<h1>Store the master key</h1>
<p>Paste the Cloudflare token you just created, then tap Save. It goes straight to the vault and is never shown again.</p>
<form method="post" action="/setup"><textarea name="token" rows="3" autocomplete="off" autocapitalize="off" spellcheck="false"></textarea>
<button type="submit">Save</button></form>`);
  }
  if (request.method !== "POST") return notFound();
  // A form posted from any other site is refused (the browser sends Origin on POST).
  if (request.headers.get("origin") !== url.origin) return page(`<p class="big fail">FAIL: wrong_origin</p>`, 403);
  const form = await request.formData().catch(() => null);
  try {
    const out = await logic.setup(String(form?.get("token") ?? ""));
    return page(`<p class="big pass">PASS: stored</p>
<h1>Paper recovery key</h1><p>Write this down or print it now and keep it away from your phone. It is shown only once.</p>
<p class="key">${esc(out.recovery_key)}</p>
<p>Next: approve the test job the agent sends you. That Face ID tap locks the key to your passkey. If no tap comes within 30 minutes, this setup lapses and you can start again.</p>`);
  } catch (e) {
    return page(`<p class="big fail">FAIL: ${esc((e as Error).message.slice(0, 120))}</p><p>Nothing was stored. Go back and try again.</p>`, 400);
  }
}
