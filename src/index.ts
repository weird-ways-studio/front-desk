// The front desk Worker. PR1 is a scaffold: it proves the deploy lock
// (only Ben-approved commits on main deploy) before any real code exists.
// Cloudflare calls the default export's fetch() for every request; see
// wrangler.jsonc for which file is the entry point (framework-forced wiring).

export const VERSION = "0.1.0-scaffold";

const SECURITY_HEADERS: Record<string, string> = {
  "x-robots-tag": "noindex, nofollow",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
};

export function handle(request: Request): Response {
  const url = new URL(request.url);
  if (request.method === "GET" && url.pathname === "/health") {
    return Response.json({ ok: true, version: VERSION }, { headers: SECURITY_HEADERS });
  }
  return new Response("Not found", { status: 404, headers: SECURITY_HEADERS });
}

export default {
  fetch: (request: Request): Response => handle(request),
};
