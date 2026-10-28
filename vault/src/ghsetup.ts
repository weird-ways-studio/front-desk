// The vault's GitHub setup pages (card C6a-1): Ben makes the two GitHub Apps from his phone with
// GitHub's manifest flow, and their keys go from GitHub straight into the vault.
//   /github                      -- the next step: a Create button (posts the manifest to GitHub) or an Install link
//   /github/created/<kind>       -- GitHub's redirect after Create: the vault trades the code for the App and key
//   /github/installed/<kind>     -- GitHub's redirect after Install: the vault checks it with the App's own sign-in
// Same guard as setup.ts: only a sign-in with an email (Ben) gets a page. Once the main key is locked to
// his passkey (job gh.app.baseline), every address answers 404.

import { ORG, manifest, type AppKind } from "./github.ts";
import { esc, notFound, page } from "./setup.ts";
import type { VaultLogic } from "./vault.ts";

const TITLE = "Connect GitHub";
const NAMES: Record<AppKind, string> = { headcount: "the read-only headcount App", main: "the main App" };
const fail = (why: string, status = 400) =>
  page(`<p class="big fail">FAIL: ${esc(why.slice(0, 120))}</p><p>Nothing was stored. Open <a href="/github">/github</a> to try again.</p>`, status, TITLE);

/** Handles every /github address on the vault. */
export async function handleGithub(request: Request, logic: VaultLogic, email: string): Promise<Response> {
  const url = new URL(request.url);
  const s = await logic.ghStatus();
  if (s.main.locked || request.method !== "GET") return notFound();
  if (!email) return fail("not_owner: only Ben's own sign-in can connect GitHub", 403);
  const [, , step, kind] = url.pathname.split("/");
  if (step && kind !== "headcount" && kind !== "main") return notFound();
  try {
    if (step === "created") {
      const app = await logic.ghCreated(kind as AppKind, url.searchParams.get("code") ?? "", url.searchParams.get("state") ?? "");
      return page(`<p class="big pass">PASS: ${NAMES[kind as AppKind]} created</p>
<p>Next, install it: choose <b>${ORG}</b>, then <b>All repositories</b>, then Install.</p>
<p><a class="big" href="https://github.com/apps/${encodeURIComponent(app.slug)}/installations/new">Install ${esc(app.slug)}</a></p>`, 200, TITLE);
    }
    if (step === "installed") {
      await logic.ghInstalled(kind as AppKind, url.searchParams.get("installation_id") ?? "");
      return page(`<p class="big pass">PASS: ${NAMES[kind as AppKind]} installed</p><p><a class="big" href="/github">Next step</a></p>`, 200, TITLE);
    }
    if (step) return notFound();
    return await next(logic, s, url.origin);
  } catch (e) {
    return fail((e as Error).message);
  }
}

// The one next step, in order: headcount App first (the watching comes before the power), then the main App.
async function next(logic: VaultLogic, s: Awaited<ReturnType<VaultLogic["ghStatus"]>>, origin: string): Promise<Response> {
  for (const kind of ["headcount", "main"] as AppKind[]) {
    if (s[kind].created && !s[kind].installed) {
      return page(`<h1>Install ${NAMES[kind]}</h1><p>It was created, but GitHub has not sent it back installed. Open GitHub &gt; Settings &gt; GitHub Apps (organization ${ORG}), install it on <b>All repositories</b>.</p>`, 200, TITLE);
    }
    if (!s[kind].created) {
      const state = await logic.ghStart(kind);
      return page(`<h1>Connect GitHub: step ${kind === "headcount" ? 1 : 2} of 2</h1>
<p>Tap the button. GitHub shows ${NAMES[kind]} with its permissions already filled in; tap <b>Create GitHub App</b> there. Its key comes straight back to the vault.</p>
<form method="post" action="https://github.com/organizations/${ORG}/settings/apps/new?state=${encodeURIComponent(state)}">
<input type="hidden" name="manifest" value="${esc(manifest(kind, origin))}"><button type="submit">Create ${NAMES[kind]}</button></form>`, 200, TITLE, "https://github.com");
    }
  }
  return page(`<p class="big pass">PASS: both Apps installed</p>
<p>Last step: tell the agent. It sends you one approval; your Face ID tap locks the main App's key to your passkey and records what GitHub access exists now. This page then switches off.</p>`, 200, TITLE);
}
