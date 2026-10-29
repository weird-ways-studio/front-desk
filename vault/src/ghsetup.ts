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
// Each App by its job, as Ben reads it (instruction.orient-the-person).
const NAMES: Record<AppKind, string> = { headcount: "the watcher (read-only)", main: "the repo-maker" };
const WHAT: Record<AppKind, string> = {
  headcount: "It only reads: each night it lists who and what can reach the studio's code, so a change you did not make alarms your phone.",
  main: "It can create repos and change code. Its key gets locked to your Face ID at the last step, so it does nothing without your tap.",
};
// What GitHub's install screen should list, so a different list is a reason to stop (VERIFIED 2026-10-28 screenshots).
const PERMS: Record<AppKind, string> = {
  headcount: "Read access to administration, members, metadata, organization administration, and organization personal access tokens",
  main: "Read access to metadata; read and write access to administration and code",
};
// The five steps, in order: watcher first (the watching comes before the power).
const STEP: Record<string, number> = { "create:headcount": 1, "install:headcount": 2, "create:main": 3, "install:main": 4, approve: 5 };
const head = (n: number, what: string) => `<p class="muted">Step ${n} of 5 · Connect GitHub</p><h1>${what}</h1>`;
const LOGIN = "<p>Login on GitHub: your own GitHub account (benculbert). If GitHub asks you to sign in, do that first.</p>";
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
      const k = kind as AppKind;
      return page(`${head(STEP[`install:${k}`]!, `Let ${NAMES[k]} into your repos`)}
<p class="big pass">Done: ${NAMES[k]} exists on GitHub (named ${esc(app.slug)}), and its key is in the vault.</p>
<p>Creating it and letting it in are two separate steps. Until you install it, it can't see any repo.</p>
<p><b>Expect on GitHub:</b> "Install ${esc(app.slug)}" on ${ORG}. Choose <b>All repositories</b>. The permissions should read: <i>${PERMS[k]}</i>. If they say anything else, stop and tell the agent. Then tap <b>Install</b>.</p>
<p><b>Next:</b> GitHub sends you back here.</p>
<p><a class="big" href="https://github.com/apps/${encodeURIComponent(app.slug)}/installations/new">Install ${esc(app.slug)} on GitHub</a></p>`, 200, TITLE);
    }
    if (step === "installed") {
      await logic.ghInstalled(kind as AppKind, url.searchParams.get("installation_id") ?? "");
      const k = kind as AppKind;
      return page(`<p class="muted">Step ${STEP[`install:${k}`]} of 5 · Connect GitHub</p>
<p class="big pass">Done: ${NAMES[k]} is installed on all repositories.</p>
<p><a class="big" href="/github">Go to step ${STEP[`install:${k}`]! + 1}</a></p>`, 200, TITLE);
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
      return page(`${head(STEP[`install:${kind}`]!, `Let ${NAMES[kind]} into your repos`)}
<p>It was created, but GitHub has not sent it back installed. On GitHub, open ${ORG}'s Settings &gt; GitHub Apps, install it on <b>All repositories</b>, and you come back here.</p>`, 200, TITLE);
    }
    if (!s[kind].created) {
      const state = await logic.ghStart(kind);
      return page(`${head(STEP[`create:${kind}`]!, `Create ${NAMES[kind]}`)}
<p>${WHAT[kind]}</p>
${kind === "main" ? "<p><b>Time limit:</b> finish steps 3 to 5 within an hour, or the vault throws this key away and you start step 3 again.</p>" : ""}
${LOGIN}
<p><b>Expect on GitHub:</b> a "Create GitHub App" page with the name already filled in. Tap the green <b>Create GitHub App for ${ORG}</b>. If GitHub says the name is taken, add a letter to it.</p>
<p><b>Next:</b> GitHub sends you back here, and its key comes straight to the vault, never to your phone.</p>
<form method="post" action="https://github.com/organizations/${ORG}/settings/apps/new?state=${encodeURIComponent(state)}">
<input type="hidden" name="manifest" value="${esc(manifest(kind, origin))}"><button type="submit">Create ${NAMES[kind]}</button></form>`, 200, TITLE, "https://github.com");
    }
  }
  return page(`${head(STEP.approve!, "Lock the repo-maker to your Face ID")}
<p class="big pass">Done: both Apps are installed.</p>
<p><b>Now:</b> tell the agent "ready" when you have 10 minutes. It sends one approval to your phone; open it from the push.</p>
<p><b>Expect:</b> a list, in plain words, of everything that can reach the studio's code. Approve with your <b>front desk passkey</b> only if you recognise every line. Your tap locks the repo-maker's key to your Face ID and saves the list the nightly check expects.</p>
<p><b>Next:</b> nothing. This page switches off, and setup is done.</p>`, 200, TITLE);
}
