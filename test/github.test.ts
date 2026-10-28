// GitHub through the vault (card C6a-1): App setup by manifest, the passkey-locked main key, the
// read-only headcount App, and the nightly GitHub count. A fake GitHub checks every App sign-in's
// signature with a real RSA key, so the vault's own key handling is what is under test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createVerify, generateKeyPairSync, type KeyObject } from "node:crypto";
import { MemoryStore } from "../src/desk.ts";
import { b64url } from "../vault/src/seal.ts";
import { GH_PENDING_MS, GH_STATE_MS, VaultLogic, type GhBaselineResult } from "../vault/src/vault.ts";
import { ORG, PERMISSIONS, appJwt, manifest, pkcs8FromPem } from "../vault/src/github.ts";
import { handleSetup } from "../vault/src/setup.ts";

const NOW = Date.UTC(2026, 9, 28, 20, 0, 0);
const ORIGIN = "https://vault.example.test";
const prf = (fill: number) => b64url(new Uint8Array(32).fill(fill));
const level = { read: 1, write: 2, admin: 3 } as Record<string, number>;

function rsa() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs1", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
  return { pem: privateKey as string, pub: publicKey as unknown as KeyObject };
}
const KEYS = { headcount: rsa(), main: rsa() };
const APP_ID = { headcount: 101, main: 202 } as const;

type Fail = "otherOwner" | "notAll" | "elsewhere" | "otherAccount" | "hcGetsWrite" | "hcMint500" | "fullPage";

// A fake GitHub: the two Apps, their org installations, and the org's lists. Records each call with
// what signed it ("jwt:<app>" or "token:<app>").
function fakeGitHub(fail?: Fail) {
  const calls: { method: string; path: string; by: string }[] = [];
  const tokens = new Map<string, { app: keyof typeof APP_ID; perms: Record<string, string> }>();
  const revoked = new Set<string>();
  const org = {
    repos: [{ name: "front-desk", private: false }, { name: "studio-os", private: true }],
    members: ["benculbert", "weird-ways"],
    keys: { "front-desk": [] as number[], "studio-os": [7] } as Record<string, number[]>,
    rulesets: [{ id: 5, enforcement: "active" }],
  };
  let n = 0;
  const json = (body: unknown, status = 200) => Response.json(body, { status });
  const who = (auth: string): string => {
    if (!auth) return "none";
    const t = auth.replace("Bearer ", "");
    if (tokens.has(t)) return revoked.has(t) ? "revoked" : `token:${tokens.get(t)!.app}`;
    const [h, p, s] = t.split(".");
    const claims = JSON.parse(Buffer.from(p ?? "", "base64url").toString() || "{}");
    const app = (Object.keys(APP_ID) as (keyof typeof APP_ID)[]).find((k) => String(APP_ID[k]) === claims.iss);
    if (!app || claims.exp - claims.iat > 600) return "bad";
    const ok = createVerify("RSA-SHA256").update(`${h}.${p}`).verify(KEYS[app].pub, Buffer.from(s, "base64url"));
    return ok ? `jwt:${app}` : "bad";
  };
  const fetchFn = async (input: string, init?: RequestInit) => {
    const url = new URL(input);
    const path = url.pathname + url.search;
    const method = init?.method ?? "GET";
    const headers = init?.headers as Record<string, string>;
    assert.equal(headers["user-agent"], "front-desk-vault");
    const by = who(headers.authorization ?? "");
    calls.push({ method, path, by });
    const conv = url.pathname.match(/^\/app-manifests\/(\w+)\/conversions$/);
    if (method === "POST" && conv) {
      const kind = conv[1].startsWith("main") ? "main" : "headcount";
      return json({ id: APP_ID[kind], slug: `wws-${kind}`, pem: KEYS[kind].pem, owner: { login: fail === "otherOwner" ? "someone-else" : ORG } }, 201);
    }
    if (by === "bad" || by === "revoked") return json({ message: "Bad credentials" }, 401);
    const inst = url.pathname.match(/^\/app\/installations\/(\d+)(\/access_tokens)?$/);
    if (by.startsWith("jwt:") && inst) {
      const app = by.slice(4) as keyof typeof APP_ID;
      if (Number(inst[1]) !== APP_ID[app] * 10) return json({ message: "Not Found" }, 404);
      if (!inst[2]) return json({ account: { login: fail === "otherAccount" ? "someone-else" : ORG }, repository_selection: fail === "notAll" ? "selected" : "all" });
      const asked = JSON.parse(String(init?.body ?? "{}")).permissions ?? PERMISSIONS[app];
      const granted = PERMISSIONS[app] as Record<string, string>;
      const over = Object.entries(asked as Record<string, string>).some(([k, v]) => !granted[k] || level[v] > level[granted[k]]);
      if (over && fail === "hcMint500" && app === "headcount") return json({ message: "Server Error" }, 500);
      if (over && !(fail === "hcGetsWrite" && app === "headcount")) return json({ message: "The permissions requested are not granted to this installation." }, 422);
      const t = `ghs_${app}_${++n}`;
      tokens.set(t, { app, perms: asked });
      return json({ token: t, expires_at: new Date(NOW + 3600_000).toISOString() }, 201);
    }
    if (by.startsWith("jwt:") && path === "/app/installations") return json(fail === "elsewhere" ? [{ id: 1 }, { id: 2 }] : [{ id: 1 }]);
    if (method === "DELETE" && path === "/installation/token" && by.startsWith("token:")) {
      revoked.add(headers.authorization.replace("Bearer ", ""));
      return new Response(null, { status: 204 });
    }
    if (method === "GET" && by === "token:headcount") {
      const list = (items: unknown[]) => json(fail === "fullPage" ? Array.from({ length: 100 }, (_, i) => ({ login: `u${i}` })) : items);
      if (url.pathname === `/orgs/${ORG}/repos`) return json(org.repos);
      if (url.pathname === `/orgs/${ORG}/members`) return list(org.members.map((login) => ({ login })));
      if (url.pathname === `/orgs/${ORG}/outside_collaborators`) return json([]);
      if (url.pathname === `/orgs/${ORG}/invitations`) return json([]);
      if (url.pathname === `/orgs/${ORG}/installations`) return json({ installations: [{ id: 1010, app_slug: "wws-headcount" }, { id: 2020, app_slug: "wws-main" }] });
      if (url.pathname === `/orgs/${ORG}/personal-access-tokens`) return json([{ id: 9, owner: { login: "weird-ways" } }]);
      const keys = url.pathname.match(new RegExp(`^/repos/${ORG}/([\\w-]+)/keys$`));
      if (keys) return json((org.keys[keys[1]] ?? []).map((id) => ({ id })));
      const rules = url.pathname.match(new RegExp(`^/repos/${ORG}/([\\w-]+)/rulesets$`));
      if (rules) return rules[1] === "front-desk" ? json(org.rulesets) : json({ message: "Upgrade to GitHub Pro" }, 403);
    }
    return json({ message: `unexpected ${method} ${path} by ${by}` }, 404);
  };
  return { calls, fetchFn, org, tokens, revoked };
}

function setupVault(fail?: Fail) {
  const gh = fakeGitHub(fail);
  const store = new MemoryStore();
  const clock = { now: NOW };
  return { gh, store, clock, vault: new VaultLogic(store, gh.fetchFn, () => clock.now) };
}

// Ben's taps on the two GitHub pages, for one App.
async function makeApp(vault: VaultLogic, kind: "headcount" | "main") {
  const state = await vault.ghStart(kind);
  await vault.ghCreated(kind, `${kind}code0123456789`, state);
  await vault.ghInstalled(kind, String(APP_ID[kind] * 10));
}
async function connected(fail?: Fail) {
  const s = setupVault(fail);
  await makeApp(s.vault, "headcount");
  await makeApp(s.vault, "main");
  return s;
}
// Everything the store holds, as text, to show what is (not) in it.
const dump = (store: MemoryStore) => JSON.stringify([...(store as unknown as { data: Map<string, unknown> }).data]);
const baseline = (vault: VaultLogic, fill = 7) => vault.run("gh.app.baseline", {}, prf(fill)) as Promise<GhBaselineResult>;

test("App key: GitHub's PKCS#1 key is wrapped for WebCrypto and signs App sign-ins GitHub can check", async () => {
  const jwt = await appJwt(202, pkcs8FromPem(KEYS.main.pem), NOW);
  const [h, p, s] = jwt.split(".");
  assert.ok(createVerify("RSA-SHA256").update(`${h}.${p}`).verify(KEYS.main.pub, Buffer.from(s, "base64url")));
  const claims = JSON.parse(Buffer.from(p, "base64url").toString());
  assert.deepEqual(claims, { iat: NOW / 1000 - 60, exp: NOW / 1000 + 540, iss: "202" });
  assert.throws(() => pkcs8FromPem("not a key"), /bad_app_key/);
});

test("manifest: the headcount App can only read; no webhooks; it comes back to the vault", () => {
  const m = JSON.parse(manifest("headcount", ORIGIN));
  assert.ok(Object.values(m.default_permissions).every((v) => v === "read"));
  assert.equal(m.public, false);
  assert.equal(m.hook_attributes.active, false);
  assert.equal(m.redirect_url, `${ORIGIN}/github/created/headcount`);
  assert.equal(m.setup_url, `${ORIGIN}/github/installed/headcount`);
});

test("setup, then Ben's tap: main key locked to his passkey, headcount App refused write, list recorded", async () => {
  const { vault, store, gh } = await connected();
  assert.ok(dump(store).includes("gh.app.main"), "the dump sees the store");
  // Before the tap the main key exists only under the one-time hold, never as plain PKCS#8.
  const main = pkcs8FromPem(KEYS.main.pem);
  assert.ok(!dump(store).includes(main), "main key never stored in the clear");
  const r = await baseline(vault);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.main.locked_to_passkey_now, true);
  assert.equal(r.main.key_works, true);
  assert.equal(r.headcount.write_refused, true);
  assert.match(r.headcount.write_error ?? "", /not granted/);
  assert.deepEqual(r.changes, ["first list"]);
  assert.equal(r.counts.deploy_keys, 1);
  assert.ok(!dump(store).includes(main), "after the tap only the passkey-sealed box remains");
  assert.equal((await store.get<any>("gh.app.main")).pending, undefined, "the one-time hold is forgotten");
  assert.equal((await vault.ghStatus()).main.locked, true);
  assert.ok([...gh.tokens.keys()].every((t) => gh.revoked.has(t)), "every one-hour key was revoked after use");
  // A second tap with another passkey secret cannot open it.
  await assert.rejects(baseline(vault, 8), /wrong_secret/);
});

test("nightly GitHub count: clean, then a planted deploy key and a removed branch rule are named", async () => {
  const { vault, gh } = await connected();
  assert.equal((await baseline(vault)).ok, true);
  gh.calls.length = 0;
  const clean = await (vault as any).ghHeadcount();
  assert.deepEqual(clean, { ok: true, changes: [] });
  assert.ok(gh.calls.every((c) => c.by === "jwt:headcount" || c.by === "token:headcount"), "the night uses only the read-only App");
  assert.ok(gh.calls.every((c) => c.method === "GET" || c.path.endsWith("/access_tokens") || c.path === "/installation/token"));
  gh.org.keys["studio-os"].push(99);
  gh.org.rulesets = [];
  const night = await (vault as any).ghHeadcount();
  assert.equal(night.ok, false);
  assert.deepEqual(night.changes, ["deploy_keys +studio-os:99", "rulesets -front-desk:5:active"]);
  // Ben accepts the changes with another tap; the list now matches.
  const again = await baseline(vault);
  assert.deepEqual(again.changes, ["deploy_keys +studio-os:99", "rulesets -front-desk:5:active"]);
  assert.deepEqual(await (vault as any).ghHeadcount(), { ok: true, changes: [] });
});

test("nightly count fails closed: not set up, and a list too long to read in one page", async () => {
  const { vault } = setupVault();
  assert.deepEqual((await vault.headcount()).github, { ok: false, changes: [], error: "github_not_set_up" });
  const full = await connected("fullPage");
  const r = await baseline(full.vault);
  assert.equal(r.ok, false);
  assert.match(r.error ?? "", /too_many/);
});

for (const fail of ["hcGetsWrite", "hcMint500"] as const) {
  test(`baseline refused when the headcount App's write test is not GitHub's permission refusal (${fail}): nothing recorded`, async () => {
    const { vault, store } = await connected(fail);
    const r = await baseline(vault);
    assert.equal(r.ok, false);
    assert.equal(r.headcount.write_refused, false, "an outage proves nothing about the App's permissions");
    assert.equal(await store.get("gh.baseline"), undefined);
  });
}

test("baseline refused before both Apps are installed", async () => {
  const { vault } = setupVault();
  await makeApp(vault, "headcount");
  await assert.rejects(baseline(vault), /github_not_set_up/);
});

for (const [why, run] of [
  ["a state the vault never issued", (v: VaultLogic) => v.ghCreated("headcount", "headcountcode0123456789", "forged")],
  ["the main App's state used for the headcount App", async (v: VaultLogic) => v.ghCreated("headcount", "headcountcode0123456789", await v.ghStart("main"))],
] as const) {
  test(`created page refuses ${why}: nothing stored`, async () => {
    const { vault } = setupVault();
    await vault.ghStart("headcount");
    await assert.rejects(run(vault), /bad_state/);
    assert.equal((await vault.ghStatus()).headcount.created, false);
  });
}

test("created page refuses a reused or expired state", async () => {
  const { vault, clock } = setupVault();
  const s = await vault.ghStart("headcount");
  await vault.ghCreated("headcount", "headcountcode0123456789", s);
  await assert.rejects(vault.ghCreated("headcount", "headcountcode0123456789", s), /bad_state/);
  const m = await vault.ghStart("main");
  clock.now += GH_STATE_MS + 1;
  await assert.rejects(vault.ghCreated("main", "maincode0123456789", m), /bad_state/);
});

for (const [fail, why] of [["otherOwner", /app_not_in_org/], ["notAll", /installation_not_all_repositories/], ["otherAccount", /installation_not_in_org/], ["elsewhere", /app_installed_elsewhere/]] as const) {
  test(`setup refuses ${fail}`, async () => {
    const { vault } = setupVault(fail);
    await assert.rejects(makeApp(vault, "headcount"), why);
    assert.equal((await vault.ghStatus()).headcount.installed, false);
  });
}

test("installed page refuses an installation the App's own sign-in does not show", async () => {
  const { vault } = setupVault();
  const s = await vault.ghStart("headcount");
  await vault.ghCreated("headcount", "headcountcode0123456789", s);
  await assert.rejects(vault.ghInstalled("headcount", "999"), /gh_404/);
});

test("main key hold lapses if Ben does not tap within the hour: erased", async () => {
  const { vault, clock } = await connected();
  clock.now += GH_PENDING_MS + 1;
  assert.equal((await vault.ghStatus()).main.created, false);
  await assert.rejects(baseline(vault), /github_not_set_up/);
});

test("pages: Ben only; GitHub's form allowed only on /github; everything 404 once locked", async () => {
  const { vault } = setupVault();
  const get = (path: string, email = "ben@example.test") => handleSetup(new Request(ORIGIN + path), vault, email);
  assert.equal((await get("/github", "")).status, 403);
  const first = await get("/github");
  const html = await first.text();
  assert.match(html, new RegExp(`action="https://github.com/organizations/${ORG}/settings/apps/new\\?state=`));
  assert.match(first.headers.get("content-security-policy")!, /form-action https:\/\/github\.com/);
  assert.match((await get("/setup")).headers.get("content-security-policy") ?? "form-action 'self'", /form-action 'self'/);
  const state = decodeURIComponent(html.match(/state=([^"]+)"/)![1]);
  const created = await get(`/github/created/headcount?code=headcountcode0123456789&state=${encodeURIComponent(state)}`);
  assert.match(await created.text(), /PASS: the read-only headcount App created/);
  assert.equal((await handleSetup(new Request(ORIGIN + "/github", { method: "POST" }), vault, "ben@example.test")).status, 404);
  await vault.ghInstalled("headcount", "1010");
  await makeApp(vault, "main");
  await baseline(vault);
  assert.equal((await get("/github")).status, 404);
});
