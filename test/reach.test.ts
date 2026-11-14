// The watcher's reach read (card N2 5fdbf2ce part A; studio-os trust-but-verify/REFINE-5fdbf2ce-watcher-reach.md v1.3,
// sections 11-13 override earlier ones): repo webhooks, org webhooks and direct collaborators, read in generations of
// slices with the headcount App, then folded into the nightly GitHub count. Rows R<n> are the spec's evidence matrix.
// A fake GitHub answers every call and counts them per slice. Fixtures use example.com and made-up names only.
// Mutants: test/reach-mutants.json (run by test/cards-mutants.test.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { MemoryStore } from "../src/desk.ts";
import { VaultLogic, type GhReachAcceptResult } from "../vault/src/vault.ts";
import { signedRun, testVault } from "./vaultsign.ts";
import { b64url } from "../vault/src/seal.ts";
import { ORG, PERMISSIONS, REACH_PERMS, checkPermissions, pkcs8FromPem, type GhSnapshot } from "../vault/src/github.ts";

const pem = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs1", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } }).privateKey as string;
const APP = 101;
const INST = 1010;
const NIGHT = Date.UTC(2026, 10, 14, 3, 47); // the first nightly slice
const DAY = Date.UTC(2026, 10, 14, 10, 0); // outside the protected window
const MIN = 60_000;

type Hook = Record<string, unknown>;
const hook = (id: number, over: Hook = {}, config: Hook = {}): Hook => ({
  id, events: ["push"], active: true, ...over,
  config: { url: "https://example.com/hook", content_type: "json", insecure_ssl: "0", secret: "********", ...config },
});

function fakeGitHub(n = 2) {
  const repos = Array.from({ length: n }, (_, i) => ({ name: `repo-${i}`, id: 5000 + i, private: i % 2 === 1 }));
  const org = {
    repos: repos as { name: string; id: unknown; private: unknown }[],
    hooks: {} as Record<string, unknown[]>,
    orgHooks: [] as unknown[],
    collabs: Object.fromEntries(repos.map((r) => [r.name, [{ login: "owner-a", role_name: "admin" }]])) as Record<string, unknown[]>,
  };
  const calls: { method: string; path: string; redirect?: string }[] = [];
  const minted: unknown[] = [];
  // A probe permission GitHub wrongly grants (R22); every other write ask is refused as GitHub does.
  const faults = { grantWrite: "" };
  const deleted: string[] = [];
  const tokens = new Set<string>();
  // A test may answer any one path itself (a refusal, a redirect, a slow answer).
  let override: ((path: string) => Response | Promise<Response> | undefined) | undefined;
  let t = 0;
  const json = (b: unknown, status = 200) => Response.json(b, { status });
  const fetchFn = async (input: string, init?: RequestInit) => {
    const url = new URL(input);
    const path = url.pathname + url.search;
    const method = init?.method ?? "GET";
    calls.push({ method, path, redirect: init?.redirect });
    const auth = String((init?.headers as Record<string, string>)?.authorization ?? "").replace("Bearer ", "");
    const o = override?.(path);
    if (o) return o;
    if (auth.split(".").length === 3) {
      if (path === "/app") return json({ id: APP, permissions: PERMISSIONS.headcount });
      if (path === `/app/installations/${INST}`) return json({ account: { login: ORG }, repository_selection: "all", permissions: PERMISSIONS.headcount });
      if (path === "/app/installations") return json([{ id: INST }]);
      if (path === `/app/installations/${INST}/access_tokens` && method === "POST") {
        const asked = JSON.parse(String(init?.body ?? "{}"));
        const writes = Object.entries(asked.permissions ?? {}).filter(([, v]) => v !== "read").map(([k]) => k);
        if (writes.length && !(writes.length === 1 && writes[0] === faults.grantWrite)) return json({ message: "The level of access for permissions requested are not granted to this installation." }, 422);
        if (!writes.length) minted.push(asked);
        const k = `ghs_reach_${++t}`;
        tokens.add(k);
        return json({ token: k, expires_at: "2099-01-01T00:00:00Z" }, 201);
      }
    }
    if (tokens.has(auth)) {
      if (method === "DELETE" && path === "/installation/token") {
        deleted.push(auth);
        return new Response(null, { status: 204 });
      }
      if (url.pathname === `/orgs/${ORG}/repos`) return json(org.repos);
      if (url.pathname === `/orgs/${ORG}/hooks`) return json(org.orgHooks);
      const m = url.pathname.match(new RegExp(`^/repos/${ORG}/([\\w-]+)/(hooks|collaborators)$`));
      if (m && m[2] === "hooks") return json(org.hooks[m[1]] ?? []);
      if (m && url.searchParams.get("affiliation") === "direct") return json(org.collabs[m[1]] ?? []);
    }
    return json({ message: `unexpected ${method} ${path}` }, 404);
  };
  return { org, calls, minted, faults, deleted, fetchFn, set: (f: typeof override) => (override = f) };
}

function setup(n = 2, at = NIGHT) {
  const gh = fakeGitHub(n);
  const store = new MemoryStore();
  const clock = { now: at };
  store.kv.put("gh.app.headcount", { id: APP, slug: "wws-front-desk-headcount", key: pkcs8FromPem(pem), installation: INST });
  const vault: VaultLogic = testVault(store, gh.fetchFn, () => clock.now);
  // The main count's own read, stubbed (its tests are in github.test.ts): the repo ids it saw this run.
  const main = (): GhSnapshot => ({ repos: [], repo_ids: gh.org.repos.map((r) => `${r.name}:${r.id}`).sort(), members: [], owners: [], outside: [], invites: [], apps: [], pats: [], deploy_keys: [], rulesets: [] });
  store.kv.put("gh.baseline", main());
  const orig = (vault as any).ghRead.bind(vault);
  (vault as any).ghRead = (hc: unknown, use: unknown, narrow?: unknown) => (narrow ? orig(hc, use, narrow) : Promise.resolve(main()));
  return { gh, store, clock, vault, main };
}
type S = ReturnType<typeof setup>;
const dump = (store: MemoryStore) => JSON.stringify([...(store as unknown as { data: Map<string, unknown> }).data]);
const night = (s: S) => s.vault.ghReachNight();
const demand = (s: S) => s.vault.ghReachStep("demand");
const step = (s: S) => s.vault.ghReachStep();
// Runs nightly slices until the generation ends.
async function nightAll(s: S) {
  let p = await night(s);
  for (let i = 0; i < 4 && p.state === "open"; i++) p = await night(s);
  return p;
}
async function demandAll(s: S) {
  let p = await demand(s);
  for (let i = 0; i < 4 && p.state === "open"; i++) p = await step(s);
  return p;
}
// What part B's acceptance writes: the lists of the latest complete read, taken as the accepted list.
function accept(s: S) {
  const g = s.store.kv.get<any>("gh.reach.complete");
  const repos = g.repos as { hooks: string[]; collabs: string[] }[];
  s.store.kv.put("gh.reach.baseline", { repo_hooks: repos.flatMap((r) => r.hooks).sort(), org_hooks: g.org_hooks, collaborators: repos.flatMap((r) => r.collabs).sort() });
}
const hc = (s: S, select?: "night" | "any") => (s.vault as any).ghHeadcount(select);
// A green night: complete nightly read, accepted, folded in at 04:17.
async function greenNight(n = 2) {
  const s = setup(n);
  assert.equal((await nightAll(s)).state, "complete");
  accept(s);
  s.clock.now = NIGHT + 30 * MIN;
  assert.deepEqual(await hc(s), { ok: true, changes: [] });
  return s;
}

test("allowed list: the headcount App may read webhooks, never write them (R11)", () => {
  assert.equal(PERMISSIONS.headcount.repository_hooks, "read");
  assert.equal(PERMISSIONS.headcount.organization_hooks, "read");
  assert.throws(() => checkPermissions({ repository_hooks: "write" }, PERMISSIONS.headcount, "app"), /too_wide/);
  assert.throws(() => checkPermissions({ organization_hooks: "write" }, PERMISSIONS.headcount, "app"), /too_wide/);
});

test("a nightly read: two slices of at most 18 repos, one narrowed key each, deleted, no redirects followed; the night folds in green", async () => {
  const s = setup(20);
  const p1 = await night(s);
  assert.deepEqual(p1, { state: "open", done: 18, total: 20, code: null });
  const p2 = await night(s);
  assert.deepEqual(p2, { state: "complete", done: 20, total: 20, code: null });
  assert.deepEqual(s.gh.minted, [{ permissions: REACH_PERMS }, { permissions: REACH_PERMS }]);
  assert.deepEqual(REACH_PERMS, { metadata: "read", repository_hooks: "read", organization_hooks: "read" });
  assert.equal(s.gh.calls.filter((c) => c.method === "DELETE").length, 2);
  const reach = s.gh.calls.filter((c) => /\/hooks|\/collaborators|\/orgs\/[\w-]+\/repos/.test(c.path));
  assert.ok(reach.length > 0 && reach.every((c) => c.redirect === "manual"), "every reach call refuses redirects");
  assert.equal(s.gh.calls.filter((c) => c.path.startsWith(`/orgs/${ORG}/hooks`)).length, 1, "org hooks read once per generation");
  const g = s.store.kv.get<any>("gh.reach.night");
  assert.equal(g.complete_at, NIGHT);
  assert.equal(g.repos.find((r: any) => r.name === "repo-1").collabs[0], "repo-1:owner-a:admin");
  assert.deepEqual(s.store.kv.get<any>("gh.reach.complete"), g);
  accept(s);
  s.clock.now = NIGHT + 30 * MIN;
  assert.deepEqual(await hc(s), { ok: true, changes: [] });
});

test("R9/R8: every slice stays within 43 GitHub calls; 36 repos complete in two slices; 37 -> reach_over_budget", async () => {
  const s = setup(36);
  for (const want of ["open", "complete"]) {
    s.gh.calls.length = 0;
    assert.equal((await night(s)).state, want);
    assert.ok(s.gh.calls.length <= 43, `${s.gh.calls.length} calls`);
  }
  const big = setup(37);
  const p = await night(big);
  assert.deepEqual(p, { state: "failed", done: 0, total: 37, code: "reach_over_budget" });
  assert.ok(big.gh.calls.length <= 43);
  assert.deepEqual(big.store.kv.get<any>("gh.reach.fail"), { seq: 1, reason: "reach_over_budget" });
});

test("R1: a new repo hook, org hook or collaborator is a change line and red", async () => {
  for (const [kind, plant] of [
    ["repo_hooks +repo-0:77:example.com:", (s: S) => (s.gh.org.hooks["repo-0"] = [hook(77)])],
    ["org_hooks +78:example.com:", (s: S) => (s.gh.org.orgHooks = [hook(78)])],
    ["collaborators +repo-0:someone-b:write", (s: S) => s.gh.org.collabs["repo-0"].push({ login: "someone-b", role_name: "write" })],
  ] as const) {
    const s = await greenNight();
    plant(s);
    s.clock.now = DAY;
    assert.equal((await demandAll(s)).state, "complete");
    const r = await hc(s, "any");
    assert.equal(r.ok, false, kind);
    assert.equal(r.changes.length, 1, JSON.stringify(r.changes));
    assert.ok(r.changes[0].startsWith(kind), r.changes[0]);
  }
});

async function withHooks(change: (h: Hook) => Hook) {
  const s = setup();
  s.gh.org.hooks["repo-0"] = [hook(5)];
  assert.equal((await nightAll(s)).state, "complete");
  accept(s);
  s.gh.org.hooks["repo-0"] = [change(hook(5))];
  s.clock.now = DAY;
  assert.equal((await demandAll(s)).state, "complete");
  return hc(s, "any");
}

test("R2/R3/R3b: a removed hook, changed events, host, active, role, or a same-host path change -> red", async () => {
  const s = await greenNight();
  s.gh.org.collabs["repo-0"] = [];
  s.clock.now = DAY;
  await demandAll(s);
  const gone = await hc(s, "any");
  assert.deepEqual(gone.changes, ["collaborators -repo-0:owner-a:admin"]);
  s.gh.org.collabs["repo-0"] = [{ login: "owner-a", role_name: "maintain" }];
  await demandAll(s);
  assert.deepEqual((await hc(s, "any")).changes.sort(), ["collaborators +repo-0:owner-a:maintain", "collaborators -repo-0:owner-a:admin"]);
  for (const ch of [(h: Hook) => ({ ...h, events: ["push", "pull_request"] }), (h: Hook) => ({ ...h, active: false }), (h: Hook) => ({ ...h, config: { ...(h.config as Hook), url: "https://other.example.com/hook" } }), (h: Hook) => ({ ...h, config: { ...(h.config as Hook), url: "https://example.com/elsewhere" } }), (h: Hook) => ({ ...h, config: { ...(h.config as Hook), url: "https://example.com/hook?x=1" } }), (h: Hook) => ({ ...h, config: { ...(h.config as Hook), insecure_ssl: "1" } }), (h: Hook) => ({ ...h, config: { ...(h.config as Hook), content_type: "form" } })]) {
    const r = await withHooks(ch);
    assert.equal(r.ok, false);
    assert.equal(r.changes.length, 2, JSON.stringify(r.changes));
  }
  // R3b: only the path differs -- host the same, the destination fingerprint is not.
  const r = await withHooks((h) => ({ ...h, config: { ...(h.config as Hook), url: "https://example.com/elsewhere" } }));
  const [a, b] = r.changes.map((c: string) => c.split(":"));
  assert.equal(a[2], "example.com");
  assert.equal(b[2], "example.com");
  assert.notEqual(a[3], b[3], "dest differs");
  assert.match(a[3], /^[0-9a-f]{12}$/);
});

test("R43: insecure_ssl 0 and \"0\" fingerprint the same; the secret field does not enter the fingerprint", async () => {
  const r = await withHooks((h) => ({ ...h, config: { ...(h.config as Hook), insecure_ssl: 0, secret: "changed" } }));
  assert.deepEqual(r, { ok: true, changes: [] });
});

test("R4/R5: a refusal, outage, redirect or full page on any of the three lists fails the generation; the night is red, never 'none'", async () => {
  const lists = [`/repos/${ORG}/repo-1/hooks`, `/repos/${ORG}/repo-1/collaborators`, `/orgs/${ORG}/hooks`, `/orgs/${ORG}/repos`];
  for (const path of lists) {
    for (const [status, code] of [[403, "reach_gh_403"], [404, "reach_gh_404"], [429, "reach_gh_429"], [500, "reach_gh_500"], [301, "reach_redirect"], [200, "reach_too_many"]] as const) {
      const s = setup();
      s.gh.set((p) => (p.startsWith(path) ? (status === 200 ? Response.json(Array.from({ length: 100 }, (_, i) => ({ id: i }))) : new Response(null, { status, headers: status === 301 ? { location: "https://example.com/" } : {} })) : undefined));
      const p = await nightAll(s);
      assert.deepEqual({ state: p.state, code: p.code }, { state: "failed", code }, `${path} ${status}`);
      assert.equal(s.store.kv.get("gh.reach.night"), undefined, "nothing complete");
      s.clock.now = NIGHT + 30 * MIN;
      const r = await hc(s);
      assert.equal(r.ok, false);
      assert.match(r.error, /reach_incomplete: no_result/);
    }
  }
});

test("R4: a failure after an earlier complete night -> red (newer failure), even though the older read was complete (R16)", async () => {
  const s = await greenNight();
  s.gh.set((p) => (p.includes("/collaborators") ? new Response(null, { status: 500 }) : undefined));
  s.clock.now = NIGHT + 35 * MIN; // 04:22: after the protected window, the night still fresh
  assert.equal((await demand(s)).code, "reach_gh_500");
  const r = await hc(s);
  assert.equal(r.ok, false);
  assert.match(r.error, /reach_incomplete: newer_failed/);
});

test("R6/R27: no night, a night older than 60 minutes from its start, or yesterday's -> red", async () => {
  const none = setup();
  none.store.kv.put("gh.reach.baseline", { repo_hooks: [], org_hooks: [], collaborators: [] });
  assert.match((await hc(none)).error, /reach_incomplete: no_result/);
  const s = await greenNight();
  s.clock.now = NIGHT + 61 * MIN;
  assert.match((await hc(s)).error, /reach_incomplete: stale/);
  s.clock.now = NIGHT + 24 * 60 * MIN;
  assert.match((await hc(s)).error, /reach_incomplete: stale/);
  // R27: started long ago, completed a moment ago: still stale (age counts from the first observation).
  const slow = setup(20);
  await night(slow);
  slow.clock.now = NIGHT + 70 * MIN;
  assert.equal((await night(slow)).state, "complete");
  accept(slow);
  assert.match((await hc(slow)).error, /reach_incomplete: stale/);
});

test("R6: an incomplete night (only its first slice ran) -> red", async () => {
  const s = setup(20);
  s.store.kv.put("gh.reach.baseline", { repo_hooks: [], org_hooks: [], collaborators: [] });
  assert.equal((await night(s)).state, "open");
  s.clock.now = NIGHT + 30 * MIN;
  assert.match((await hc(s)).error, /reach_incomplete: no_result/);
});

test("R10: hook URL path, query and config.secret never reach state, results or errors", async () => {
  const s = setup();
  s.gh.org.hooks["repo-0"] = [hook(9, {}, { url: "https://example.com/PATHSECRET?token=QUERYSECRET", secret: "CONFIGSECRET" })];
  s.gh.org.orgHooks = [hook(10, {}, { url: "http://example.com:8080/ORGPATH?k=ORGQUERY" })];
  const p = await nightAll(s);
  accept(s);
  s.clock.now = NIGHT + 30 * MIN;
  const r = await hc(s);
  // A shape failure whose input carries the URL: the error stays a fixed code.
  const bad = setup();
  bad.gh.org.hooks["repo-0"] = [hook(9, { events: "push" }, { url: "https://example.com/PATHSECRET?token=QUERYSECRET" })];
  const pb = await nightAll(bad);
  assert.equal(pb.code, "reach_shape");
  const all = dump(s.store) + dump(bad.store) + JSON.stringify([p, r, pb]);
  for (const secret of ["PATHSECRET", "QUERYSECRET", "CONFIGSECRET", "ORGPATH", "ORGQUERY", "https://", "********"]) assert.ok(!all.includes(secret), secret);
  assert.ok(dump(s.store).includes("repo-0:9:example.com:"), "the host is kept");
  assert.ok(!JSON.stringify(s.store.kv.get("gh.reach.fp_key") ?? "").includes("example"), "the key is random bytes");
  assert.ok(!JSON.stringify([p, r, pb]).includes(String(s.store.kv.get("gh.reach.fp_key"))), "the key is never returned");
});

test("R23/R42: a hook or collaborator with a missing or unsupported field -> reach_shape, never fingerprinted", async () => {
  const cases: [string, (s: S) => void][] = [
    ["no id", (s) => (s.gh.org.hooks["repo-0"] = [{ ...hook(1), id: undefined }])],
    ["no url", (s) => (s.gh.org.hooks["repo-0"] = [hook(1, {}, { url: undefined })])],
    ["not http", (s) => (s.gh.org.hooks["repo-0"] = [hook(1, {}, { url: "ftp://example.com/x" })])],
    ["bad url", (s) => (s.gh.org.hooks["repo-0"] = [hook(1, {}, { url: "not a url" })])],
    ["events not array", (s) => (s.gh.org.hooks["repo-0"] = [hook(1, { events: "push" })])],
    ["active not boolean", (s) => (s.gh.org.hooks["repo-0"] = [hook(1, { active: "true" })])],
    ["content_type xml (R42)", (s) => (s.gh.org.hooks["repo-0"] = [hook(1, {}, { content_type: "xml" })])],
    ["content_type missing", (s) => (s.gh.org.hooks["repo-0"] = [hook(1, {}, { content_type: undefined })])],
    ["insecure_ssl \"2\" (R42)", (s) => (s.gh.org.hooks["repo-0"] = [hook(1, {}, { insecure_ssl: "2" })])],
    ["insecure_ssl missing", (s) => (s.gh.org.hooks["repo-0"] = [hook(1, {}, { insecure_ssl: undefined })])],
    ["org hook without config", (s) => (s.gh.org.orgHooks = [{ id: 3, events: ["push"], active: true }])],
    ["collaborator without role", (s) => (s.gh.org.collabs["repo-0"] = [{ login: "owner-a" }])],
    ["collaborator without login", (s) => (s.gh.org.collabs["repo-0"] = [{ role_name: "admin" }])],
    ["repo without id", (s) => (s.gh.org.repos[0] = { name: "repo-0", private: false, id: "x" })],
    ["list not an array", (s) => s.gh.set((p) => (p.startsWith(`/orgs/${ORG}/hooks`) ? Response.json({ message: "hi" }) : undefined))],
  ];
  for (const [what, plant] of cases) {
    const s = setup();
    plant(s);
    const p = await nightAll(s);
    assert.deepEqual({ state: p.state, code: p.code }, { state: "failed", code: "reach_shape" }, what);
  }
});

test("R24: a private repo with an empty collaborators list -> reach_collabs_empty; an empty public repo list is fine", async () => {
  const s = setup();
  s.gh.org.collabs["repo-0"] = []; // public
  assert.equal((await nightAll(s)).state, "complete");
  const p = setup();
  p.gh.org.collabs["repo-1"] = []; // private
  assert.deepEqual(await nightAll(p), { state: "failed", done: 0, total: 2, code: "reach_collabs_empty" });
});

test("R17: a repo replaced under the same name between slices -> reach_inventory_changed; the next slice starts again", async () => {
  const s = setup(20);
  await night(s);
  s.gh.org.repos[3] = { ...s.gh.org.repos[3], id: 9999 };
  const p = await night(s);
  assert.equal(p.code, "reach_inventory_changed");
  assert.equal(s.store.kv.get<any>("gh.reach.fail").reason, "reach_inventory_changed");
  const again = await night(s);
  assert.deepEqual(again, { state: "open", done: 18, total: 20, code: null }, "a new generation began");
  assert.equal(s.store.kv.get<any>("gh.reach.gen").seq, 2);
});

test("R18: the read's repo list differs from the main count's -> red; another App or installation -> red", async () => {
  const s = await greenNight();
  const main = s.main;
  (s.vault as any).ghRead = async () => ({ ...main(), repo_ids: [...main().repo_ids, "extra:1"].sort() });
  assert.match((await hc(s)).error, /reach_incomplete: inventory/);
  (s.vault as any).ghRead = async () => main();
  s.store.kv.put("gh.app.headcount", { ...s.store.kv.get<any>("gh.app.headcount"), installation: 1011 });
  assert.match((await hc(s)).error, /reach_incomplete: scope/);
});

test("R14: a delayed slice of a replaced generation writes nothing (reach_superseded)", async () => {
  const s = setup(20);
  s.clock.now = DAY;
  let release!: () => void;
  const held = new Promise<void>((r) => (release = r));
  let hold = true;
  s.gh.set((p) => (hold && p.includes("/repo-5/hooks") ? held.then(() => Response.json([])) : undefined));
  const slow = demand(s);
  await new Promise((r) => setTimeout(r, 20));
  hold = false;
  s.clock.now = NIGHT + 24 * 60 * MIN; // next night: the nightly start replaces the demand read
  const n1 = await night(s);
  assert.equal(n1.state, "open");
  const before = dump(s.store);
  release();
  assert.deepEqual(await slow, { state: "refused", done: 0, total: 0, code: "reach_superseded" });
  assert.equal(dump(s.store), before, "the loser wrote nothing");
});

test("R15 (6.2): an on-demand read and the nightly start at once -> one wins, the other reach_superseded", async () => {
  const s = setup(4);
  s.clock.now = DAY;
  const both = await Promise.all([demand(s), night(s)]);
  assert.deepEqual(both.map((p) => p.state).sort(), ["complete", "refused"]);
  assert.equal(both.find((p) => p.state === "refused")!.code, "reach_superseded");
  assert.equal(s.store.kv.get<any>("gh.reach.seq"), 1, "one generation exists");
});

test("R25/R26: failure -> replacement -> open, and a newer open read over an older complete one -> red", async () => {
  const s = await greenNight(20);
  s.clock.now = NIGHT + 35 * MIN;
  s.gh.set((p) => (p.includes("/collaborators") ? new Response(null, { status: 500 }) : undefined));
  assert.equal((await demand(s)).state, "failed"); // seq 2
  s.gh.set(undefined);
  assert.equal((await demand(s)).state, "open"); // replacement, seq 3, open
  const r = await hc(s);
  assert.equal(r.ok, false);
  assert.match(r.error, /reach_incomplete: newer_open/);
  const s2 = await greenNight(20);
  s2.clock.now = NIGHT + 35 * MIN;
  assert.equal((await demand(s2)).state, "open");
  assert.match((await hc(s2)).error, /reach_incomplete: newer_open/);
});

test("R29: no on-demand start inside 03:40-04:20 UTC; R30: a demand read open at 03:47 is replaced by the night and recorded", async () => {
  for (const at of [Date.UTC(2026, 10, 14, 3, 40), Date.UTC(2026, 10, 14, 4, 19)]) {
    const s = setup();
    s.clock.now = at;
    assert.deepEqual(await demand(s), { state: "refused", done: 0, total: 0, code: "reach_window" });
    assert.equal(s.gh.calls.length, 0);
  }
  const s = setup(20);
  s.clock.now = Date.UTC(2026, 10, 14, 3, 39);
  assert.equal((await demand(s)).state, "open");
  s.clock.now = NIGHT;
  assert.equal((await night(s)).state, "open");
  assert.deepEqual(s.store.kv.get("gh.reach.fail"), { seq: 1, reason: "reach_superseded" });
  assert.equal(s.store.kv.get<any>("gh.reach.gen").purpose, "night");
});

test("an open verify read is never replaced by a demand read: demand steps continue it", async () => {
  const s = setup(20);
  s.clock.now = DAY;
  s.store.transactionSync(() => (s.vault as any).reachReserve("verify:a1"));
  assert.equal((await demand(s)).state, "open");
  const g = s.store.kv.get<any>("gh.reach.gen");
  assert.equal(g.purpose, "verify:a1");
  assert.equal(g.repos.length, 18);
  assert.throws(() => s.store.transactionSync(() => (s.vault as any).reachReserve("verify:a2")), /reach_verify_open/);
  assert.equal((await step(s)).state, "complete");
  assert.equal(s.store.kv.get("gh.reach.night"), undefined, "a verify read never becomes the night");
});

test("step: nothing open and no purpose -> idle; an unknown purpose is refused", async () => {
  const s = setup();
  s.clock.now = DAY;
  assert.deepEqual(await step(s), { state: "idle", done: 0, total: 0, code: null });
  for (const bad of ["night", "verify:x", { purpose: "demand" }]) assert.deepEqual(await s.vault.ghReachStep(bad), { state: "refused", done: 0, total: 0, code: "reach_bad_purpose" });
  assert.equal(s.gh.calls.length, 0);
});

test("R31: the 03:47 and 03:52 invocations continue one night; a third call after completion reads nothing", async () => {
  const s = setup(20);
  await night(s);
  s.clock.now = NIGHT + 5 * MIN;
  assert.equal((await night(s)).state, "complete");
  assert.equal(s.store.kv.get<any>("gh.reach.seq"), 1);
  s.gh.calls.length = 0;
  assert.equal((await night(s)).state, "complete");
  assert.equal(s.gh.calls.length, 0);
});

test("R32/R41: a demand read completed after the night keeps the scheduled count on the night; on demand selects the newest", async () => {
  const s = await greenNight();
  s.gh.org.hooks["repo-0"] = [hook(77)];
  s.clock.now = NIGHT + 40 * MIN;
  assert.equal((await demandAll(s)).state, "complete");
  assert.deepEqual(await hc(s, "night"), { ok: true, changes: [] }, "04:17 selects the night");
  assert.equal(s.store.kv.get<any>("gh.reach.night").purpose, "night");
  const any = await hc(s, "any");
  assert.equal(any.ok, false);
  assert.match(any.changes[0], /^repo_hooks \+repo-0:77:/);
  // The public headcount() defaults to the scheduled selection.
  assert.equal((await s.vault.headcount()).github.ok, true);
  assert.equal((await s.vault.headcount("any")).github.ok, false);
});

test("no accepted reach list yet -> red reach_no_baseline (fail closed)", async () => {
  const s = setup();
  await nightAll(s);
  s.clock.now = NIGHT + 30 * MIN;
  const r = await hc(s);
  assert.equal(r.ok, false);
  assert.match(r.error, /reach_no_baseline/);
});

test("R38: fingerprint key lost while the accepted list holds hooks -> red reach_fp_key_lost; the read never re-keys", async () => {
  const s = setup();
  s.gh.org.hooks["repo-0"] = [hook(5)];
  await nightAll(s);
  accept(s);
  (s.store as any).kv.delete("gh.reach.fp_key");
  s.clock.now = NIGHT + 30 * MIN;
  assert.match((await hc(s)).error, /reach_fp_key_lost/);
  s.clock.now = DAY;
  assert.equal((await demandAll(s)).code, "reach_fp_key_lost");
  assert.equal(s.store.kv.get("gh.reach.fp_key"), undefined, "no silent new key");
  // With no hooks accepted, a missing key is simply made (first run).
  const fresh = setup();
  assert.equal((await nightAll(fresh)).state, "complete");
  assert.match(String(fresh.store.kv.get("gh.reach.fp_key")), /^[A-Za-z0-9_-]{43}$/);
});

test("the main count still names its own changes alongside a red reach part, and an unset App stays github_not_set_up", async () => {
  const s = setup();
  s.store.kv.put("gh.baseline", null);
  s.store.kv.put("gh.app.headcount", null);
  assert.deepEqual(await hc(s), { ok: false, changes: [], error: "github_not_set_up" });
});

test("a repo named like an object property (constructor, __proto__, toString) is read like any other", async () => {
  const s = setup(3);
  s.gh.org.repos = ["constructor", "__proto__", "toString"].map((name, i) => ({ name, id: 7000 + i, private: false }));
  // The fake's own maps must not have a prototype either, or it would answer with Object's own properties.
  s.gh.org.hooks = Object.create(null);
  s.gh.org.collabs = Object.create(null);
  for (const r of s.gh.org.repos) {
    s.gh.org.hooks[r.name as string] = [hook(40)];
    s.gh.org.collabs[r.name as string] = [];
  }
  assert.deepEqual(await nightAll(s), { state: "complete", done: 3, total: 3, code: null });
  for (const name of ["constructor", "__proto__", "toString"]) assert.ok(s.gh.calls.some((c) => c.path.startsWith(`/repos/${ORG}/${name}/hooks`)), name);
  accept(s);
  assert.equal(s.store.kv.get<any>("gh.reach.baseline").repo_hooks.length, 3);
});

test("a generation is read by one App installation only: a slice after the installation changed fails reach_scope_changed", async () => {
  const s = setup(20);
  await night(s);
  s.store.kv.put("gh.app.headcount", { ...s.store.kv.get<any>("gh.app.headcount"), installation: 1011 });
  assert.equal((await night(s)).code, "reach_scope_changed");
});

// ---- Part B: accepting the list (job gh.reach.baseline; spec 11.3, 12.2-12.4, 13.1) ----
const PRF = b64url(new Uint8Array(32).fill(7));
type Shown = Awaited<ReturnType<VaultLogic["ghReachPreview"]>>;
// Ben's tap with what his screen showed (the desk's params: the preview's fields, changes as lines).
const tap = async (s: S, shown?: Shown, o: { id?: string } = {}) => {
  const seen = shown ?? (await s.vault.ghReachPreview());
  const { changes, ...bound } = seen;
  return signedRun(s.vault, "gh.reach.baseline", { changes: changes.join("\n") || "none", ...bound }, PRF, o) as Promise<GhReachAcceptResult>;
};
const approvals = (s: S) => [...s.store.kv.list<any>({ prefix: "gh.reach.approval:" })].map(([, a]) => a);
async function stepAll(s: S) {
  let p = await step(s);
  for (let i = 0; i < 4 && p.state === "open"; i++) p = await step(s);
  return p;
}
// A fresh complete demand read at 10:00, ready to preview.
async function readDay(n = 2) {
  const s = setup(n, DAY);
  assert.equal((await demandAll(s)).state, "complete");
  return s;
}

test("first acceptance: no list and no key yet; the tap writes nothing, the re-read records exactly what Ben saw", async () => {
  const s2 = await readDay();
  s2.gh.org.hooks["repo-0"] = [hook(3)];
  await demandAll(s2);
  const shown = await s2.vault.ghReachPreview();
  assert.ok(shown.changes.some((c) => c.startsWith("repo_hooks +repo-0:3:example.com:")), JSON.stringify(shown.changes));
  const r = await tap(s2, shown);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.state, "pending");
  assert.equal(s2.store.kv.get("gh.reach.baseline"), undefined, "the tap records no list");
  assert.equal(s2.store.kv.get<any>("gh.reach.gen").purpose, `verify:${approvals(s2)[0].id}`);
  const p = await stepAll(s2);
  assert.equal(p.acceptance, "accepted");
  assert.equal(approvals(s2)[0].state, "accepted");
  assert.deepEqual(s2.store.kv.get<any>("gh.reach.baseline").repo_hooks.length, 1);
  assert.deepEqual(await hc(s2, "any"), { ok: true, changes: [] });
  assert.ok(!JSON.stringify(p).includes("example.com"), "progress carries no hosts");
});

test("R12/R19: GitHub changes between Ben's screen and the re-read -> refused, nothing recorded", async () => {
  const s = await readDay();
  const shown = await s.vault.ghReachPreview();
  s.gh.org.collabs["repo-0"].push({ login: "someone-b", role_name: "write" });
  assert.equal((await tap(s, shown)).ok, true);
  const p = await stepAll(s);
  assert.deepEqual({ a: p.acceptance, code: p.code }, { a: "refused", code: "reach_changed_since_request" });
  assert.equal(s.store.kv.get("gh.reach.baseline"), undefined);
  // During the re-read (tap first, change after): also refused.
  const t = await readDay(20);
  assert.equal((await tap(t)).ok, true);
  assert.equal((await step(t)).state, "open");
  t.gh.org.hooks["repo-19"] = [hook(8)];
  assert.equal((await step(t)).acceptance, "refused");
});

test("R21: the accepted list changed by anyone between preview and completion -> refused, the other write survives", async () => {
  const s = await readDay(20);
  assert.equal((await tap(s)).ok, true);
  await step(s);
  const other = { repo_hooks: [], org_hooks: [], collaborators: ["x:y:admin"] };
  s.store.kv.put("gh.reach.baseline", other);
  assert.deepEqual({ a: (await step(s)).acceptance, list: s.store.kv.get("gh.reach.baseline") }, { a: "refused", list: other });
  assert.equal(approvals(s)[0].reason, "reach_baseline_changed");
});

test("R20: an approval past its 20 minutes ends expired and its read fails; nothing recorded", async () => {
  const s = await readDay(20);
  assert.equal((await tap(s)).ok, true);
  await step(s);
  s.clock.now += 21 * MIN;
  const p = await step(s);
  assert.deepEqual({ state: p.state, code: p.code, a: p.acceptance }, { state: "failed", code: "reach_verify_expired", a: "expired" });
  assert.equal(s.store.kv.get("gh.reach.baseline"), undefined);
});

test("R22: any of the three write probes granted -> tap fails, that key is deleted, no approval and no read", async () => {
  for (const perm of ["repository_hooks", "organization_hooks", "administration"]) {
    const s = await readDay();
    s.gh.faults.grantWrite = perm;
    const before = s.gh.deleted.length;
    const r = await tap(s);
    assert.equal(r.ok, false, perm);
    assert.match(r.error ?? "", /not refused write/);
    assert.equal(s.gh.deleted.length, before + 1, `${perm}: the granted key was revoked`);
    assert.deepEqual(approvals(s), []);
    assert.notEqual(s.store.kv.get<any>("gh.reach.gen").purpose.slice(0, 7), "verify:");
  }
  // An unrelated failure of a probe is not a refusal either (Release Checklist 6.1).
  const s = await readDay();
  s.gh.set((p) => (p.endsWith("/access_tokens") ? Response.json({ message: "Server Error" }, { status: 500 }) : undefined));
  assert.equal((await tap(s)).ok, false);
  assert.deepEqual(approvals(s), []);
});

test("R28/R39: admission by the tap's own time: a tap whose 20 minutes reach 03:40 is refused, no approval, no read; the preview says so first", async () => {
  const s = setup(2, Date.UTC(2026, 10, 14, 3, 10));
  await demandAll(s);
  s.clock.now = Date.UTC(2026, 10, 14, 3, 15);
  const shown = await s.vault.ghReachPreview();
  s.clock.now = Date.UTC(2026, 10, 14, 3, 21);
  const r = await tap(s, shown);
  assert.deepEqual({ ok: r.ok, error: r.error }, { ok: false, error: "reach_try_after_0420" });
  assert.deepEqual(approvals(s), []);
  assert.equal(s.store.kv.get<any>("gh.reach.gen").purpose, "demand");
  await assert.rejects(s.vault.ghReachPreview(), /reach_try_after_0420/);
  s.clock.now = Date.UTC(2026, 10, 14, 4, 0);
  await assert.rejects(s.vault.ghReachPreview(), /reach_try_after_0420/);
  // 03:19 + 20 min = 03:39: admitted. A nightly start before it ends supersedes it; one after its expiry ends it expired.
  for (const [at, state] of [[Date.UTC(2026, 10, 14, 3, 30), "superseded"], [NIGHT, "expired"]] as const) {
    const ok = setup(2, Date.UTC(2026, 10, 14, 3, 5));
    await demandAll(ok);
    ok.clock.now = Date.UTC(2026, 10, 14, 3, 19);
    assert.equal((await tap(ok)).ok, true);
    ok.clock.now = at;
    assert.equal((await night(ok)).state, "complete");
    assert.equal(approvals(ok)[0].state, state);
    assert.equal(ok.store.kv.get("gh.reach.baseline"), undefined);
  }
});

test("R40 (6.2): two taps at once -> exactly one approval and one verify read", async () => {
  const s = await readDay();
  const shown = await s.vault.ghReachPreview();
  const both = await Promise.all([tap(s, shown), tap(s, shown)]);
  assert.deepEqual(both.map((r) => r.ok).sort(), [false, true]);
  assert.equal(both.find((r) => !r.ok)!.error, "reach_verify_open");
  assert.equal(approvals(s).length, 1);
});

test("preview: no fresh complete read -> reach_read_first; an open verify -> reach_verify_open; a lost key -> reach_fp_key_lost", async () => {
  const s = setup(2, DAY);
  await assert.rejects(s.vault.ghReachPreview(), /reach_read_first/);
  await demandAll(s);
  s.clock.now = DAY + 61 * MIN;
  await assert.rejects(s.vault.ghReachPreview(), /reach_read_first/);
  const v = await readDay(20);
  assert.equal((await tap(v)).ok, true);
  await assert.rejects(v.vault.ghReachPreview(), /reach_verify_open/);
  const k = await readDay();
  k.store.kv.put("gh.reach.baseline", { repo_hooks: ["repo-0:1:example.com:abc:push:true"], org_hooks: [], collaborators: [] });
  (k.store as any).kv.delete("gh.reach.fp_key");
  await assert.rejects(k.vault.ghReachPreview(), /reach_fp_key_lost/);
});

test("removal invalidates the approval (6.3): another App or installation before completion -> refused at the tap or completion", async () => {
  const s = await readDay();
  const shown = await s.vault.ghReachPreview();
  s.store.kv.put("gh.app.headcount", { ...s.store.kv.get<any>("gh.app.headcount"), installation: 1011 });
  const r = await tap(s, shown);
  assert.deepEqual({ ok: r.ok, error: r.error }, { ok: false, error: "reach_scope_changed" });
  assert.deepEqual(approvals(s), []);
});

test("rates: at most 12 on-demand steps an hour; verify steps are exempt but capped per approval", async () => {
  const s = setup(2, DAY);
  for (let i = 0; i < 12; i++) assert.equal((await step(s)).state, "idle");
  assert.deepEqual(await step(s), { state: "refused", done: 0, total: 0, code: "reach_rate_limited" });
  s.clock.now += 60 * MIN;
  assert.equal((await demandAll(s)).state, "complete");
  for (let i = 0; i < 9; i++) await step(s);
  assert.equal((await tap(s)).ok, true);
  const g = s.store.kv.get<any>("gh.reach.gen");
  s.store.kv.put("gh.reach.gen", { ...g, rev: 3 }); // already used its ceil(2/18) + 1 = 2 slices
  assert.deepEqual(await step(s), { state: "refused", done: 0, total: 0, code: "reach_verify_steps" });
});
