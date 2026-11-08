// Job gh.repo.create (card 77ec1e64; studio-os spike-08313e62/THREATS-77ec1e64.md). Every test goes through the real
// card path -- CardBook.open/run -> VaultLogic.runCardEntry -> vault/src/ghrepo.ts -> a fake GitHub -- so each threat
// is tested where it enters (RCA 5d9fcd1c), not in the helper alone (Codex r1 X4). The fake GitHub hands out known key
// values, so the leak search (T7) can look for them everywhere. Mutants: test/cards-mutants.json (c4-*).
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { CardBook } from "../vault/src/cards.ts";
import { GH_LABEL, VaultLogic } from "../vault/src/vault.ts";
import { ORG, PERMISSIONS, diff, pkcs8FromPem, type GhSnapshot } from "../vault/src/github.ts";
import { seal, secretBytes } from "../vault/src/seal.ts";
import { CREATE_PERMS } from "../vault/src/ghrepo.ts";
import { MemoryCardStore, PRF, TestRecorder, makeCard, openReq, runReq } from "./cardsign.ts";
import { TEST_PIN, signedRun } from "./vaultsign.ts";

const T = 1_800_000_000_000;
const MAIN = 202;
const INST = 2020;
const REPO_ID = 777001;
const refused = (code: string) => new RegExp(`^Error: ${code}`);

type Fault =
  | "bypass" | "noBypassField" | "noRule" | "twoRules" | "exists" | "exists500" | "mintRefused"
  | "createLost" | "create500" | "create422" | "createPublic" | "createNoId" | "createLate" | "revokeFails" | "wideApp" | "notAll"
  | "create422dup" | "create403" | "create409" | "create400" | "create422raw" | "createWholeSecond";

const pem = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs1", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } }).privateKey as string;

/** A fake GitHub for the repo-maker App: records every call, hands out known key values, honours revokes. */
function fakeGitHub(clock: { now: number }, faults: Fault[] = []) {
  const has = (f: Fault) => faults.includes(f);
  const calls: { method: string; path: string; by: string; body?: unknown }[] = [];
  const tokens = new Map<string, Record<string, string>>();
  const revoked = new Set<string>();
  const handed: string[] = [];
  let n = 0;
  const json = (body: unknown, status = 200) => Response.json(body, { status });
  const fetchFn = async (input: string, init?: RequestInit) => {
    const url = new URL(input);
    const path = url.pathname;
    const method = init?.method ?? "GET";
    const auth = String((init?.headers as Record<string, string>)?.authorization ?? "").replace("Bearer ", "");
    const by = tokens.has(auth) ? (revoked.has(auth) ? "revoked" : `token:${auth}`) : auth.split(".").length === 3 ? "jwt" : "none";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path: path + url.search, by, body });
    if (by === "revoked" || by === "none") return json({ message: "Bad credentials" }, 401);
    if (by === "jwt") {
      if (path === "/app") return json({ id: MAIN, permissions: { ...PERMISSIONS.main, ...(has("wideApp") ? { members: "write" } : {}) } });
      if (path === `/app/installations/${INST}`) return json({ account: { login: ORG }, repository_selection: has("notAll") ? "selected" : "all", permissions: PERMISSIONS.main });
      if (path === "/app/installations") return json([{ id: INST }]);
      if (path === `/app/installations/${INST}/access_tokens` && method === "POST") {
        if (has("mintRefused") && body?.permissions?.repository_creation) return json({ message: "The level of access for permissions requested are not granted to this installation." }, 422);
        const t = `ghs_known_${++n}_secret`;
        tokens.set(t, body?.permissions ?? {});
        handed.push(t);
        return json({ token: t, expires_at: new Date(clock.now + 3600_000).toISOString() }, 201);
      }
    }
    if (by.startsWith("token:")) {
      const t = by.slice(6);
      const perms = tokens.get(t)!;
      if (method === "DELETE" && path === "/installation/token") {
        if (has("revokeFails")) return json({ message: "Server Error" }, 500);
        revoked.add(t);
        return new Response(null, { status: 204 });
      }
      if (path === "/installation/repositories") return json({ total_count: 1, repositories: [] });
      if (path === `/repos/${ORG}/front-desk/rulesets` && perms.administration === "write") {
        if (has("noRule")) return json([]);
        return json(has("twoRules") ? [{ id: 5, name: "protect-main" }, { id: 6, name: "protect-main" }] : [{ id: 5, name: "protect-main" }, { id: 9, name: "other" }]);
      }
      if (path === `/repos/${ORG}/front-desk/rulesets/5` && perms.administration === "write") {
        const rule: Record<string, unknown> = { id: 5, name: "protect-main", enforcement: "active" };
        if (!has("noBypassField")) rule.bypass_actors = has("bypass") ? [{ actor_type: "RepositoryRole", actor_id: 5 }] : [];
        return json(rule);
      }
      if (method === "GET" && path === `/repos/${ORG}/new-app` && perms.repository_creation === "write") {
        if (has("exists500")) return json({ message: "Server Error" }, 500);
        return has("exists") ? json({ id: 1, name: "new-app" }) : json({ message: "Not Found" }, 404);
      }
      if (method === "POST" && path === `/orgs/${ORG}/repos` && perms.repository_creation === "write") {
        if (has("createLost")) throw new TypeError("network connection lost");
        if (has("create500")) return json({ message: "Server Error" }, 502);
        if (has("create422")) return json({ message: "Repository creation failed." }, 422);
        if (has("create422dup")) return json({ message: "Repository creation failed.", errors: [{ resource: "Repository", code: "custom", field: "name", message: "name already exists on this account" }] }, 422);
        if (has("create403")) return json({ message: "Forbidden" }, 403);
        if (has("create409")) return json({ message: "Conflict" }, 409);
        if (has("create400")) return json({ message: "Bad Request" }, 400);
        if (has("create422raw")) return new Response("<html>oops</html>", { status: 422 });
        const at = has("createLate") ? clock.now + 60 * 60_000 : has("createWholeSecond") ? Math.floor(clock.now / 1000) * 1000 : clock.now;
        return json({ ...(has("createNoId") ? {} : { id: REPO_ID }), name: body.name, private: !has("createPublic"), owner: { login: ORG }, created_at: new Date(at).toISOString() }, 201);
      }
    }
    return json({ message: `unexpected ${method} ${path} by ${by}` }, 404);
  };
  return { calls, fetchFn, handed, revoked, tokens };
}

const BASELINE: GhSnapshot = { repos: ["front-desk:public"], repo_ids: ["front-desk:9001"], members: ["weird-ways"], owners: ["weird-ways"], outside: [], invites: [], apps: [], pats: [], deploy_keys: [], rulesets: [] };

/** The vault set up as live: the repo-maker App sealed to Ben's passkey secret (PRF), installed, and an accepted list. */
async function setup(faults: Fault[] = [], o: { baseline?: GhSnapshot | null; locked?: boolean } = {}) {
  const store = new MemoryCardStore();
  const clock = { now: T };
  const gh = fakeGitHub(clock, faults);
  const key = pkcs8FromPem(pem);
  store.kv.put("gh.app.main", { id: MAIN, slug: "wws-front-desk", installation: INST, ...(o.locked === false ? {} : { by_passkey: await seal(secretBytes(PRF), GH_LABEL, key) }) });
  if (o.baseline !== null) store.kv.put("gh.baseline", o.baseline ?? BASELINE);
  const rec = await TestRecorder.create();
  const vault = new VaultLogic(store, gh.fetchFn, () => clock.now, TEST_PIN);
  const book = new CardBook(store, (job, params, prf) => vault.runCardEntry(job, params, prf), TEST_PIN, { now: () => clock.now, recorderKey: rec.pub });
  return { store, clock, gh, rec, vault, book };
}

const repoCard = (name = "new-app", more: [string, Record<string, string>][] = []) => makeCard(T, [["gh.repo.create", { name }], ...more]);
/** Opens a card and runs entry 0; returns the entry state and its answer. */
async function runRepo(s: Awaited<ReturnType<typeof setup>>, name = "new-app", more: [string, Record<string, string>][] = []) {
  const c = await repoCard(name, more);
  await s.book.open(openReq(c));
  const r = await s.book.run(await runReq(c, 0, s.rec));
  return { c, state: r.state, answer: r.card.answers[0] as Record<string, any>, card: r.card };
}
/** The done result body the desk freezes for entry 0 (src/carddesk.ts sendResult), and its recorder receipt. */
async function resultOf(s: Awaited<ReturnType<typeof setup>>, grant: string, over: Record<string, unknown> = {}) {
  const body = JSON.stringify({ v: 1, grant, stage: "result", job: "gh.repo.create", request: "r".repeat(64), outcome: "done", at: T, repo_id: String(REPO_ID), ...over });
  return { body, receipt: await s.rec.receipt(grant, "result", body) };
}
const posts = (gh: ReturnType<typeof fakeGitHub>) => gh.calls.filter((c) => c.method === "POST" && c.path === `/orgs/${ORG}/repos`);

// ---- Outcome 1, 2: the success path ----
test("one tap makes the repo: private, empty, by name and id; 13 GitHub calls; both keys narrowed, deleted and probed 401 (F9 X5)", async () => {
  const s = await setup();
  const { state, answer, card } = await runRepo(s);
  assert.equal(state, "done");
  assert.equal(card.closed_at, T, "a one-entry card closes when its entry is done");
  assert.deepEqual({ ok: answer.ok, created: answer.created, name: answer.name, repo_id: answer.repo_id }, { ok: true, created: "confirmed", name: "new-app", repo_id: String(REPO_ID) });
  assert.deepEqual(posts(s.gh)[0].body, { name: "new-app", private: true, auto_init: false, has_wiki: false });
  assert.equal(s.gh.calls.length, 13, s.gh.calls.map((c) => `${c.method} ${c.path}`).join("\n"));
  // The two mints: exactly the narrowed permissions, the rule-read key on front-desk only.
  const mints = s.gh.calls.filter((c) => c.path.endsWith("/access_tokens"));
  assert.deepEqual(mints.map((m) => m.body), [{ permissions: { administration: "write" }, repositories: ["front-desk"] }, { permissions: { repository_creation: "write", metadata: "read" } }]);
  assert.deepEqual(CREATE_PERMS, { repository_creation: "write", metadata: "read" }, "the creation key cannot delete or transfer");
  assert.deepEqual(answer.keys.map((k: any) => [k.purpose, k.revoke_status, k.probe_status, k.revoke]), [["rule-read", 204, 401, "proven"], ["create", 204, 401, "proven"]]);
  assert.equal(s.gh.revoked.size, 2);
  // Settle wrote the durable record, eligible; the nightly list is NOT touched until the recorder's receipt (Y1).
  assert.deepEqual(s.book.repoFacts(s.store.kv.list<any>({ prefix: "gh.created:" })[0][1].grant), { grant: s.store.kv.list<any>({ prefix: "gh.created:" })[0][1].grant, card: card.card, name: "new-app", repo_id: String(REPO_ID), created_at: new Date(T).toISOString(), eligible: true, recorded: false });
  assert.deepEqual(s.store.kv.get("gh.baseline"), BASELINE, "no baseline line before the receipt");
});

// ---- T3 / X3: the vault's own name check, before any network call ----
test("T3: a correctly signed card holding a bad name fails bad_params with ZERO GitHub calls", async () => {
  for (const name of ["Bad", "a--b", "-a", "a", "x".repeat(65), "a_b", "a.b", "../x"]) {
    const s = await setup();
    const { state, answer } = await runRepo(s, name);
    assert.equal(state, "failed", name);
    assert.equal(answer.refusal, "bad_params", name);
    assert.equal(s.gh.calls.length, 0, `${name}: no fetch`);
  }
});

// ---- T4: card only ----
test("T4: the standalone vault.run refuses gh.repo.create with a valid signed grant: job_not_offered, nothing called", async () => {
  const s = await setup();
  await assert.rejects(signedRun(s.vault, "gh.repo.create", { name: "new-app" }, PRF), refused("job_not_offered"));
  assert.equal(s.gh.calls.length, 0);
});

// ---- C6a-2 2.1, 2.2: set up, App and install no wider than allowed ----
test("2.1/2.2: no locked App, no accepted list, an App or install wider than the repo-maker's -> failed, nothing created", async () => {
  for (const [label, s, code] of [
    ["not locked", await setup([], { locked: false }), "github_not_set_up"],
    ["no baseline", await setup([], { baseline: null }), "no_baseline"],
    ["wide App", await setup(["wideApp"]), "app_permissions_too_wide"],
    ["install not on all repos", await setup(["notAll"]), "installation_not_all_repositories"],
  ] as const) {
    const { state, answer } = await runRepo(s);
    assert.equal(state, "failed", label);
    assert.match(String(answer.error ?? answer.refusal), new RegExp(`^${code}`), label);
    assert.equal(posts(s.gh).length, 0, `${label}: no create`);
  }
});

// ---- T8: the bypass list ----
test("T8: a bypass actor on protect-main, a missing bypass field, no rule or two rules -> failed before create; the rule key is still deleted", async () => {
  for (const [f, code] of [["bypass", "bypass_on_protect_main: RepositoryRole#5"], ["noBypassField", "bypass_unreadable: no bypass list shown"], ["noRule", "bypass_unreadable: protect-main not found once"], ["twoRules", "bypass_unreadable: protect-main not found once"]] as const) {
    const s = await setup([f]);
    const { state, answer } = await runRepo(s);
    assert.equal(state, "failed", f);
    assert.deepEqual({ created: answer.created, refusal: answer.refusal }, { created: "absent", refusal: code }, f);
    assert.equal(posts(s.gh).length, 0, `${f}: no create`);
    assert.equal(s.gh.calls.filter((c) => c.path.endsWith("/access_tokens")).length, 1, `${f}: the creation key is never minted`);
    assert.deepEqual(answer.keys.map((k: any) => [k.purpose, k.revoke]), [["rule-read", "proven"]], `${f}: the rule-read key deleted and probed`);
    assert.equal(s.gh.calls.length, f === "noRule" || f === "twoRules" ? 7 : 8, `${f}: F9 count on a refusal path (3 checks, 1 mint, rule reads, delete, probe)`);
  }
});

// ---- T10: check before write ----
test("T10: an existing repo -> failed repo_exists, no create; an unreadable existence answer -> failed, no create", async () => {
  for (const [f, code] of [["exists", "repo_exists"], ["exists500", "existence_unreadable: gh_500: Server Error"]] as const) {
    const s = await setup([f]);
    const { state, answer } = await runRepo(s);
    assert.equal(state, "failed", f);
    assert.equal(answer.refusal, code, f);
    assert.equal(posts(s.gh).length, 0, f);
    assert.ok(answer.keys.every((k: any) => k.revoke === "proven"), `${f}: both keys deleted`);
  }
});

test("Open fact 1 (X6): GitHub refusing the narrowed creation mint -> failed, nothing created, no wider key tried", async () => {
  const s = await setup(["mintRefused"]);
  const { state, answer } = await runRepo(s);
  assert.equal(state, "failed");
  assert.match(answer.refusal, /^gh_422: The level of access/);
  assert.equal(posts(s.gh).length, 0);
  assert.equal(s.gh.calls.filter((c) => c.path.endsWith("/access_tokens")).length, 2, "one refused mint, no fallback to administration");
});

// ---- T9: GitHub's reply ----
test("T9: a lost or 5xx create reply -> unknown, the card ends, facts kept, keys still deleted; a 4xx -> failed absent", async () => {
  for (const f of ["createLost", "create500"] as const) {
    const s = await setup([f]);
    const { state, answer, card } = await runRepo(s, "new-app", [["test.echo", { word: "after" }]]);
    assert.equal(state, "unknown", f);
    assert.equal(answer.created, "unknown", f);
    assert.equal(answer.ok, null, f);
    assert.ok(answer.notes.length >= 1, `${f}: why is kept`);
    assert.deepEqual(card.entries.map((e) => e.state), ["unknown", "not_run"], `${f}: nothing after it starts`);
    assert.deepEqual(answer.keys.map((k: any) => k.revoke), ["proven", "proven"], f);
    assert.equal(s.store.kv.list({ prefix: "gh.created:" }).length, 0, `${f}: no repo record without an id`);
  }
  const s = await setup(["create422"]);
  const { state, answer } = await runRepo(s);
  assert.equal(state, "failed");
  assert.deepEqual({ created: answer.created, refusal: answer.refusal }, { created: "absent", refusal: "create_refused: gh_422" });
});

test("T9: a reply that is public, or has no id -> created not_as_asked -> unknown; no record is eligible", async () => {
  for (const f of ["createPublic", "createNoId"] as const) {
    const s = await setup([f]);
    const { state, answer } = await runRepo(s);
    assert.equal(state, "unknown", f);
    assert.equal(answer.created, "not_as_asked", f);
    assert.match(answer.notes.join(" "), /differs from what was asked/, f);
    assert.equal(s.store.kv.list({ prefix: "gh.created:" }).length, 0, `${f}: not done, so no record to add`);
  }
});

// ---- X4: cleanup failures after creation keep the creation facts ----
test("X4: both revokes failing after a create keeps created confirmed and the id; every key still gets its DELETE and probe", async () => {
  const s = await setup(["revokeFails"]);
  const { state, answer } = await runRepo(s);
  assert.equal(state, "done", "the repo was made as asked; cleanup does not rewrite that");
  assert.equal(answer.repo_id, String(REPO_ID));
  assert.deepEqual(answer.keys.map((k: any) => [k.revoke_status, k.probe_status, k.revoke]), [[500, 200, "unproven"], [500, 200, "unproven"]]);
  assert.equal(s.gh.calls.filter((c) => c.method === "DELETE").length, 2);
  assert.equal(s.gh.calls.filter((c) => c.path.startsWith("/installation/repositories")).length, 2);
  assert.match(answer.notes.join(" "), /create key: revoke unproven \(delete 500, probe 200\)/);
  assert.equal(s.gh.calls.length, 13, "F9 (X5): the cleanup path makes the same 13 calls");
});

// ---- T7: no key value anywhere ----
test("T7: no key GitHub handed out appears in the answer, the card view, the stored book, records or the grant", async () => {
  for (const faults of [[], ["createLost"], ["bypass"], ["revokeFails"]] as Fault[][]) {
    const s = await setup(faults);
    const { card } = await runRepo(s);
    assert.ok(s.gh.handed.length >= 1, "the fake handed out keys");
    const everything = [s.store.dump(), JSON.stringify(card), JSON.stringify(s.book.status(card.card))].join("\n");
    for (const t of s.gh.handed) assert.ok(!everything.includes(t), `${faults}: ${t} leaked`);
    assert.doesNotMatch(everything, /ghs_/, `${faults}: no token-shaped string`);
  }
});

// ---- T15 / Z2: the creation window ----
test("T15: GitHub's created_at outside [card open, deadline] -> unknown, the record is never eligible, repoRecorded refuses", async () => {
  const s = await setup(["createLate"]);
  const { state, c } = await runRepo(s);
  assert.equal(state, "unknown");
  const rec = s.book.repoFacts(c.grants[0].id)!;
  assert.equal(rec.eligible, false);
  const { body, receipt } = await resultOf(s, c.grants[0].id);
  await assert.rejects(s.book.repoRecorded(c.grants[0].id, body, receipt), refused("repo_not_eligible"));
  assert.deepEqual(s.store.kv.get("gh.baseline"), BASELINE);
});

test("T15: an entry the alarm already closed unknown, settling late as done, leaves an ineligible record", async () => {
  const s = await setup();
  const c = await repoCard();
  await s.book.open(openReq(c));
  // The GitHub create is slow: the deadline passes and the alarm closes the entry while it is out.
  const slow = s.gh.fetchFn;
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  (s.vault as any).fetch = async (i: string, init?: RequestInit) => (init?.method === "POST" && i.endsWith(`/orgs/${ORG}/repos`) ? (await gate, slow(i, init)) : slow(i, init));
  const run = s.book.run(await runReq(c, 0, s.rec));
  await new Promise((r) => setTimeout(r, 50));
  s.clock.now = c.manifest.deadline + 1;
  await s.book.alarm();
  release();
  const r = await run;
  assert.equal(r.state, "unknown");
  assert.equal(r.card.entries[0].late, "done");
  assert.equal(s.book.repoFacts(c.grants[0].id)?.eligible, false);
});

// ---- T11, Y1, Z1-Z3: the baseline add, only after the recorder's receipt over the exact body ----
test("T11/Y1: the recorder's receipt over the exact done body adds exactly two lines, once; a planted change still alarms", async () => {
  const s = await setup();
  const { c } = await runRepo(s);
  const g = c.grants[0].id;
  const { body, receipt } = await resultOf(s, g);
  assert.deepEqual(await s.book.repoRecorded(g, body, receipt), { recorded: "now" });
  const after = s.store.kv.get<GhSnapshot>("gh.baseline")!;
  assert.deepEqual(diff(BASELINE, after), ["repos +new-app:private", `repo_ids +new-app:${REPO_ID}`], "exactly the two lines, nothing else");
  assert.deepEqual(await s.book.repoRecorded(g, body, receipt), { recorded: "already" }, "a second call is a no-op that confirms (Z1)");
  assert.deepEqual(s.store.kv.get("gh.baseline"), after);
  // The night after: GitHub shows the repo plus a planted, unrelated change -> only the planted change alarms.
  const night = { ...after, members: [...after.members, "intruder"] };
  assert.deepEqual(diff(after, night), ["members +intruder"]);
});

test("Z3: a genuine receipt with an altered body, a forged or borrowed receipt, another stage -> refused, no line", async () => {
  const s = await setup();
  const { c } = await runRepo(s);
  const g = c.grants[0].id;
  const good = await resultOf(s, g);
  const cases: [string, () => Promise<unknown>][] = [];
  // Each body field changed under the genuine receipt: the hash no longer matches. `at` and `request` are fields only
  // the hash binds (the body checks do not read them), so the recorder's receipt must be over exactly these bytes.
  for (const over of [{ repo_id: "999" }, { outcome: "failed" }, { job: "test.echo" }, { grant: "g-other-xxxx" }, { stage: "approval" }, { at: 5 }, { request: "x".repeat(64) }]) {
    cases.push([`altered ${Object.keys(over)[0]}`, () => s.book.repoRecorded(g, JSON.stringify({ ...JSON.parse(good.body), ...over }), good.receipt)]);
  }
  // Signed by the recorder over an altered body: the hash matches, the body does not.
  for (const over of [{ repo_id: "999" }, { outcome: "failed" }, { job: "test.echo" }, { grant: "g-other-xxxx" }, { stage: "approval" }]) {
    const x = await resultOf(s, g, over);
    cases.push([`signed altered ${Object.keys(over)[0]}`, () => s.book.repoRecorded(g, x.body, x.receipt)]);
  }
  const forger = await TestRecorder.create();
  const forged = await forger.receipt(g, "result", good.body);
  cases.push(["forged", () => s.book.repoRecorded(g, good.body, forged)]);
  const borrowed = await s.rec.receipt("g-other-xxxx", "result", good.body);
  cases.push(["borrowed from another grant", () => s.book.repoRecorded(g, good.body, borrowed)]);
  const stage = await s.rec.receipt(g, "approval", good.body);
  cases.push(["approval-stage receipt", () => s.book.repoRecorded(g, good.body, stage)]);
  cases.push(["receipt with no signature", () => s.book.repoRecorded(g, good.body, { ...good.receipt, sig: undefined })]);
  cases.push(["extra argument", () => (s.book.repoRecorded as any).call(s.book, g, good.body, good.receipt, "x")]);
  const other = await s.rec.receipt("g-nothing-xxxx", "result", good.body);
  cases.push(["unknown grant", () => s.book.repoRecorded("g-nothing-xxxx", good.body, other)]);
  for (const [label, p] of cases) await assert.rejects(p(), /^Error: (bad_receipt|bad_result|no_repo_record|wrong_shape)$/, label);
  assert.deepEqual(s.store.kv.get("gh.baseline"), BASELINE, "no line from any of them");
  assert.equal(s.book.repoFacts(g)?.recorded, false);
});

test("Z2: the receipt is accepted after the answer expired and the card's deadline passed (no time limit on recovery)", async () => {
  const s = await setup();
  const { c } = await runRepo(s);
  s.clock.now = c.manifest.deadline + 7 * 86_400_000;
  await s.book.alarm();
  const { body, receipt } = await resultOf(s, c.grants[0].id);
  assert.deepEqual(await s.book.repoRecorded(c.grants[0].id, body, receipt), { recorded: "now" });
  assert.ok(s.store.kv.get<GhSnapshot>("gh.baseline")!.repo_ids.includes(`new-app:${REPO_ID}`));
});

test("T11: the same id already in the baseline at settle -> unknown, never added twice; a second card's record is its own", async () => {
  const s = await setup([], { baseline: { ...BASELINE, repos: [...BASELINE.repos, "new-app:private"], repo_ids: [...BASELINE.repo_ids, `new-app:${REPO_ID}`] } });
  const { state, c } = await runRepo(s);
  assert.equal(state, "unknown");
  assert.equal(s.book.repoFacts(c.grants[0].id)?.eligible, false);
});

// ---- Y1 nightly: a job-made repo not yet receipted names itself ----
test("Y1: the nightly GitHub count names a job-made repo the recorder has not receipted, until it is in the list", async () => {
  const s = await setup();
  const { c } = await runRepo(s);
  const live: GhSnapshot = { ...BASELINE, repos: [...BASELINE.repos, "new-app:private"].sort(), repo_ids: [...BASELINE.repo_ids, `new-app:${REPO_ID}`].sort() };
  s.store.kv.put("gh.app.headcount", { id: 101, slug: "wws-front-desk-headcount", key: "k", installation: 1010 });
  (s.vault as any).ghRead = async () => live;
  const night1 = await (s.vault as any).ghHeadcount();
  assert.equal(night1.ok, false);
  assert.deepEqual(night1.changes, ["repos +new-app:private", `repo_ids +new-app:${REPO_ID}`, "repo_result_unrecorded: new-app"]);
  const { body, receipt } = await resultOf(s, c.grants[0].id);
  await s.book.repoRecorded(c.grants[0].id, body, receipt);
  const night2 = await (s.vault as any).ghHeadcount();
  assert.deepEqual(night2, { ok: true, changes: [] }, "the next night is clean");
});

// ---- T13: same name, new repo ----
test("T13: a repo deleted and re-made under the same name between nights shows as repo_ids -old/+new", () => {
  const now = { ...BASELINE, repo_ids: ["front-desk:9999"] };
  assert.deepEqual(diff(BASELINE, now), ["repo_ids +front-desk:9999", "repo_ids -front-desk:9001"]);
});

// ---- X2 / T12: the two writers of gh.baseline -- the race with gh.app.baseline is in test/github.test.ts ----

// ---- Release Checklist 6.2: two calls at once ----
test("6.2: two repoRecorded calls at once for the same receipt -> one 'now', one 'already', exactly two lines", async () => {
  const s = await setup();
  const { c } = await runRepo(s);
  const { body, receipt } = await resultOf(s, c.grants[0].id);
  const both = await Promise.all([s.book.repoRecorded(c.grants[0].id, body, receipt), s.book.repoRecorded(c.grants[0].id, body, receipt)]);
  assert.deepEqual(both.map((r) => r.recorded).sort(), ["already", "now"]);
  assert.deepEqual(diff(BASELINE, s.store.kv.get<GhSnapshot>("gh.baseline")!), ["repos +new-app:private", `repo_ids +new-app:${REPO_ID}`]);
});

test("6.2: two repo cards racing -> both repos added, no line lost", async () => {
  const s = await setup();
  const a = await runRepo(s, "new-app");
  (s.gh as any).calls.length = 0;
  const b = await runRepo(s, "new-app");
  const ra = await resultOf(s, a.c.grants[0].id);
  // The second card's repo, as GitHub would answer it: another id. Its record is rewritten to that id.
  const rec = s.book.repoFacts(b.c.grants[0].id)!;
  s.store.kv.put(`gh.created:${b.c.grants[0].id}`, { ...rec, name: "other-app", repo_id: "777002" });
  const rb = await resultOf(s, b.c.grants[0].id, { repo_id: "777002" });
  await Promise.all([s.book.repoRecorded(a.c.grants[0].id, ra.body, ra.receipt), s.book.repoRecorded(b.c.grants[0].id, rb.body, rb.receipt)]);
  const ids = s.store.kv.get<GhSnapshot>("gh.baseline")!.repo_ids;
  assert.ok(ids.includes(`new-app:${REPO_ID}`) && ids.includes("other-app:777002"), JSON.stringify(ids));
});

// ---- Codex build r1 #3: only documented, readable refusals count as "nothing made" ----
test("r1 #3: a 422 naming the name as taken (lost race after the existence check) -> failed repo_exists; 403 and a readable 422 -> failed", async () => {
  for (const [f, code] of [["create422dup", "repo_exists"], ["create403", "create_refused: gh_403"], ["create422", "create_refused: gh_422"]] as const) {
    const s = await setup([f]);
    const { state, answer } = await runRepo(s);
    assert.equal(state, "failed", f);
    assert.deepEqual({ created: answer.created, refusal: answer.refusal }, { created: "absent", refusal: code }, f);
  }
});

test("r1 #3: any other 4xx, or a 422 with no readable body -> unknown (it may exist), never absent", async () => {
  for (const f of ["create409", "create400", "create422raw"] as const) {
    const s = await setup([f]);
    const { state, answer } = await runRepo(s);
    assert.equal(state, "unknown", f);
    assert.equal(answer.created, "unknown", f);
    assert.match(answer.notes.join(" "), /unexpected answer 4\d\d/, f);
  }
});

// ---- Codex build r1 #4: GitHub's whole-second created_at ----
test("r1 #4: a repo made in the same second the card opened, reported in whole seconds, is inside the window", async () => {
  const s = await setup(["createWholeSecond"]);
  s.clock.now = T + 700; // the card opens 0.7 s into the second; GitHub reports the second itself
  const { state, c } = await runRepo(s);
  assert.equal(state, "done");
  assert.equal(s.book.repoFacts(c.grants[0].id)?.eligible, true);
});

// ---- Codex build r1 #1: the stored answer of an ineligible creation says so ----
test("r1 #1: an ineligible creation (late, or already listed) stores ok null and eligible false, so no sentence says Done", async () => {
  const { JOBS } = await import("../src/jobs.ts");
  for (const [label, s] of [["late", await setup(["createLate"])], ["listed", await setup([], { baseline: { ...BASELINE, repo_ids: [...BASELINE.repo_ids, `new-app:${REPO_ID}`] } })]] as const) {
    const { state, answer } = await runRepo(s);
    assert.equal(state, "unknown", label);
    assert.deepEqual({ ok: answer.ok, eligible: answer.eligible, created: answer.created }, { ok: null, eligible: false, created: "confirmed" }, label);
    const said = JOBS["gh.repo.create"].done(answer);
    assert.match(said, /^Not done as planned: weird-ways-studio\/new-app exists, but the nightly check will not add it by itself/, label);
    assert.doesNotMatch(said, /^Done/, label);
  }
});

// ---- Codex build r1 #2: Ben accepting the list does not silence an unreceipted eligible creation ----
test("r1 #2: an eligible repo Ben accepted into the list still alarms repo_result_unrecorded until the receipt; an ineligible one clears once accepted", async () => {
  const s = await setup();
  const { c } = await runRepo(s);
  const live: GhSnapshot = { ...BASELINE, repos: [...BASELINE.repos, "new-app:private"].sort(), repo_ids: [...BASELINE.repo_ids, `new-app:${REPO_ID}`].sort() };
  s.store.kv.put("gh.app.headcount", { id: 101, slug: "wws-front-desk-headcount", key: "k", installation: 1010 });
  (s.vault as any).ghRead = async () => live;
  s.store.kv.put("gh.baseline", live); // Ben accepted the GitHub list with the repo in it, before the receipt arrived
  assert.deepEqual((await (s.vault as any).ghHeadcount()).changes, ["repo_result_unrecorded: new-app"]);
  const { body, receipt } = await resultOf(s, c.grants[0].id);
  assert.deepEqual(await s.book.repoRecorded(c.grants[0].id, body, receipt), { recorded: "now" });
  assert.deepEqual(await (s.vault as any).ghHeadcount(), { ok: true, changes: [] });
  // Ineligible: alarms while unlisted, clears when Ben accepts it.
  const late = await setup(["createLate"]);
  await runRepo(late);
  late.store.kv.put("gh.app.headcount", { id: 101, slug: "x", key: "k", installation: 1010 });
  (late.vault as any).ghRead = async () => live;
  assert.ok((await (late.vault as any).ghHeadcount()).changes.includes("repo_result_unrecorded: new-app"));
  late.store.kv.put("gh.baseline", live);
  assert.deepEqual(await (late.vault as any).ghHeadcount(), { ok: true, changes: [] });
});
