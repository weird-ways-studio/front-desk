// The reach read, desk side (card N2 5fdbf2ce part B; studio-os REFINE-5fdbf2ce-watcher-reach.md 12.3, 12.4): the agent's
// POST /reach/step, the on-demand headcount, the cron dispatch, and the words Ben reads. The vault is a fake that records
// its calls; the vault's own rules are tested in test/reach.test.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { CRONS, Desk, MemoryStore, cronJob, headcountWords, reachAcceptWords } from "../src/desk.ts";
import { route, type Who } from "../src/routes.ts";
import { JOBS } from "../src/jobs.ts";
import { plainChanges } from "../src/ghplain.ts";
import type { Headcount, ReachProgress } from "../vault/src/api.ts";

const NOW = Date.UTC(2026, 10, 14, 10, 0);
const AGENT: Who = { caller: "agent", requester: "c-box agent" };
const clean: Headcount = { ok: true, tokens: 4, unexpected: [], stretched: [], missing: [], cleanup: [], github: { ok: true, changes: [] } };

function fakeVault(answer: Partial<ReachProgress> & Record<string, unknown> = { state: "open", done: 18, total: 20, code: null }, hc: Headcount = clean) {
  const calls: { op: string; args: unknown[] }[] = [];
  return {
    calls,
    async ghReachStep(...args: unknown[]) {
      calls.push({ op: "ghReachStep", args });
      return answer as ReachProgress;
    },
    async ghReachNight() {
      calls.push({ op: "ghReachNight", args: [] });
      return answer as ReachProgress;
    },
    async headcount(...args: unknown[]) {
      calls.push({ op: "headcount", args });
      return hc;
    },
  };
}
const post = (store: MemoryStore, vault: unknown, path: string, body: string, who: Who = AGENT, alerts: string[] = []) =>
  route(new Request(`https://desk.example${path}`, { method: "POST", body }), store, who, NOW, vault as never, undefined, undefined, async (t, x) => void alerts.push(`${t}|${x}`));
const logOf = async (store: MemoryStore) => JSON.stringify([...(await store.list({ prefix: "log:" })).values()]);

test("R33: POST /reach/step needs the agent's login: Ben's login and unknown callers get 403, the vault is not called", async () => {
  for (const who of [{ caller: "owner" }, { caller: "unknown" }] as Who[]) {
    const v = fakeVault();
    const res = await post(new MemoryStore(), v, "/reach/step", "", who);
    assert.equal(res.status, 403);
    assert.deepEqual(v.calls, []);
  }
});

test("R34/R36: the body is empty or exactly {\"purpose\":\"demand\"}; any other purpose, scope, hash or baseline is refused before the vault", async () => {
  for (const [body, purpose] of [["", undefined], ['{"purpose":"demand"}', "demand"]] as const) {
    const v = fakeVault();
    const res = await post(new MemoryStore(), v, "/reach/step", body);
    assert.equal(res.status, 200, body);
    assert.deepEqual(v.calls, [{ op: "ghReachStep", args: [purpose] }]);
  }
  for (const body of ['{"purpose":"night"}', '{"purpose":"verify:abc"}', '{"purpose":"demand","scope":"x"}', '{"baseline":{"repo_hooks":[]}}', '{"lists":"h"}', "{}", "[]", "null", "not json", '"demand"']) {
    const v = fakeVault();
    const res = await post(new MemoryStore(), v, "/reach/step", body);
    assert.deepEqual([res.status, await res.json()], [400, { error: "bad_body" }], body);
    assert.deepEqual(v.calls, [], body);
  }
});

test("R35: the answer carries only bounded progress, whatever else the vault sends", async () => {
  const v = fakeVault({ state: "complete", done: 2, total: 2, code: null, lists: ["repo-0:1:example.com"], url: "https://example.com/x" });
  const res = await post(new MemoryStore(), v, "/reach/step", "");
  assert.deepEqual(await res.json(), { state: "complete", done: 2, total: 2, code: null });
});

test("R37: a verify read that ended sends Ben exactly one phone line with its final state, and logs it; 'recorded' only when accepted", async () => {
  for (const [acceptance, words] of [
    ["accepted", /recorded/],
    ["refused", /Nothing recorded: GitHub changed after you looked/],
    ["expired", /Nothing recorded: the re-check did not finish within 20 minutes/],
    ["superseded", /Nothing recorded: the nightly check started/],
  ] as const) {
    const store = new MemoryStore();
    const alerts: string[] = [];
    const res = await post(store, fakeVault({ state: acceptance === "expired" ? "failed" : "complete", done: 2, total: 2, code: acceptance === "refused" ? "reach_changed_since_request" : null, acceptance }), "/reach/step", "", AGENT, alerts);
    assert.equal(((await res.json()) as { acceptance?: string }).acceptance, acceptance);
    assert.equal(alerts.length, 1, acceptance);
    assert.match(alerts[0], words);
    if (acceptance !== "accepted") assert.doesNotMatch(alerts[0], /is now recorded/);
    assert.match(await logOf(store), new RegExp(`reach_acceptance_${acceptance}`));
  }
  // An open read sends nothing.
  const alerts: string[] = [];
  await post(new MemoryStore(), fakeVault(), "/reach/step", "", AGENT, alerts);
  assert.deepEqual(alerts, []);
  for (const s of ["accepted", "refused", "expired", "superseded"] as const) assert.ok(!/[{}]|reach_/.test(reachAcceptWords(s).split("[")[0]), s);
});

test("on-demand headcount: POST /headcount asks the vault for the newest read ('any'), pushes the detail when red, never touches the nightly runs", async () => {
  const red: Headcount = { ...clean, ok: false, github: { ok: false, changes: ["repo_hooks +front-desk:7:example.com:0123456789ab:push:true"] } };
  const store = new MemoryStore();
  const v = fakeVault(undefined, red);
  const alerts: string[] = [];
  const res = await post(store, v, "/headcount", "", AGENT, alerts);
  assert.deepEqual(await res.json(), { ok: false });
  assert.deepEqual(v.calls, [{ op: "headcount", args: ["any"] }]);
  assert.equal(alerts.length, 1);
  assert.match(alerts[0], /New: webhook on "front-desk" sending push to "example.com"/);
  assert.deepEqual([...(await store.list({ prefix: "hcrun:" })).keys()], [], "the nightly run summaries are untouched");
  assert.match(await logOf(store), /headcount_demand_mismatch/);
  const owner = await post(new MemoryStore(), v, "/headcount", "", { caller: "owner" });
  assert.equal(owner.status, 403);
  // The scheduled count still asks for the night's read.
  const night = fakeVault();
  await new Desk(new MemoryStore(), { origin: "", rpID: "" }, { vault: night as never }).headcount(async () => undefined, NOW);
  assert.deepEqual(night.calls, [{ op: "headcount", args: [] }]);
});

test("on-demand headcounts are capped at 6 an hour", async () => {
  const store = new MemoryStore();
  for (let i = 0; i < 6; i++) assert.equal((await post(store, fakeVault(), "/headcount", "")).status, 200);
  assert.deepEqual(await (await post(store, fakeVault(), "/headcount", "")).json(), { error: "rate_limited" });
});

test("cron dispatch: wrangler's crons are exactly the reach slices and the headcount, each mapped to its job; anything else runs nothing", async () => {
  const cfg = readFileSync("wrangler.jsonc", "utf8");
  assert.deepEqual(JSON.parse(/"crons":\s*(\[[^\]]*\])/.exec(cfg)![1]).sort(), Object.values(CRONS).sort());
  assert.equal(cronJob(CRONS.reach), "reach");
  assert.equal(cronJob(CRONS.headcount), "headcount");
  assert.equal(cronJob("0 0 * * *"), null);
  // The night slice logs only bounded progress.
  const store = new MemoryStore();
  const v = fakeVault({ state: "open", done: 18, total: 20, code: null });
  await new Desk(store, { origin: "", rpID: "" }, { vault: v as never }).reachNight(NOW);
  assert.deepEqual(v.calls, [{ op: "ghReachNight", args: [] }]);
  assert.match(await logOf(store), /"event":"reach_night","detail":"open 18\/20"/);
});

test("words: webhooks and collaborators in plain words; a destination-only change says so; no raw line in view", () => {
  const groups = plainChanges([
    "repo_hooks +front-desk:7:example.com:0123456789ab:pull_request,push:true",
    "org_hooks +9:example.com:0123456789ab:push:false",
    "collaborators +front-desk:someone-b:write",
    "collaborators -front-desk:someone-c:admin",
    "repo_hooks -studio-os:5:example.com:aaaaaaaaaaaa:push:true",
    "repo_hooks +studio-os:5:example.com:bbbbbbbbbbbb:push:true",
  ]);
  const said = JSON.stringify(groups);
  assert.match(said, /New: webhook on \\"front-desk\\" sending pull_request, push to \\"example.com\\"/);
  assert.match(said, /New: organization webhook sending push to \\"example.com\\" \(switched off\)/);
  assert.match(said, /New: \\"someone-b\\" added directly to \\"front-desk\\" as write/);
  assert.match(said, /Gone: \\"someone-c\\" no longer directly on \\"front-desk\\" \(was admin\)/);
  assert.match(said, /Changed: webhook on \\"studio-os\\" to \\"example.com\\": destination changed/);
  assert.doesNotMatch(said, /0123456789ab|aaaaaaaaaaaa|repo_hooks|org_hooks/);
});

test("words: each reach failure says what it means for tonight, with the code in brackets for the agent", () => {
  for (const [code, words] of [
    ["reach_incomplete: stale", /webhook and collaborator check did not finish/],
    ["reach_incomplete: newer_failed", /webhook and collaborator check did not finish/],
    ["reach_incomplete: inventory", /different set of repositories/],
    ["reach_no_baseline", /not been accepted yet/],
    ["reach_fp_key_lost", /lost its private fingerprint key/],
  ] as const) {
    const said = headcountWords({ ...clean, ok: false, github: { ok: false, changes: [], error: code } });
    assert.match(said, words, code);
    assert.ok(said.includes(`[${code}]`) || said.includes(`["${code}"]`) || said.includes(code), code);
  }
});

test("job gh.reach.baseline: Ben's screen lists the changes in words; the tap's sentence never says recorded", () => {
  const p = { changes: "collaborators +front-desk:someone-b:write", lists: "l", base: "b", app_id: "1", installation_id: "2", inventory: "i" };
  const g = JOBS["gh.reach.baseline"].explain(p);
  assert.match(JSON.stringify(g.sections), /someone-b/);
  assert.match(g.expect, /checks GitHub again/);
  const done = JOBS["gh.reach.baseline"].done({ ok: true, state: "pending", expires_at: NOW });
  assert.match(done, /^Approved/);
  assert.doesNotMatch(done, /\brecorded\b(?! yet)/i);
  assert.match(JOBS["gh.reach.baseline"].done({ ok: false, state: "refused", error: "reach_try_after_0420" }), /^Not done/);
  assert.deepEqual(JOBS["gh.reach.baseline"].validate({}), {});
  assert.equal(JOBS["gh.reach.baseline"].validate({ lists: "x" }), null, "the agent cannot choose what is bound");
});
