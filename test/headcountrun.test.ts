// Headcount runs agents can read (card build 5 6ab972c8; studio-os REFINE-6ab972c8-night.md v2.1, tests T1-T14).
// The refinement says "night"; the code says "headcount run" (Ben, 2026-11-10: a run need not be at night).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Desk, MemoryStore, headcountWords, type Store } from "../src/desk.ts";
import { route } from "../src/routes.ts";
import { GAP_MS, KEEP, LIST_MAX, judge, runSummary, type RunSummary, type RunView } from "../src/headcountrun.ts";
import { headcountArgs } from "../scripts/agent.mjs";
import type { Headcount } from "../vault/src/api.ts";

const H = 3600_000;
const T0 = Date.parse("2026-11-12T04:17:00.000Z");
const iso = (t: number) => new Date(t).toISOString();

const clean: Headcount = { ok: true, tokens: 4, unexpected: [], stretched: [], missing: [], cleanup: [], github: { ok: true, changes: [] } };

// A published run: clean unless `over` says otherwise; it takes a minute.
function run(seq: number, start: number, over: Partial<RunSummary> = {}): RunSummary {
  return {
    seq,
    started_at: iso(start),
    completed_at: iso(start + 60_000),
    ok: true,
    cloudflare: { tokens: 4, unexpected: 0, stretched: 0, missing: 0, cleanup: 0, widened: 0 },
    github: { ok: true, repos_added: [], repos_removed: [], other_changes: {} },
    errors: [],
    truncated: false,
    ...over,
  };
}
const view = (runs: RunSummary[], attempt?: { seq: number; started_at: string }): RunView => ({
  attempt: attempt ?? { seq: Math.max(...runs.map((r) => r.seq)), started_at: runs.find((r) => r.seq === Math.max(...runs.map((x) => x.seq)))!.started_at },
  runs: [...runs].sort((a, b) => b.seq - a.seq),
});
const alarmedRun = (seq: number, start: number, repo = "newrepo") => run(seq, start, { ok: false, github: { ok: false, repos_added: [`${repo}:private`], repos_removed: [], other_changes: { repo_ids: 1 } } });

// ---- the summary (T1, T2, T4, T5) ----

test("T1 the summary holds exactly the listed fields and no key, member, App, PAT or deploy-key string", () => {
  const r: Headcount = {
    ok: false,
    tokens: 9,
    unexpected: [{ id: "tokidAAA", name: "toknameBBB" }],
    stretched: [{ id: "stretchCCC", expires_on: "2027-01-01T00:00:00Z" }],
    missing: ["missingDDD"],
    cleanup: [{ id: "cleanEEE", expires_on: "2026-11-13T00:00:00Z", expired: false, recorded: true }],
    widened: [{ id: "widenFFF", why: "whyGGG" }],
    github: {
      ok: false,
      changes: [
        "repos +alpha:private", "repos -beta:public", "repo_ids +alpha:999111", "members +memberHHH", "owners +ownerIII",
        "outside +outsideOOO", "invites +inviteJJJ", "apps +appKKK#1:all:x=read", "pats +patLLL:5", "deploy_keys +alpha:dkMMM",
        "rulesets +alpha:1:active:{}", "repo_result_unrecorded: alpha", "strange line NNN", "zzqq_kind +x",
      ],
    },
  };
  const s = runSummary(r, { seq: 3, started_at: iso(T0) }, T0 + 5000);
  const keys = (o: object, at = ""): string[] => Object.entries(o).flatMap(([k, v]) => (v && typeof v === "object" && !Array.isArray(v) && k !== "other_changes" ? keys(v, `${at}${k}.`) : [`${at}${k}`]));
  assert.deepEqual(keys(s).sort(), [
    "cloudflare.cleanup", "cloudflare.missing", "cloudflare.stretched", "cloudflare.tokens", "cloudflare.unexpected", "cloudflare.widened",
    "completed_at", "errors", "github.ok", "github.other_changes", "github.repos_added", "github.repos_removed", "ok", "seq", "started_at", "truncated",
  ]);
  const text = JSON.stringify(s);
  for (const leak of ["zzqq", "AAA", "BBB", "CCC", "DDD", "EEE", "FFF", "GGG", "HHH", "III", "JJJ", "KKK", "LLL", "MMM", "NNN", "OOO", "999111"]) assert.ok(!text.includes(leak), `leaked ${leak}`);
  // Repo names appear only in the two repo lists.
  assert.equal(text.split("alpha").length - 1, 1);
  assert.deepEqual(s.github.repos_added, ["alpha:private"]);
  assert.deepEqual(s.github.repos_removed, ["beta:public"]);
  // A kind the list does not know counts under "other", never under its own name.
  assert.equal(s.github.other_changes.other, 2);
});

test("T2 counts and change kinds are right, and a visibility flip shows in both repo lists", () => {
  const r: Headcount = {
    ...clean,
    ok: false,
    unexpected: [{ id: "a", name: "a" }, { id: "b", name: "b" }],
    widened: [{ id: "w", why: "x" }],
    github: { ok: false, changes: ["repos +x:public", "repos -x:private", "members +m", "members -n", "apps +q", "repo_result_unrecorded: x", "odd"] },
  };
  const s = runSummary(r, { seq: 1, started_at: iso(T0) }, T0 + 1);
  assert.deepEqual(s.cloudflare, { tokens: 4, unexpected: 2, stretched: 0, missing: 0, cleanup: 0, widened: 1 });
  assert.deepEqual(s.github.repos_added, ["x:public"]);
  assert.deepEqual(s.github.repos_removed, ["x:private"]);
  assert.deepEqual(s.github.other_changes, { members: 2, apps: 1, repo_result_unrecorded: 1, other: 1 });
  assert.equal(s.ok, false);
  assert.equal(s.completed_at, iso(T0 + 1));
});

test("T4 errors are fixed codes only: no part of any message survives", () => {
  const tokenish = "abcdefghijklmnopqrstuvwxyz0123456789abcd";
  const a = runSummary({ ...clean, ok: false, error: tokenish }, { seq: 1, started_at: iso(T0) }, T0);
  assert.deepEqual(a.errors, ["headcount_failed"]);
  const b = runSummary({ ...clean, ok: false, github: { ok: false, changes: [], error: `github_read: 502 ${tokenish}` } }, { seq: 1, started_at: iso(T0) }, T0);
  assert.deepEqual(b.errors, ["github_failed"]);
  const c = runSummary({ ...clean, ok: false, error: "vault not connected", github: { ok: false, changes: [], error: "github_not_set_up" } }, { seq: 1, started_at: iso(T0) }, T0);
  assert.deepEqual(c.errors, ["headcount_failed", "github_failed"]);
  for (const s of [a, b, c]) for (const bit of [tokenish, "502", "vault not", "not_set_up"]) assert.ok(!JSON.stringify(s).includes(bit));
});

test("T5 more than 50 added repos: 50 listed and truncated", () => {
  const changes = Array.from({ length: LIST_MAX + 1 }, (_, i) => `repos +r${i}:private`);
  const s = runSummary({ ...clean, ok: false, github: { ok: false, changes } }, { seq: 1, started_at: iso(T0) }, T0);
  assert.equal(s.github.repos_added.length, LIST_MAX);
  assert.equal(s.truncated, true);
  assert.equal(runSummary({ ...clean, ok: false, github: { ok: false, changes: changes.slice(0, LIST_MAX) } }, { seq: 1, started_at: iso(T0) }, T0).truncated, false);
});

// ---- the desk: saving, isolation from the alarm (T6, T7, T10, T11) ----

// A store whose writes to keys matching `fail` throw.
class FailingStore extends MemoryStore {
  fail: RegExp | null = null;
  override async put<T>(key: string, value: T) {
    if (this.fail?.test(key)) throw new Error(`store refused ${key}`);
    return super.put(key, value);
  }
}
function desk(answer: () => Promise<Headcount>, store: Store = new MemoryStore()) {
  const vault = { status: async () => ({ stored: true, pending: false }), run: async () => ({}) as any, headcount: answer, ghPreview: async () => ({ changes: [], snapshot: "", base: "" }), cfPreview: async () => [], approvalApi: async () => ({ version: 1 }) };
  const told: { ok: boolean; detail: string }[] = [];
  const alarm = async (ok: boolean, detail: string) => void told.push({ ok, detail });
  return { desk: new Desk(store, { origin: "https://desk.example", rpID: "desk.example" }, { vault }), told, alarm, store };
}

test("T7 no run yet: { none: true }, and the verdict is UNPROVEN", async () => {
  const { desk: d } = desk(async () => clean);
  const v = await d.headcountRuns();
  assert.deepEqual(v, { none: true, attempt: null, runs: [] });
  assert.equal(judge(v, T0).verdict, "UNPROVEN");
  assert.equal(judge(v, T0, { after: T0 - H }).verdict, "UNPROVEN");
});

test("headcount runs: each run takes the next number at its start and publishes start and completion times", async () => {
  const { desk: d } = desk(async () => clean);
  await d.headcount(async () => {}, T0, () => T0 + 7000);
  await d.headcount(async () => {}, T0 + 24 * H, () => T0 + 24 * H + 9000);
  const v = await d.headcountRuns();
  assert.deepEqual(v.attempt, { seq: 2, started_at: iso(T0 + 24 * H) });
  assert.deepEqual(v.runs.map((r) => [r.seq, r.started_at, r.completed_at]), [
    [2, iso(T0 + 24 * H), iso(T0 + 24 * H + 9000)],
    [1, iso(T0), iso(T0 + 7000)],
  ]);
  assert.equal(judge(v, T0 + 25 * H).verdict, "PASS");
});

test("headcount runs: only the newest 14 are kept", async () => {
  const { desk: d } = desk(async () => clean);
  for (let i = 0; i < KEEP + 3; i++) await d.headcount(async () => {}, T0 + i * 24 * H, () => T0 + i * 24 * H + 1000);
  const v = await d.headcountRuns();
  assert.equal(v.runs.length, KEEP);
  assert.deepEqual([v.runs[0].seq, v.runs.at(-1)!.seq], [KEEP + 3, 4]);
});

test("T6 the log write failing does not stop the summary or the alarm; the summary is built from the result, not the log", async () => {
  const store = new FailingStore();
  store.fail = /^(log:|meta:logseq)/;
  const { desk: d, told, alarm } = desk(async () => ({ ...clean, ok: false, unexpected: [{ id: "k", name: "n" }] }), store);
  await d.headcount(alarm, T0, () => T0 + 1000).catch(() => undefined);
  assert.equal(told.length, 1, "the alarm was called");
  assert.equal(told[0].ok, false);
  const v = await d.headcountRuns();
  assert.equal(v.runs.length, 1);
  assert.equal(v.runs[0].cloudflare.unexpected, 1);
});

test("T10 saving failing, and its diagnostic log failing, never stop the alarm, which gets the same ok and words", async () => {
  const bad: Headcount = { ...clean, ok: false, missing: ["m1"] };
  const store = new FailingStore();
  store.fail = /^(hcrun:n:|log:|meta:logseq)/;
  const { desk: d, told, alarm } = desk(async () => bad, store);
  await d.headcount(alarm, T0).catch(() => undefined);
  assert.deepEqual(told, [{ ok: false, detail: headcountWords(bad) }]);
  // With the log working, the failed save is logged for Ben.
  const s2 = new FailingStore();
  s2.fail = /^hcrun:n:/;
  const b = desk(async () => clean, s2);
  await b.desk.headcount(b.alarm, T0);
  assert.deepEqual((await b.desk.readLog()).map((e) => e.event), ["headcount_ok", "headcount_run_save_failed"]);
  assert.equal(b.told.length, 1);
});

test("T10b the alarm failing still leaves the run saved, and is logged", async () => {
  const { desk: d } = desk(async () => clean);
  await d.headcount(async () => { throw new Error("healthchecks answered 500"); }, T0, () => T0 + 1000);
  assert.equal((await d.headcountRuns()).runs.length, 1);
  assert.deepEqual((await d.readLog()).map((e) => e.event), ["headcount_ok", "headcount_alarm_failed"]);
});

test("T11 a clean run, then a run whose save fails: UNPROVEN, never the old PASS", async () => {
  const store = new FailingStore();
  const { desk: d, alarm } = desk(async () => clean, store);
  await d.headcount(alarm, T0, () => T0 + 1000);
  assert.equal(judge(await d.headcountRuns(), T0 + H).verdict, "PASS");
  store.fail = /^hcrun:n:/;
  await d.headcount(alarm, T0 + 24 * H, () => T0 + 24 * H + 1000);
  const j = judge(await d.headcountRuns(), T0 + 24 * H + 2000);
  assert.equal(j.verdict, "UNPROVEN");
  assert.match(j.line, /did not publish/);
  // ...and a change made between them is not proven by the old run either.
  assert.equal(judge(await d.headcountRuns(), T0 + 25 * H, { after: T0 + 2 * H }).verdict, "UNPROVEN");
});

// ---- the route (T3, T8) ----

test("T3/T8 GET /headcount: agent 200; no login and Ben's login 403; other methods not served; a read changes nothing", async () => {
  const store = new MemoryStore();
  const d = desk(async () => clean, store);
  await d.desk.headcount(d.alarm, T0, () => T0 + 1000);
  const dump = async () => JSON.stringify([...(await store.list({ prefix: "" })).entries()]);
  const before = await dump();
  const get = (who: Parameters<typeof route>[2], method = "GET") => route(new Request("https://desk.example/headcount", { method }), store, who, T0 + H);
  const ok = await get({ caller: "agent", requester: "cbox" });
  assert.equal(ok.status, 200);
  const body = (await ok.json()) as RunView;
  assert.equal(body.runs.length, 1);
  const again = await get({ caller: "agent", requester: "cbox" });
  assert.equal(again.status, 200);
  assert.equal(await dump(), before, "two reads left storage and the log unchanged");
  assert.equal((await get({ caller: "unknown", why: "no ticket" })).status, 403);
  assert.equal((await get({ caller: "owner" })).status, 403);
  assert.equal((await get({ caller: "agent", requester: "cbox" }, "POST")).status, 404);
  assert.equal((await get({ caller: "owner" }, "POST")).status, 403);
});

// ---- the judge (T9, T12-T14) ----

test("T9 now: PASS only for a clean, published run that started within 26 hours", () => {
  const v = view([run(1, T0 - 24 * H), run(2, T0)]);
  assert.equal(judge(v, T0 + H).verdict, "PASS");
  assert.match(judge(v, T0 + H).line, /^PASS: the headcount run that started 2026-11-12 04:17 UTC was clean/);
  assert.equal(judge(v, T0 + 27 * H).verdict, "UNPROVEN", "stale");
  assert.equal(judge(view([run(2, T0)], { seq: 3, started_at: iso(T0 + 24 * H) }), T0 + 24 * H + 1000).verdict, "UNPROVEN", "unpublished attempt");
  assert.equal(judge(view([run(2, T0, { errors: ["github_failed"], ok: false, github: { ok: false, repos_added: [], repos_removed: [], other_changes: {} } })]), T0 + H).verdict, "UNPROVEN", "errored");
  assert.equal(judge(view([run(2, T0, { truncated: true })]), T0 + H).verdict, "UNPROVEN", "truncated");
  assert.equal(judge(view([run(2, T0, { github: { ok: false, repos_added: [], repos_removed: [], other_changes: {} } })]), T0 + H).verdict, "UNPROVEN", "github not confirmed");
  assert.equal(judge(view([run(2, T0, { started_at: "yesterday" })]), T0 + H).verdict, "UNPROVEN", "unreadable time");
});

test("T9 every Cloudflare mismatch, and any alarmed run, is FAIL", () => {
  for (const k of ["unexpected", "stretched", "missing", "cleanup", "widened"] as const) {
    const r = run(2, T0, { ok: false, cloudflare: { tokens: 4, unexpected: 0, stretched: 0, missing: 0, cleanup: 0, widened: 0, [k]: 1 } });
    const j = judge(view([r]), T0 + H);
    assert.equal(j.verdict, "FAIL", k);
    assert.match(j.line, new RegExp(`cloudflare ${k} 1`));
  }
});

test("T9 after a change: the first run after it decides; named repo FAIL; a repo_ids-only alarm FAIL unnamed", () => {
  const made = T0 - 12 * H;
  assert.equal(judge(view([run(1, T0 - 24 * H), run(2, T0)]), T0 + H, { after: made, repo: "newrepo" }).verdict, "PASS");
  const named = judge(view([run(1, T0 - 24 * H), alarmedRun(2, T0)]), T0 + H, { after: made, repo: "newrepo" });
  assert.equal(named.verdict, "FAIL");
  assert.match(named.line, /^FAIL: repo newrepo was flagged/);
  const idsOnly = run(2, T0, { ok: false, github: { ok: false, repos_added: [], repos_removed: [], other_changes: { repo_ids: 2 } } });
  const unnamed = judge(view([run(1, T0 - 24 * H), idsOnly]), T0 + H, { after: made, repo: "newrepo" });
  assert.equal(unnamed.verdict, "FAIL");
  assert.match(unnamed.line, /alarmed \(repo_ids 2\)/);
  // A repo listed as added fails even if the run said ok (it cannot, but the judge does not trust that).
  assert.equal(judge(view([run(1, T0 - 24 * H), run(2, T0, { github: { ok: true, repos_added: ["newrepo:private"], repos_removed: [], other_changes: {} } })]), T0 + H, { after: made, repo: "newrepo" }).verdict, "FAIL");
  assert.equal(judge(view([run(1, T0 - 24 * H)]), T0 + H, { after: made }).verdict, "UNPROVEN", "no run after the change yet");
  assert.equal(judge(view([run(1, T0 - 24 * H), run(2, T0, { errors: ["headcount_failed"], ok: false })]), T0 + H, { after: made }).verdict, "UNPROVEN", "errored");
});

test("T9 after a change: the run before the first one must be in the history", () => {
  // seq 2 is missing (missed, unpublished or pruned): seq 1 must not stand in for it.
  assert.equal(judge(view([run(1, T0 - 24 * H), run(3, T0)]), T0 + H, { after: T0 - 12 * H }).verdict, "UNPROVEN");
  // The very first run has no predecessor.
  assert.equal(judge(view([run(1, T0)]), T0 + H, { after: T0 - 12 * H }).verdict, "UNPROVEN");
});

test("T12 a run that overlaps the change: FAIL if it alarmed, else UNPROVEN, and the judge never moves on to a later run", () => {
  const made = T0 + 30_000; // between the run's start and its completion
  const failedThenClean = view([run(1, T0 - 24 * H), alarmedRun(2, T0), run(3, T0 + 24 * H)]);
  const f = judge(failedThenClean, T0 + 25 * H, { after: made, repo: "newrepo" });
  assert.equal(f.verdict, "FAIL");
  assert.match(f.line, /repo newrepo was flagged/);
  const cleanOverlap = judge(view([run(1, T0 - 24 * H), run(2, T0), run(3, T0 + 24 * H)]), T0 + 25 * H, { after: made, repo: "newrepo" });
  assert.equal(cleanOverlap.verdict, "UNPROVEN");
  assert.match(cleanOverlap.line, /overlapped/);
});

test("T13 a run lost before its marker, between two clean runs 48 hours apart: UNPROVEN", () => {
  assert.equal(judge(view([run(1, T0 - 24 * H), run(2, T0 + 24 * H)]), T0 + 25 * H, { after: T0 - 23 * H }).verdict, "UNPROVEN");
});

test("T14 the predecessor 30 hours before the first run after the change: UNPROVEN; 25 hours: PASS", () => {
  assert.equal(judge(view([run(1, T0 - 30 * H), run(2, T0)]), T0 + H, { after: T0 - 12 * H }).verdict, "UNPROVEN");
  assert.equal(judge(view([run(1, T0 - 25 * H), run(2, T0)]), T0 + H, { after: T0 - 12 * H }).verdict, "PASS");
});

// Card N2 5fdbf2ce added the reach slices' cron ("47,52 3 * * *", src/desk.ts CRONS.reach). It runs no headcount, so the
// headcount's own schedule -- and with it GAP_MS -- is unchanged: still exactly one "17 4 * * *" headcount a day.
test("GAP_MS fits the cron: one run a day, so 26 hours", () => {
  const cfg = readFileSync("wrangler.jsonc", "utf8");
  assert.deepEqual(JSON.parse(/"crons":\s*(\[[^\]]*\])/.exec(cfg)![1]), ["47,52 3 * * *", "17 4 * * *"], "the schedule changed: change GAP_MS in src/headcountrun.ts to fit, then this test");
  assert.equal(GAP_MS, 26 * H);
});

test("agent.mjs headcount: --after must be a readable ISO time; unknown flags are refused (exit 2)", () => {
  assert.deepEqual(headcountArgs(["--after", "2026-11-12T04:17:00Z", "--repo", "x"]), { after: T0, repo: "x" });
  assert.deepEqual(headcountArgs([]), {});
  for (const bad of [["--after", "tomorrow"], ["--after"], ["--repo"], ["--since", "2026-11-12T04:17:00Z"]]) {
    assert.throws(() => headcountArgs(bad), (e: Error & { exit?: number }) => e.exit === 2);
  }
});

// ---- Codex build r1 (studio-os REVIEW-codex-6ab972c8-build-r1.md) ----

test("r1#1 a cut-off run is UNPROVEN even when it alarmed (G1); an overlapping alarmed run stays FAIL (G9a)", () => {
  const cut = run(2, T0, { ok: false, truncated: true, github: { ok: false, repos_added: ["newrepo:private"], repos_removed: [], other_changes: {} } });
  assert.equal(judge(view([run(1, T0 - 24 * H), cut]), T0 + H).verdict, "UNPROVEN");
  assert.equal(judge(view([run(1, T0 - 24 * H), cut]), T0 + H, { after: T0 - 12 * H, repo: "newrepo" }).verdict, "UNPROVEN");
  assert.equal(judge(view([run(1, T0 - 24 * H), cut]), T0 + H, { after: T0 + 30_000, repo: "newrepo" }).verdict, "FAIL");
});

test("r1#2 an overlapping clean run says later runs cannot replace it, never 'ask again'", () => {
  const j = judge(view([run(1, T0 - 24 * H), run(2, T0), run(3, T0 + 24 * H)]), T0 + 25 * H, { after: T0 + 30_000 });
  assert.equal(j.verdict, "UNPROVEN");
  assert.match(j.line, /cannot prove the change clean, and later runs do not replace it/);
  assert.doesNotMatch(j.line, /ask again/i);
});

test("r1#4 impossible times are UNPROVEN: future runs, completion before start, starts out of order, a future change time", () => {
  const now = Date.parse("2026-11-12T05:00:00Z");
  // Codex's example: a candidate a day in the future.
  const ex = view([run(1, Date.parse("2026-11-12T04:17:00Z")), run(2, Date.parse("2026-11-13T04:17:00Z"))]);
  assert.equal(judge(ex, now).verdict, "UNPROVEN");
  assert.equal(judge(ex, now, { after: Date.parse("2026-11-12T04:30:00Z") }).verdict, "UNPROVEN");
  // Within the 5-minute drift allowance is fine.
  const near = view([run(1, now - 24 * H), run(2, now + 4 * 60_000 - 60_000)]);
  assert.equal(judge(near, now).verdict, "PASS");
  const backwards = run(2, T0, { completed_at: iso(T0 - 1000) });
  assert.equal(judge(view([run(1, T0 - 24 * H), backwards]), T0 + H).verdict, "UNPROVEN");
  const swapped = view([run(1, T0), run(2, T0 - 24 * H)]);
  assert.equal(judge(swapped, T0 + H).verdict, "UNPROVEN");
  assert.equal(judge(swapped, T0 + H, { after: T0 - 30 * H }).verdict, "UNPROVEN");
  const ok = view([run(1, T0 - 24 * H), run(2, T0)]);
  assert.equal(judge(ok, T0 + H, { after: T0 + 2 * H }).verdict, "UNPROVEN", "a change time in the future (no run can have completed after it without being in the future itself)");
  assert.equal(judge(view([run(2, T0)], { seq: 3, started_at: iso(T0 + 48 * H) }), T0 + H).verdict, "UNPROVEN", "a future attempt marker");
});
