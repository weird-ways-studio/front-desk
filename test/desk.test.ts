// Each safeguard is shown working first, then refusing the unsafe case
// (instruction.control-must-refuse-unsafe-case).

import { test } from "node:test";
import assert from "node:assert/strict";
import { APPROVE_WINDOW_MS, CHALLENGE_TTL_MS, COLLECT_WINDOW_MS, Desk, DeskError, MemoryStore, headcountAlarm, type DeskHooks } from "../src/desk.ts";
import { JOBS } from "../src/jobs.ts";
import type { Headcount } from "../vault/src/api.ts";
import { SoftKey } from "./softkey.ts";

const site = { origin: "https://desk.example", rpID: "desk.example" };
const T0 = 1_800_000_000_000;
const ask = { job: "test.echo", params: { word: "hello" }, reason: "prove the desk works" };

async function refuses(p: Promise<unknown>, code: string) {
  await assert.rejects(p, (e: unknown) => e instanceof DeskError && e.code === code);
}

async function setup(hooks: DeskHooks = {}) {
  const store = new MemoryStore();
  const desk = new Desk(store, site, hooks);
  const key = await SoftKey.create();
  await desk.enroll(await key.register(await desk.enrollOptions(T0), site.origin), T0);
  return { store, desk, key };
}

async function approveWith(desk: Desk, key: SoftKey, id: string, now = T0) {
  const options = await desk.approvalOptions(id, now);
  return desk.approve(id, await key.assert(options.challenge, site.rpID, site.origin), now);
}

test("happy path: ask, approve with the passkey, collect once", async () => {
  const { desk, key } = await setup();
  const g = await desk.request(ask, "agent", T0);
  assert.equal((await approveWith(desk, key, g.id)).status, "approved");
  const { result } = await desk.collect(g.id, "agent", T0 + 1000);
  assert.deepEqual(result, { echoed: "hello" });
  const events = (await desk.readLog()).map((e) => e.event);
  assert.deepEqual(events, ["passkey_enrolled", "requested", "approved", "collected"]);
});

test("no mint without Ben: collect before approval is refused", async () => {
  const { desk } = await setup();
  const g = await desk.request(ask, "agent", T0);
  await refuses(desk.collect(g.id, "agent", T0), "not_approved");
});

test("a replayed approval is refused", async () => {
  const { desk, key } = await setup();
  const g = await desk.request(ask, "agent", T0);
  const options = await desk.approvalOptions(g.id, T0);
  const signed = await key.assert(options.challenge, site.rpID, site.origin);
  await desk.approve(g.id, signed, T0);
  await refuses(desk.approve(g.id, signed, T0), "not_pending");
  const g2 = await desk.request(ask, "agent", T0);
  await refuses(desk.approve(g2.id, signed, T0), "challenge_used");
});

test("an approval for grant A cannot approve grant B", async () => {
  const { desk, key } = await setup();
  const a = await desk.request(ask, "agent", T0);
  const b = await desk.request({ ...ask, params: { word: "other" } }, "agent", T0);
  const options = await desk.approvalOptions(a.id, T0);
  await refuses(desk.approve(b.id, await key.assert(options.challenge, site.rpID, site.origin), T0), "wrong_grant");
  assert.equal((await desk.grant(b.id)).status, "pending");
});

test("a forged approval (another key, no user check, wrong site) is refused", async () => {
  const { desk, key } = await setup();
  const g = await desk.request(ask, "agent", T0);
  const stranger = await SoftKey.create();
  let o = await desk.approvalOptions(g.id, T0);
  await refuses(desk.approve(g.id, await stranger.assert(o.challenge, site.rpID, site.origin), T0), "unknown_passkey");
  o = await desk.approvalOptions(g.id, T0);
  await refuses(desk.approve(g.id, await key.assert(o.challenge, site.rpID, site.origin, { userVerified: false }), T0), "passkey_check_failed");
  o = await desk.approvalOptions(g.id, T0);
  await refuses(desk.approve(g.id, await key.assert(o.challenge, site.rpID, "https://phish.example"), T0), "passkey_check_failed");
  assert.equal((await desk.grant(g.id)).status, "pending");
});

test("expired grants and closed collect windows are refused", async () => {
  const { desk, key } = await setup();
  const late = await desk.request(ask, "agent", T0);
  await refuses(desk.approvalOptions(late.id, T0 + APPROVE_WINDOW_MS + 1), "grant_expired");
  const g = await desk.request(ask, "agent", T0);
  await approveWith(desk, key, g.id);
  await refuses(desk.collect(g.id, "agent", T0 + COLLECT_WINDOW_MS + 1), "collect_window_closed");
});

test("a grant is collected at most once, and only by its requester", async () => {
  const { desk, key } = await setup();
  const g = await desk.request(ask, "agent", T0);
  await approveWith(desk, key, g.id);
  await refuses(desk.collect(g.id, "someone-else", T0), "not_your_grant");
  await desk.collect(g.id, "agent", T0);
  await refuses(desk.collect(g.id, "agent", T0), "already_collected");
});

test("jobs not on the fixed list, and bad params, are refused", async () => {
  const { desk } = await setup();
  await refuses(desk.request({ ...ask, job: "billing.add_card" }, "agent", T0), "job_not_offered");
  await refuses(desk.request({ ...ask, job: "toString" }, "agent", T0), "job_not_offered");
  await refuses(desk.request({ ...ask, params: { word: "rm -rf /" } }, "agent", T0), "bad_params");
  assert.ok((await desk.readLog()).some((e) => e.event === "refused" && e.detail?.includes("billing.add_card")));
});

test("a second passkey cannot enroll through the first-passkey path", async () => {
  const { desk } = await setup();
  await refuses(desk.enrollOptions(T0), "already_enrolled");
  assert.equal((await desk.passkeys()).length, 1);
});

test("the stored grant cannot be swapped under an approval", async () => {
  const { store, desk, key } = await setup();
  const g = await desk.request(ask, "agent", T0);
  const options = await desk.approvalOptions(g.id, T0);
  await store.put(`grant:${g.id}`, { ...g, params: { word: "swapped" }, hash: "0".repeat(64) });
  await refuses(desk.approve(g.id, await key.assert(options.challenge, site.rpID, site.origin), T0), "wrong_grant");
});

test("two approvals in flight for one grant: exactly one wins, and a collected grant stays collected", async () => {
  const { desk, key } = await setup();
  const g = await desk.request(ask, "agent", T0);
  const o1 = await desk.approvalOptions(g.id, T0);
  const o2 = await desk.approvalOptions(g.id, T0);
  const s1 = await key.assert(o1.challenge, site.rpID, site.origin);
  const s2 = await key.assert(o2.challenge, site.rpID, site.origin);
  const results = await Promise.allSettled([desk.approve(g.id, s1, T0), desk.approve(g.id, s2, T0)]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  await desk.collect(g.id, "agent", T0);
  assert.equal((await desk.grant(g.id)).status, "collected");
});

test("two first-passkey enrollments in flight: exactly one passkey ends up enrolled", async () => {
  const store = new MemoryStore();
  const desk = new Desk(store, site);
  const a = await SoftKey.create();
  const b = await SoftKey.create();
  const ra = await a.register(await desk.enrollOptions(T0), site.origin);
  const rb = await b.register(await desk.enrollOptions(T0), site.origin);
  const results = await Promise.allSettled([desk.enroll(ra, T0), desk.enroll(rb, T0)]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal((await desk.passkeys()).length, 1);
});

test("the log records who, what (exact params), why, when and expiry", async () => {
  const { desk, key } = await setup();
  const g = await desk.request(ask, "agent", T0);
  await approveWith(desk, key, g.id);
  await desk.collect(g.id, "agent", T0);
  for (const e of (await desk.readLog()).filter((e) => e.grant_id === g.id)) {
    assert.equal(e.requester, "agent");
    assert.deepEqual(e.params, { word: "hello" });
    assert.equal(e.reason, "prove the desk works");
    assert.equal(e.expires_at, g.expires_at);
    assert.equal(typeof e.at, "number");
  }
});

// A gate a test opens by hand, to hold one approval after its signature check.
function gate() {
  let open!: () => void;
  const opened = new Promise<void>((r) => (open = r));
  let reached!: () => void;
  const arrived = new Promise<void>((r) => (reached = r));
  return { open, arrived, wait: async () => (reached(), opened) };
}

test("a held approval released after collect is refused; the grant stays collected", async () => {
  const hold = gate();
  let target = "";
  const { desk, key } = await setup({ afterVerify: async (id) => (id === target ? hold.wait() : undefined) });
  const g = await desk.request(ask, "agent", T0);
  const o1 = await desk.approvalOptions(g.id, T0);
  const o2 = await desk.approvalOptions(g.id, T0);
  const late = key.assert(o2.challenge, site.rpID, site.origin);
  const early = await key.assert(o1.challenge, site.rpID, site.origin);
  target = g.id;
  const held = desk.approve(g.id, await late, T0);
  await hold.arrived;
  target = "";
  await desk.approve(g.id, early, T0);
  await desk.collect(g.id, "agent", T0);
  hold.open();
  await refuses(held, "not_pending");
  assert.equal((await desk.grant(g.id)).status, "collected");
});

test("a held counter-0 approval cannot roll back a counter-1 approval on another grant", async () => {
  const hold = gate();
  let target = "";
  const { desk, key } = await setup({ afterVerify: async (id) => (id === target ? hold.wait() : undefined) });
  const a = await desk.request(ask, "agent", T0);
  const b = await desk.request({ ...ask, params: { word: "other" } }, "agent", T0);
  const oa = await desk.approvalOptions(a.id, T0);
  const ob = await desk.approvalOptions(b.id, T0);
  target = a.id;
  const held = desk.approve(a.id, await key.assert(oa.challenge, site.rpID, site.origin, { counter: 0 }), T0);
  await hold.arrived;
  await desk.approve(b.id, await key.assert(ob.challenge, site.rpID, site.origin, { counter: 1 }), T0);
  hold.open();
  await refuses(held, "stale_counter");
  assert.equal((await desk.passkeys())[0].counter, 1);
  assert.equal((await desk.grant(a.id)).status, "pending");
});

test("taps refused before the passkey check are logged (expired, reused, unknown passkey)", async () => {
  const { desk, key } = await setup();
  const fresh = await SoftKey.create();
  const lines = async () => (await desk.readLog()).filter((e) => e.event === "refused").map((e) => e.detail);
  // Enrollment page left open past the challenge clock -- Ben's 2026-10-26 first attempt.
  const store2 = new MemoryStore();
  const desk2 = new Desk(store2, site);
  const late = await fresh.register(await desk2.enrollOptions(T0), site.origin);
  await refuses(desk2.enroll(late, T0 + CHALLENGE_TTL_MS + 1), "challenge_expired");
  assert.deepEqual((await desk2.readLog()).map((e) => e.detail), ["enroll: challenge_expired"]);
  const g = await desk.request(ask, "agent", T0);
  const options = await desk.approvalOptions(g.id, T0);
  await refuses(desk.approve(g.id, await key.assert(options.challenge, site.rpID, site.origin), T0 + CHALLENGE_TTL_MS + 1), "challenge_expired");
  const o2 = await desk.approvalOptions(g.id, T0);
  await refuses(desk.approve(g.id, await fresh.assert(o2.challenge, site.rpID, site.origin), T0), "unknown_passkey");
  const o3 = await desk.approvalOptions(g.id, T0);
  const signed = await key.assert(o3.challenge, site.rpID, site.origin);
  await desk.approve(g.id, signed, T0);
  const g2 = await desk.request(ask, "agent", T0);
  await refuses(desk.approve(g2.id, signed, T0), "challenge_used");
  assert.deepEqual(await lines(), ["approve: challenge_expired", "unknown passkey", "approve: challenge_used"]);
});

test("approvals for missing, used or expired grants and a second enrollment are logged", async () => {
  const { desk, key } = await setup();
  const fresh = await SoftKey.create();
  const g = await desk.request(ask, "agent", T0);
  const o = await desk.approvalOptions(g.id, T0);
  const signed = await key.assert(o.challenge, site.rpID, site.origin);
  await refuses(desk.approve("nope", signed, T0), "no_such_grant");
  await desk.approve(g.id, signed, T0);
  await refuses(desk.approve(g.id, signed, T0), "not_pending");
  const late = await desk.request(ask, "agent", T0);
  await refuses(desk.approve(late.id, signed, T0 + APPROVE_WINDOW_MS + 1), "grant_expired");
  await refuses(desk.enroll(await fresh.register({ challenge: "x", rp: { id: site.rpID, name: "x" }, user: { id: "eA", name: "x", displayName: "x" } } as never, site.origin), T0), "already_enrolled");
  const details = (await desk.readLog()).filter((e) => e.event === "refused").map((e) => e.detail);
  assert.deepEqual(details, ["approve: no_such_grant", "approve: not_pending", "approve: grant_expired", "enroll: already_enrolled"]);
});

test("log detail stays valid JSON and says when it shortened a long token list", async () => {
  const { logDetail, LOG_DETAIL_MAX } = await import("../src/desk.ts");
  const small = { ok: true, audit: { new_since_setup: [], minted_still_listed: [] } };
  assert.equal(logDetail(small), JSON.stringify(small));
  const ids = Array.from({ length: 300 }, (_, i) => `token${i}`);
  const big = logDetail({ ok: false, zone: "benculbert.com", audit: { tokens: 300, new_since_setup: ids, minted_still_listed: [] } });
  assert.ok(big.length <= LOG_DETAIL_MAX);
  const parsed = JSON.parse(big);
  assert.equal(parsed.truncated, true);
  assert.deepEqual(parsed.audit.new_since_setup, { first: ids.slice(0, 10), total: 300 });
  assert.equal(parsed.ok, false);
});

// Nightly headcount (C5c-2 3baea7cc): the desk logs the vault's count and tells the alarm.
const clean: Headcount = { ok: true, tokens: 5, unexpected: [], stretched: [], missing: [], github: { ok: true, changes: [] } };
function headcountDesk(answer: () => Promise<Headcount>) {
  const store = new MemoryStore();
  const vault = { status: async () => ({ stored: true, pending: false }), run: async () => ({}) as any, headcount: answer, ghPreview: async () => ({ changes: [], snapshot: "" }) };
  const told: { ok: boolean; detail: string }[] = [];
  const alarm = async (ok: boolean, detail: string) => void told.push({ ok, detail });
  return { desk: new Desk(store, site, { vault }), told, alarm };
}

test("headcount: a clean night logs 'headcount_ok' and sends the all-clear", async () => {
  const { desk, told, alarm } = headcountDesk(async () => clean);
  await desk.headcount(alarm, T0);
  assert.deepEqual(told, [{ ok: true, detail: "ok: 5 keys, all expected" }]);
  const [row] = await desk.readLog();
  assert.equal(row.event, "headcount_ok");
});

test("headcount: a planted key fails the alarm, naming the key, and is logged", async () => {
  const { desk, told, alarm } = headcountDesk(async () => ({ ...clean, ok: false, unexpected: [{ id: "planted1", name: "x" }] }));
  await desk.headcount(alarm, T0);
  assert.equal(told[0].ok, false);
  assert.match(told[0].detail, /planted1/);
  assert.equal((await desk.readLog())[0].event, "headcount_mismatch");
});

test("headcount: a vault error is a fail, never an all-clear", async () => {
  const { desk, told, alarm } = headcountDesk(async () => {
    throw new Error("vault down");
  });
  await desk.headcount(alarm, T0);
  assert.equal(told[0].ok, false);
  assert.match(told[0].detail, /vault down/);
});

test("headcount: no alarm, or an alarm that fails, is logged", async () => {
  const a = headcountDesk(async () => clean);
  await a.desk.headcount(undefined, T0);
  assert.deepEqual((await a.desk.readLog()).map((e) => e.event), ["headcount_ok", "headcount_alarm_failed"]);
  const b = headcountDesk(async () => clean);
  await b.desk.headcount(async () => {
    throw new Error("healthchecks answered 503");
  }, T0);
  assert.match((await b.desk.readLog())[1].detail ?? "", /503/);
});

test("headcount alarm: all-clear pings the check; a fail pings /fail AND pushes the detail to ntfy; refuses other URLs", async () => {
  const hc = "https://hc-ping.com/0f2e8a4c-1b2d-4e5f-8a9b-0c1d2e3f4a5b";
  const topic = "https://ntfy.sh/front-desk-test-topic-0001";
  const sent: { url: string; body: unknown; title?: string }[] = [];
  const fetchFn = (async (url: string, init?: RequestInit) => (
    sent.push({ url, body: init?.body, title: (init?.headers as Record<string, string> | undefined)?.Title }), new Response("OK")
  )) as typeof fetch;
  await headcountAlarm(hc, topic, fetchFn)!(true, "ok");
  await headcountAlarm(hc, topic, fetchFn)!(false, "MISMATCH planted1");
  assert.deepEqual(sent, [
    { url: hc, body: "ok", title: undefined },
    { url: `${hc}/fail`, body: "MISMATCH planted1", title: undefined },
    { url: topic, body: "MISMATCH planted1", title: "Front desk: key headcount MISMATCH" },
  ]);
  for (const bad of [undefined, "", "http://hc-ping.com/0f2e8a4c-1b2d-4e5f-8a9b-0c1d2e3f4a5b", "https://evil.example/0f2e8a4c-1b2d-4e5f-8a9b-0c1d2e3f4a5b"])
    assert.equal(headcountAlarm(bad, topic, fetchFn), undefined);
  sent.length = 0;
  await assert.rejects(headcountAlarm(hc, "https://evil.example/topic-name-long-enough", fetchFn)!(false, "x"), /no ntfy topic/);
  assert.deepEqual(sent.map((x) => x.url), [`${hc}/fail`], "healthchecks still gets the fail when ntfy is not set");
  const down = (async () => new Response("", { status: 503 })) as unknown as typeof fetch;
  await assert.rejects(headcountAlarm(hc, topic, down)!(true, "ok"), /503/);
  const ntfyDown = (async (url: string) => new Response("", { status: url.includes("ntfy") ? 502 : 200 })) as unknown as typeof fetch;
  await assert.rejects(headcountAlarm(hc, topic, ntfyDown)!(false, "x"), /ntfy answered 502/);
});

test("headcount setup job: takes no parameters and says it is a standing key", () => {
  const job = JOBS["cf.token.headcount.setup"];
  assert.deepEqual(job.validate({}), {});
  assert.equal(job.validate({ zone: "benculbert.com" }), null);
  assert.equal(job.validate(null), null);
  assert.match(job.describe(), /standing key/);
  assert.equal(job.vault, true);
});
