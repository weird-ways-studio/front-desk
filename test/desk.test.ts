// Each safeguard is shown working first, then refusing the unsafe case
// (instruction.control-must-refuse-unsafe-case).

import { test } from "node:test";
import assert from "node:assert/strict";
import { APPROVE_WINDOW_MS, COLLECT_WINDOW_MS, Desk, DeskError, MemoryStore } from "../src/desk.ts";
import { SoftKey } from "./softkey.ts";

const site = { origin: "https://desk.example", rpID: "desk.example" };
const T0 = 1_800_000_000_000;
const ask = { job: "test.echo", params: { word: "hello" }, reason: "prove the desk works" };

async function refuses(p: Promise<unknown>, code: string) {
  await assert.rejects(p, (e: unknown) => e instanceof DeskError && e.code === code);
}

async function setup() {
  const store = new MemoryStore();
  const desk = new Desk(store, site);
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
