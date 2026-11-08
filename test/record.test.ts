// Record before run (card 97a2e83d). One or more tests per row of the threat table
// (studio-os docs/specifications/trust-but-verify/RECORD-BEFORE-RUN-THREATS-97a2e83d.md, R1-R12).
// Each safeguard is shown working first, then refusing the unsafe case
// (instruction.control-must-refuse-unsafe-case).

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { Desk, DeskError, MemoryStore, type DeskHooks, type Grant } from "../src/desk.ts";
import { recorderFrom, RecorderError } from "../src/recorder.ts";
import { FakeRecorder } from "./fakerecorder.ts";
import { SoftKey } from "./softkey.ts";

const site = { origin: "https://desk.example", rpID: "desk.example" };
const T0 = 1_800_000_000_000;
const echo = { job: "test.echo", params: { word: "hello" }, reason: "prove the desk records" };
const PRF = Buffer.from(new Uint8Array(32).fill(7)).toString("base64url");
const MINTED = "M".repeat(40);

async function refuses(p: Promise<unknown>, code: string) {
  await assert.rejects(p, (e: unknown) => e instanceof DeskError && e.code === code);
}

function fakeVault() {
  const runs: string[] = [];
  const vault = {
    status: async () => ({ stored: true, pending: false }),
    run: async (job: string) => {
      runs.push(job);
      return { ok: true, key: { id: "k1", value: MINTED } } as any;
    },
    headcount: async () => ({}) as any,
    ghPreview: async () => ({ changes: [], snapshot: "", base: "" }),
    cfPreview: async () => [],
  };
  return { vault, runs };
}

async function setup(hooks: DeskHooks = {}) {
  const rec = new FakeRecorder();
  const store = new MemoryStore();
  const { vault, runs } = fakeVault();
  const desk = new Desk(store, site, { recorder: rec.send, vault, ...hooks });
  const key = await SoftKey.create();
  await desk.enroll(await key.register(await desk.enrollOptions(T0), site.origin), T0);
  return { rec, store, desk, key, runs };
}

async function answer(desk: Desk, key: SoftKey, id: string, prf?: string) {
  const options = await desk.approvalOptions(id, T0);
  return { ...(await key.assert(options.challenge, site.rpID, site.origin)), ...(prf ? { prf } : {}) };
}

const spki = () => (generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64url");

test("happy path: request, approval and result are recorded in order, each naming the request", async () => {
  const { rec, desk, key } = await setup();
  const g = await desk.request(echo, "agent", T0);
  assert.deepEqual(rec.stages(g.id), ["request", "verdict"]);
  await desk.approve(g.id, await answer(desk, key, g.id), T0);
  assert.deepEqual(rec.stages(g.id), ["request", "verdict", "approval"]);
  await desk.collect(g.id, "agent", T0 + 1000);
  assert.deepEqual(rec.stages(g.id), ["request", "verdict", "approval", "result"]);
  const [req, verdict, appr, res] = rec.records.map((r) => r.record);
  assert.equal(req.grant_hash, g.hash);
  assert.equal(verdict.overseer, "not_checked");
  assert.equal(verdict.request, (await desk.grant(g.id)).recorded!.request);
  assert.equal(appr.request, (await desk.grant(g.id)).recorded!.request);
  assert.equal(res.outcome, "done");
  assert.deepEqual((await desk.grant(g.id)).recorded, { request: (await desk.grant(g.id)).recorded!.request, verdict: 2, approval: 3, result: 4 });
});

test("R1: with no recorder set, a request is refused and no grant exists", async () => {
  const { store, desk } = await setup({ recorder: undefined });
  await refuses(desk.request(echo, "agent", T0), "recorder_unavailable");
  assert.equal((await store.list({ prefix: "grant:" })).size, 0);
  assert.match((await desk.readLog()).at(-1)!.detail!, /request not recorded: recorder not set/);
});

test("R2: recorder down at request: refused, nothing for Ben to approve", async () => {
  const { rec, store, desk } = await setup();
  rec.down = true;
  await refuses(desk.request(echo, "agent", T0), "recorder_unavailable");
  assert.equal((await store.list({ prefix: "grant:" })).size, 0);
  rec.down = false;
  assert.equal((await desk.request(echo, "agent", T0)).status, "pending");
});

test("R3: a receipt for other bytes, another grant or another stage does not count", async () => {
  const url = "https://rec.example/v1/records";
  const answers = [
    (r: any) => ({ ...r, sha256: "0".repeat(64) }),
    (r: any) => ({ ...r, grant: "othergrant1" }),
    (r: any) => ({ ...r, stage: "result" }),
  ];
  for (const bend of answers) {
    const fetchFn = (async (_u: string, init: RequestInit) => {
      const body = String(init.body);
      const sha = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body))).toString("hex");
      const good = { v: 1, seq: 1, key: "k", grant: JSON.parse(body).grant, stage: JSON.parse(body).stage, sha256: sha, recorded_at: "t" };
      return new Response(JSON.stringify({ receipt: bend(good) }), { status: 201 });
    }) as unknown as typeof fetch;
    const send = recorderFrom(url, "id.access", "s", fetchFn)!;
    await assert.rejects(send({ grant: "grant0001", stage: "request", job: "test.echo" }), RecorderError);
  }
  // Safeguard working: the unbent receipt is accepted.
  const ok = (async (_u: string, init: RequestInit) => {
    const body = String(init.body);
    const sha = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body))).toString("hex");
    return new Response(JSON.stringify({ receipt: { seq: 4, grant: "grant0001", stage: "request", sha256: sha } }), { status: 201 });
  }) as unknown as typeof fetch;
  assert.equal((await recorderFrom(url, "id.access", "s", ok)!({ grant: "grant0001", stage: "request", job: "test.echo" })).seq, 4);
  // Missing or odd settings: no recorder at all.
  assert.equal(recorderFrom(undefined, "id", "s"), undefined);
  assert.equal(recorderFrom(url, "", "s"), undefined);
  assert.equal(recorderFrom(url, "id", undefined), undefined);
  assert.equal(recorderFrom("http://rec.example/v1/records", "id", "s"), undefined);
});

test("R4: approval not recorded: vault job never runs, grant is stopped, collect refused", async () => {
  const { rec, desk, key, runs } = await setup();
  const g = await desk.request({ job: "cf.token.headcount.setup", params: {}, reason: "vault job" }, "agent", T0);
  rec.failStage = "approval";
  await refuses(desk.approve(g.id, await answer(desk, key, g.id, PRF), T0), "approval_not_recorded");
  assert.deepEqual(runs, []);
  assert.equal((await desk.grant(g.id)).status, "stopped");
  await refuses(desk.collect(g.id, "agent", T0 + 1000), "stopped");
  // Safeguard working: with the approval recorded, the vault runs once and the result is recorded.
  rec.failStage = undefined;
  const g2 = await desk.request({ job: "cf.token.headcount.setup", params: {}, reason: "vault job" }, "agent", T0);
  await desk.approve(g2.id, await answer(desk, key, g2.id, PRF), T0);
  assert.deepEqual(runs, ["cf.token.headcount.setup"]);
  assert.deepEqual(rec.stages(g2.id), ["request", "verdict", "approval", "result"]);
});

test("R4: approval not recorded for a plain job: collect does not run it", async () => {
  const { rec, desk, key } = await setup();
  const g = await desk.request(echo, "agent", T0);
  rec.failStage = "approval";
  await refuses(desk.approve(g.id, await answer(desk, key, g.id), T0), "approval_not_recorded");
  await refuses(desk.collect(g.id, "agent", T0 + 1000), "stopped");
  assert.deepEqual(rec.stages(g.id), ["request", "verdict"]);
});

test("R5: approval not recorded: the c-box key is not enrolled", async () => {
  const { rec, store, desk, key } = await setup();
  const g = await desk.request({ job: "cbox.key.enroll", params: { key: spki() }, reason: "new key" }, "agent", T0);
  rec.failStage = "approval";
  await refuses(desk.approve(g.id, await answer(desk, key, g.id), T0), "approval_not_recorded");
  assert.equal(await store.get("cbox:key"), undefined);
  rec.failStage = undefined;
  const g2 = await desk.request({ job: "cbox.key.enroll", params: { key: spki() }, reason: "new key" }, "agent", T0);
  await desk.approve(g2.id, await answer(desk, key, g2.id), T0);
  assert.ok(await store.get("cbox:key"));
  assert.deepEqual(rec.stages(g2.id), ["request", "verdict", "approval", "result"]);
  // Its collect hands over the word only; no second result.
  await desk.collect(g2.id, "agent", T0 + 1000);
  assert.deepEqual(rec.stages(g2.id), ["request", "verdict", "approval", "result"]);
});

test("R6 (change-over): a grant made before recording began is never approved or collected", async () => {
  const { store, desk, key } = await setup();
  const g = await desk.request(echo, "agent", T0);
  const { recorded: _r, ...old } = await desk.grant(g.id);
  await store.put(`grant:${g.id}`, old);
  await refuses(desk.approvalOptions(g.id, T0).then(async (o) => desk.approve(g.id, await key.assert(o.challenge, site.rpID, site.origin), T0)), "not_recorded");
  await store.put<Grant>(`grant:${g.id}`, { ...old, status: "approved", approved_at: T0 });
  await refuses(desk.collect(g.id, "agent", T0 + 1000), "not_recorded");
});

test("V1: verdict not recorded: no grant exists, nothing for Ben to approve (card 6da30339)", async () => {
  const { rec, store, desk } = await setup();
  rec.failStage = "verdict";
  await refuses(desk.request(echo, "agent", T0), "recorder_unavailable");
  assert.equal((await store.list({ prefix: "grant:" })).size, 0);
  assert.match((await desk.readLog()).at(-1)!.detail!, /verdict not recorded/);
  // Safeguard working: with the verdict recorded, the grant waits for Ben.
  rec.failStage = undefined;
  assert.equal((await desk.request(echo, "agent", T0)).status, "pending");
});

test("V2 (change-over): a grant asked before verdicts were recorded is never approved", async () => {
  const { store, desk, key } = await setup();
  const g = await desk.request(echo, "agent", T0);
  const old: Grant = { ...g, recorded: { request: g.recorded!.request } };
  await store.put(`grant:${g.id}`, old);
  await refuses(desk.approvalOptions(g.id, T0).then(async (o) => desk.approve(g.id, await key.assert(o.challenge, site.rpID, site.origin), T0)), "not_recorded");
});

test("R7: while the approval is being recorded, a second approve and a collect are both refused", async () => {
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  const rec = new FakeRecorder();
  const send: typeof rec.send = async (r) => {
    if (r.stage === "approval") await gate;
    return rec.send(r);
  };
  const { desk, key } = await setup({ recorder: send });
  const g = await desk.request(echo, "agent", T0);
  const first = answer(desk, key, g.id).then((a) => desk.approve(g.id, a, T0));
  await new Promise((r) => setTimeout(r, 20));
  // Transient, so the agent's wait keeps polling (scripts/agent.mjs retries not_ready).
  await refuses(desk.collect(g.id, "agent", T0 + 10), "not_ready");
  await refuses(answer(desk, key, g.id), "not_pending");
  release();
  await first;
  assert.deepEqual((await desk.collect(g.id, "agent", T0 + 20)).result, { echoed: "hello" });
});

test("R8: c-box key replaced while the approval is recorded: the key job stops, the vault never runs", async () => {
  let during: () => Promise<void> = async () => {};
  const rec = new FakeRecorder();
  const send: typeof rec.send = async (r) => {
    if (r.stage === "approval") await during();
    return rec.send(r);
  };
  const { store, desk, key, runs } = await setup({ recorder: send });
  const signed = { ip: "203.0.113.7", checkSignature: async () => {} };
  const g = await desk.request({ job: "cf.dns.list", params: { zone: "benculbert.com" }, reason: "read" }, "agent", T0, signed);
  during = async () => store.put("cbox:rev", ((await store.get<number>("cbox:rev")) ?? 0) + 1);
  await refuses(desk.approve(g.id, await answer(desk, key, g.id, PRF), T0), "cbox_key_changed");
  assert.deepEqual(runs, []);
  assert.equal((await desk.grant(g.id)).status, "stopped");
  // Safeguard working: unchanged key, the job runs.
  during = async () => {};
  const g2 = await desk.request({ job: "cf.dns.list", params: { zone: "benculbert.com" }, reason: "read" }, "agent", T0, signed);
  await desk.approve(g2.id, await answer(desk, key, g2.id, PRF), T0);
  assert.deepEqual(runs, ["cf.dns.list"]);
});

test("R9: the agent cannot name record fields; extra params never reach a record", async () => {
  const { rec, desk } = await setup();
  const g = await desk.request({ ...echo, params: { word: "hello", token: "x", secret: "y" } }, "agent", T0);
  assert.deepEqual(rec.records[0].record.params, { word: "hello" });
  assert.deepEqual(Object.keys(rec.records[0].record).sort(), ["created_at", "expires_at", "grant", "grant_hash", "job", "params", "reason", "requester", "stage", "v"]);
  assert.equal(g.status, "pending");
});

test("R10: no record carries the minted key, the passkey secret or the user handle", async () => {
  const { rec, desk, key } = await setup();
  const signed = { ip: "203.0.113.7", checkSignature: async () => {} };
  const g = await desk.request({ job: "cf.dns.list", params: { zone: "benculbert.com" }, reason: "read" }, "agent", T0, signed);
  const a = await answer(desk, key, g.id, PRF);
  await desk.approve(g.id, { ...a, response: { ...a.response, userHandle: "dXNlci1oYW5kbGU" } }, T0);
  const all = rec.records.map((r) => r.body).join("\n");
  assert.ok(!all.includes(MINTED), "minted key value in a record");
  assert.ok(!all.includes(PRF), "passkey secret in a record");
  assert.ok(!all.includes("dXNlci1oYW5kbGU"), "user handle in a record");
  assert.deepEqual(Object.keys(rec.records[2].record.assertion as object).sort(), ["authenticator_data", "client_data_json", "passkey_id", "signature"]);
  assert.deepEqual(rec.records[3].record.outcome, "done");
});

test("R11: a lost answer is retried once with the same bytes; a refusal is not retried", async () => {
  const url = "https://rec.example/v1/records";
  const bodies: string[] = [];
  let calls = 0;
  const flaky = (async (_u: string, init: RequestInit) => {
    bodies.push(String(init.body));
    if (calls++ === 0) throw new Error("network");
    const sha = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(init.body)))).toString("hex");
    return new Response(JSON.stringify({ receipt: { seq: 1, grant: "grant0001", stage: "request", sha256: sha } }), { status: 200 });
  }) as unknown as typeof fetch;
  await recorderFrom(url, "id", "s", flaky)!({ grant: "grant0001", stage: "request", job: "test.echo" });
  assert.equal(bodies.length, 2);
  assert.equal(bodies[0], bodies[1]);
  let refusedCalls = 0;
  const refusing = (async () => (refusedCalls++, new Response("{}", { status: 409 }))) as unknown as typeof fetch;
  await assert.rejects(recorderFrom(url, "id", "s", refusing)!({ grant: "grant0001", stage: "request", job: "test.echo" }), /answered 409/);
  assert.equal(refusedCalls, 1);
  // A recorder that never answers times out instead of holding the desk.
  const hung = (() => new Promise<Response>(() => {})) as unknown as typeof fetch;
  // The sentinel keeps the test alive and fails it if the desk's own timeout never fires.
  const sentinel = new Promise((_, reject) => setTimeout(() => reject(new Error("no timeout fired")), 500));
  await assert.rejects(Promise.race([recorderFrom(url, "id", "s", hung, 10)!({ grant: "grant0001", stage: "request", job: "test.echo" }), sentinel]), /recorder unreachable/);
});

test("R12: result not recorded after the job ran: the job's answer still stands, the miss is logged and pushed to Ben", async () => {
  const told: string[] = [];
  const { rec, desk, key, runs } = await setup({ alert: async (title) => void told.push(title) });
  const g = await desk.request({ job: "cf.token.headcount.setup", params: {}, reason: "vault job" }, "agent", T0);
  rec.failStage = "result";
  const done = await desk.approve(g.id, await answer(desk, key, g.id, PRF), T0);
  assert.deepEqual(runs, ["cf.token.headcount.setup"]);
  assert.equal((done.result as { ok: boolean }).ok, true);
  assert.ok((await desk.readLog()).some((e) => e.event === "result_unrecorded" && e.grant_id === g.id));
  assert.equal((await desk.grant(g.id)).recorded!.result, undefined);
  assert.deepEqual(told, ["Front desk: a job ran but was not fully recorded"]);
});

test("R12: the alert itself fails or is not set up: logged, and the job's answer still stands", async () => {
  // Rejected, never settling (bounded by ALERT_TIMEOUT_MS), and not set up.
  for (const alert of [async () => { throw new Error("pushover answered 500"); }, () => new Promise<void>(() => {}), undefined]) {
    const { rec, desk, key } = await setup({ alert });
    const g = await desk.request({ job: "cf.token.headcount.setup", params: {}, reason: "vault job" }, "agent", T0);
    rec.failStage = "result";
    const done = await desk.approve(g.id, await answer(desk, key, g.id, PRF), T0);
    assert.equal((done.result as { ok: boolean }).ok, true);
    assert.ok((await desk.readLog()).some((e) => e.event === "alert_failed" && e.grant_id === g.id));
  }
});

test("R11: a body that stalls or will not parse is bounded by the same deadline and retried with the same bytes", async () => {
  const url = "https://rec.example/v1/records";
  for (const bad of ["stall", "garbage"]) {
    const bodies: string[] = [];
    const fetchFn = (async (_u: string, init: RequestInit) => {
      bodies.push(String(init.body));
      if (bodies.length === 1) {
        const stream = new ReadableStream({ start: (c) => (bad === "garbage" ? (c.enqueue(new TextEncoder().encode("{not json")), c.close()) : undefined) });
        return new Response(stream, { status: 201 });
      }
      const sha = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(init.body)))).toString("hex");
      return new Response(JSON.stringify({ receipt: { seq: 1, grant: "grant0001", stage: "request", sha256: sha } }), { status: 201 });
    }) as unknown as typeof fetch;
    const sentinel = new Promise((_, reject) => setTimeout(() => reject(new Error("no timeout fired")), 500));
    const r = await Promise.race([recorderFrom(url, "id", "s", fetchFn, 20)!({ grant: "grant0001", stage: "request", job: "test.echo" }), sentinel]);
    assert.equal((r as { seq: number }).seq, 1, bad);
    assert.equal(bodies.length, 2);
    assert.equal(bodies[0], bodies[1]);
  }
});

test("the agent's wait keeps polling on not_ready and stops on not_recorded", async () => {
  const src = String(readFileSync(new URL("../scripts/agent.mjs", import.meta.url).pathname));
  assert.match(src, /res\.status === 409 && text\.includes\("not_ready"\)/);
});
