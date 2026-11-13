// Card 139071ea, desk side (studio-os REFINE-139071ea-cf-keys-in-results.md v2.1, evidence E1 items 4, 5 and 7): the
// desk copies the vault's `cf` into the signed result -- frozen for a card entry, built once for an ordinary tap with
// a completion time -- and signs "unknown" when it holds no well-formed answer. Jobs that never open the master carry
// no `cf`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { CF_MASTER_JOBS, Desk, MemoryStore, cfOf } from "../src/desk.ts";
import { CardDesk } from "../src/carddesk.ts";
import { CARD_API_VERSION, CARD_CAP, JOBS_VERSION, type RunEntry } from "../vault/src/cards.ts";
import { CF_LIST_MAX } from "../vault/src/cloudflare.ts";
import { cardBook, PRF } from "./cardsign.ts";
import { FakeRecorder } from "./fakerecorder.ts";
import { TEST_KEY } from "./vaultsign.ts";
import { SoftKey } from "./softkey.ts";

const T0 = 1_800_000_000_000;
const site = { origin: "https://desk.example", rpID: "desk.example" };
const signedSrc = { checkSignature: async () => {} };
const hexId = (n: number) => n.toString(16).padStart(32, "0");
const CF = { made: [hexId(1), hexId(2)], deleted: [hexId(1), hexId(2), hexId(3)] };
const zoneRead = { job: "cf.zone.read", params: { zone: "benculbert.com" }, reason: "read the zone" };
const echo = { job: "test.echo", params: { word: "hello" }, reason: "prove cards" };

async function rig(runEntry: RunEntry = async (job) => ({ ok: true, job, data: {}, cf: CF })) {
  const vb = await cardBook({ runEntry, t: T0 });
  const fr = new FakeRecorder();
  fr.signer = vb.rec;
  const fail: Partial<Record<string, number>> = {};
  const lose = async <T>(name: string, p: () => Promise<T> | T): Promise<T> => {
    if (fail[name]) {
      fail[name]!--;
      throw new Error("vault unreachable");
    }
    return p();
  };
  const vault = {
    cardApi: async () => ({ version: CARD_API_VERSION, jobs_version: JOBS_VERSION, cap: CARD_CAP }),
    cardOpen: (r: unknown) => lose("cardOpen", () => vb.book.open(r)),
    cardRun: (r: unknown) => lose("cardRun", () => vb.book.run(r)),
    cardStop: (id: string) => lose("cardStop", () => vb.book.stop(id)),
    cardStatus: (id: string) => lose("cardStatus", () => vb.book.status(id)),
    cardAck: (id: string, i: number) => lose("cardAck", () => vb.book.ack(id, i)),
    setKeyRev: async (rev: number) => rev,
  };
  const store = new MemoryStore();
  const desk = new CardDesk(store, site, { recorder: fr.send, vault: vault as never });
  await desk.enroll(await TEST_KEY.register(await desk.enrollOptions(T0), site.origin), T0);
  const again = () => new CardDesk(store, site, { recorder: fr.send, vault: vault as never }); // a restart: same storage
  return { desk, store, vb, fr, fail, again };
}
async function tap(desk: CardDesk, id: string, now = T0) {
  const o = await desk.cardOptions(id, now);
  const r = await TEST_KEY.assert(o.challenge, site.rpID, site.origin);
  return desk.approveCard(id, { ...r, prf: PRF } as never, now);
}
const resultsOf = (fr: FakeRecorder, grant: string) => fr.sent.filter((b) => JSON.parse(b).stage === "result" && JSON.parse(b).grant === grant);

test("cfOf: copies only well-formed lists; anything else is unknown; no cf for jobs that never open the master", () => {
  for (const job of CF_MASTER_JOBS) assert.deepEqual(cfOf(job, { ok: true, cf: CF }), CF, job);
  const bad: unknown[] = [
    undefined, null, {}, { cf: "unknown" }, { cf: null }, { cf: [] }, { cf: { made: [] } }, { cf: { made: [], deleted: [], extra: 1 } },
    { cf: { made: ["minted1"], deleted: [] } }, { cf: { made: [hexId(0xab).toUpperCase()], deleted: [] } }, { cf: { made: [], deleted: [7] } },
    { cf: { made: Array.from({ length: CF_LIST_MAX + 1 }, (_, i) => hexId(i)), deleted: [] } }, { error: "cf_500", vault_stage: "unknown" },
  ];
  for (const a of bad) assert.equal(cfOf("cf.dns.list", a), "unknown", JSON.stringify(a));
  const bound = Array.from({ length: CF_LIST_MAX }, (_, i) => hexId(i));
  assert.deepEqual(cfOf("cf.dns.list", { cf: { made: [], deleted: bound } }), { made: [], deleted: bound }, "exactly the bound is admitted");
  for (const job of ["test.echo", "gh.repo.create", "gh.app.baseline", "cbox.key.enroll"]) assert.equal(cfOf(job, { cf: CF }), undefined, job);
});

test("E1.4 card: the result names the keys the entry made and deleted; a test.echo entry carries no cf", async () => {
  const { desk, fr } = await rig();
  const { card, grants } = await desk.requestCard({ entries: [echo, zoneRead] }, "agent", T0, signedSrc);
  await tap(desk, card.id);
  const [e, z] = grants.map((g) => JSON.parse(resultsOf(fr, g.id)[0]));
  assert.equal("cf" in e, false, "a job that never opens the master signs no cf");
  assert.deepEqual(z.cf, CF);
  assert.equal(z.outcome, "done");
});

test("E1.4 card: lost recorder reply, two concurrent reads and a restart all resend identical bytes with the same cf", async () => {
  const { desk, fr, again } = await rig();
  const { card, grants } = await desk.requestCard({ entries: [zoneRead] }, "agent", T0, signedSrc);
  fr.loseAnswer.add("result");
  await tap(desk, card.id);
  await Promise.all([desk.collectCard(card.id, "agent", T0 + 1000, signedSrc), desk.collectCard(card.id, "agent", T0 + 1000, signedSrc)]);
  await again().collectCard(card.id, "agent", T0 + 2000, signedSrc);
  const sent = resultsOf(fr, grants[0].id);
  assert.ok(sent.length >= 2, String(sent.length));
  assert.ok(sent.every((b) => b === sent[0]), "identical bytes on every send");
  assert.deepEqual(JSON.parse(sent[0]).cf, CF);
});

test("E1.4 card: the answer erased after the freeze keeps the frozen cf", async () => {
  const { desk, fr, store } = await rig();
  const { card, grants } = await desk.requestCard({ entries: [zoneRead] }, "agent", T0, signedSrc);
  fr.loseAnswer.add("result");
  await tap(desk, card.id);
  const g = (await desk.grant(grants[0].id))!;
  await store.put(`grant:${g.id}`, { ...g, result: undefined, answer_erased: true });
  await desk.collectCard(card.id, "agent", T0 + 1000, signedSrc);
  const sent = resultsOf(fr, grants[0].id);
  assert.equal(sent.length, 2);
  assert.equal(sent[1], sent[0]);
  assert.deepEqual(JSON.parse(sent[1]).cf, CF);
});

test("E1.4 card: no answer held when the body is first frozen signs unknown", async () => {
  const { desk, fr, vb, fail } = await rig();
  const { card, grants } = await desk.requestCard({ entries: [zoneRead] }, "agent", T0, signedSrc);
  fail.cardStatus = 1; // the read right after the tap is lost: nothing stored, nothing frozen
  await tap(desk, card.id);
  assert.equal(resultsOf(fr, grants[0].id).length, 0, "checkpoint: nothing frozen yet");
  vb.clock.now = T0 + 10 * 60_000; // the vault has dropped its answer (closed + 5 min)
  await desk.collectCard(card.id, "agent", T0 + 10 * 60_000, signedSrc);
  const body = JSON.parse(resultsOf(fr, grants[0].id)[0]);
  assert.equal(body.outcome, "done");
  assert.equal(body.cf, "unknown");
});

test("E1.4 card: a malformed cf, or a job that threw, signs unknown", async () => {
  const answers: RunEntry[] = [
    async (job) => ({ ok: true, job, data: {}, cf: { made: ["nothex"], deleted: [] } }),
    async (job) => ({ ok: true, job, data: {} }),
    async (job) => ({ ok: true, job, data: {}, cf: "unknown" }),
    async () => {
      throw new Error("lost");
    },
  ];
  for (const runEntry of answers) {
    const { desk, fr } = await rig(runEntry);
    const { card, grants } = await desk.requestCard({ entries: [zoneRead] }, "agent", T0, signedSrc);
    await tap(desk, card.id);
    assert.equal(JSON.parse(resultsOf(fr, grants[0].id)[0]).cf, "unknown");
  }
});

// ---- Ordinary taps (desk.ts approve -> recordResult) ----
const HC = { job: "cf.token.headcount.setup", params: {}, reason: "set up the count" };
async function plain(run: (req: { grant: { job: string } }) => Promise<unknown>, clock?: () => number) {
  const fr = new FakeRecorder();
  const vault = {
    status: async () => ({ stored: true, pending: false }),
    run,
    headcount: async () => ({}) as never,
    ghPreview: async () => ({ changes: [], snapshot: "", base: "" }),
    cfPreview: async () => [],
    approvalApi: async () => ({ version: 1 }),
  };
  const desk = new Desk(new MemoryStore(), site, { recorder: fr.send, vault: vault as never, clock });
  const key = await SoftKey.create();
  await desk.enroll(await key.register(await desk.enrollOptions(T0), site.origin), T0);
  const approve = async (job = HC) => {
    const g = await desk.request(job, "agent", T0);
    const o = await desk.approvalOptions(g.id, T0);
    await desk.approve(g.id, { ...(await key.assert(o.challenge, site.rpID, site.origin)), prf: PRF } as never, T0);
    if (job.job === "test.echo") await desk.collect(g.id, "agent", T0 + 1000); // not a vault job: its result is recorded at collect
    const rec = (stage: string) => fr.records.find((x) => x.grant === g.id && x.stage === stage)?.record as Record<string, any> | undefined;
    return { approval: rec("approval"), result: rec("result") };
  };
  return { approve, fr };
}

test("E1.5 ordinary tap: cf copied from the vault's answer; at is the completion time, after approved_at and every effect", async () => {
  const { approve } = await plain(async () => ({ ok: true, key_id: hexId(1), cf: CF }), () => T0 + 2000);
  const { approval, result } = await approve();
  assert.deepEqual(result!.cf, CF);
  assert.equal(result!.outcome, "done");
  assert.equal(approval!.approved_at, T0);
  assert.equal(result!.at, T0 + 2000, "read after the vault answered, not the request-entry time");
});

test("E1.5 ordinary tap: a vault that answers 2 s after the request -> the result is after it (real clock)", async () => {
  let effectAt = 0;
  const started = Date.now();
  const { approve } = await plain(async () => {
    await new Promise((r) => setTimeout(r, 30)); // a slow vault (time compressed)
    effectAt = Date.now();
    return { ok: true, cf: CF };
  });
  const { result } = await approve();
  assert.ok(result!.at >= effectAt && effectAt >= started, `${result!.at} >= ${effectAt}`);
});

test("E1.5 ordinary tap: a vault that throws, or answers without a well-formed cf, signs unknown", async () => {
  for (const run of [async () => { throw new Error("network connection lost"); }, async () => ({ ok: false, error: "x" }), async () => ({ ok: true, cf: { made: [], deleted: [], more: [] } })]) {
    const { approve } = await plain(run as never, () => T0 + 5);
    assert.equal((await approve()).result!.cf, "unknown");
  }
});

test("E1.7 ordinary tap: a job that never opens the master carries no cf", async () => {
  const { approve } = await plain(async () => ({ ok: true, cf: CF }), () => T0 + 5);
  const { result } = await approve({ job: "test.echo", params: { word: "hello" }, reason: "x" });
  assert.ok(result, "a result was recorded");
  assert.equal("cf" in result!, false);
});
