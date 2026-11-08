// Cards, desk side (card 85818ab1; studio-os REFINE-85818ab1.md v2.2: Outcome 1 and 7, U4-U6, V1-V4, W1, T13, T15).
// The desk runs against the REAL vault card book (vault/src/cards.ts) in-process and a recorder that signs real
// receipt/v1 receipts, so the vault's own checks (passkey over the card hash, signed receipt, order, deadline) run
// unmodified. Each safeguard is shown working, then refusing (instruction.control-must-refuse-unsafe-case).
import { test } from "node:test";
import assert from "node:assert/strict";
import { COLLECT_WINDOW_MS, DeskError, MemoryStore } from "../src/desk.ts";
import { CardDesk } from "../src/carddesk.ts";
import { route } from "../src/routes.ts";
import { cardView } from "../src/page.ts";
import { CARD_API_VERSION, CARD_CAP, JOBS_VERSION, type RunEntry } from "../vault/src/cards.ts";
import { cardBook, PRF } from "./cardsign.ts";
import { FakeRecorder } from "./fakerecorder.ts";
import { TEST_KEY } from "./vaultsign.ts";
import type { SoftKey } from "./softkey.ts";

const T0 = 1_800_000_000_000;
const site = { origin: "https://desk.example", rpID: "desk.example" };
const ZONE = { zone: "benculbert.com" };
const signedSrc = { checkSignature: async () => {} };
const two = [
  { job: "test.echo", params: { word: "hello" }, reason: "prove cards" },
  { job: "cf.zone.read", params: ZONE, reason: "read the zone" },
];

async function refuses(p: Promise<unknown>, code: string) {
  await assert.rejects(p, (e: unknown) => e instanceof DeskError && e.code === code, `expected ${code}`);
}

/** A desk wired to a real card book; `calls` lists every vault call in order (the F9 count uses it). */
async function rig(o: { runEntry?: RunEntry; jobs?: readonly string[]; signedReceipts?: boolean; apiVersion?: number } = {}) {
  const vb = await cardBook({ runEntry: o.runEntry, opts: o.jobs ? { jobs: o.jobs } : {}, t: T0 });
  const fr = new FakeRecorder();
  if (o.signedReceipts !== false) fr.signer = vb.rec;
  const calls: string[] = [];
  const fail: Partial<Record<string, number>> = {}; // vault call name -> how many next calls throw after doing their work (lost reply)
  const lose = async <T>(name: string, p: () => Promise<T> | T): Promise<T> => {
    calls.push(name);
    const out = await p();
    if (fail[name]) {
      fail[name]!--;
      throw new Error("network connection lost");
    }
    return out;
  };
  const vault = {
    cardApi: async () => lose("cardApi", () => ({ version: o.apiVersion ?? CARD_API_VERSION, jobs_version: JOBS_VERSION, cap: CARD_CAP })),
    cardOpen: (r: unknown) => lose("cardOpen", () => vb.book.open(r)),
    cardRun: (r: unknown) => lose("cardRun", () => vb.book.run(r)),
    cardStop: (id: string) => lose("cardStop", () => vb.book.stop(id)),
    cardStatus: (id: string) => lose("cardStatus", () => vb.book.status(id)),
    cardAck: (id: string, i: number) => lose("cardAck", () => vb.book.ack(id, i)),
  };
  const store = new MemoryStore();
  const desk = new CardDesk(store, site, { recorder: fr.send, vault: vault as never });
  await desk.enroll(await TEST_KEY.register(await desk.enrollOptions(T0), site.origin), T0);
  return { desk, store, vb, fr, calls, fail, vault };
}

/** The entry's vault state, or "none" before the card is opened (the tap is still checking). */
async function stateOf(vb: { book: { status(id: string): { entries: { state: string }[] } } }, id: string, i = 0): Promise<string> {
  try {
    return vb.book.status(id).entries[i].state;
  } catch {
    return "none";
  }
}
async function until(f: () => Promise<boolean>) {
  for (let i = 0; i < 200 && !(await f()); i++) await new Promise((r) => setTimeout(r, 2));
}

async function tap(desk: CardDesk, id: string, now = T0, key: SoftKey = TEST_KEY, prf: string | null = PRF) {
  const o = await desk.cardOptions(id, now);
  const r = await key.assert(o.challenge, site.rpID, site.origin);
  return desk.approveCard(id, { ...r, prf } as never, now);
}

// ---- Outcome 1 + 7: one tap runs the card, in order; the agent collects everything once ----
test("one tap runs both entries in order; every stage is recorded; the agent collects answers and signed receipts", async () => {
  const { desk, fr, vb, calls } = await rig();
  const { card, grants } = await desk.requestCard({ entries: two }, "agent", T0, signedSrc);
  assert.equal(card.status, "pending");
  assert.equal(card.manifest.deadline, card.expires_at + 15 * 60_000);
  const r = await tap(desk, card.id);
  assert.deepEqual(r.entries.map((e) => e.state), ["done", "done"]);
  assert.deepEqual(vb.calls, ["cf.zone.read"], "test.echo touches nothing; the read ran once");
  for (const g of grants) assert.deepEqual(fr.stages(g.id), ["request", "verdict", "approval", "result"]);
  // Card marks on the records, as the Observatory requires.
  const req = fr.records.find((x) => x.grant === grants[0].id && x.stage === "request")!.record;
  assert.equal(req.card, card.id);
  const appr = fr.records.find((x) => x.grant === grants[1].id && x.stage === "approval")!.record;
  assert.equal(appr.approval_kind, "card/v1");
  assert.deepEqual(appr.manifest, card.manifest);
  const res = fr.records.find((x) => x.grant === grants[1].id && x.stage === "result")!.record;
  assert.equal(res.outcome, "done");
  // Collected once, signed, by the asker only.
  const got = await desk.collectCard(card.id, "agent", T0 + 1000, signedSrc);
  assert.deepEqual(got.entries[0].answer, { ok: true, data: { echoed: "hello" } });
  assert.deepEqual(got.entries[1].answer, { ok: true, job: "cf.zone.read", data: { read: "benculbert.com" } });
  for (const e of got.entries) for (const s of ["request", "verdict", "approval", "result"]) assert.equal(typeof e.receipts[s]?.sig, "string", `${s} receipt signed`);
  await refuses(desk.collectCard(card.id, "someone else", T0, signedSrc), "not_your_card");
  await refuses(desk.collectCard(card.id, "agent", T0, {}), "not_signed");
  // The vault's copies were dropped once the desk stored them (V2).
  assert.equal((await vb.book.status(card.id)).answers[0], undefined);
  assert.ok(calls.includes("cardAck"));
});

// ---- POST /card refusals: nothing reaches Ben or the vault's card book ----
test("POST /card refuses a card over the cap, an ineligible job, bad params, an unsigned request -- before recording anything", async () => {
  const { desk, fr, calls } = await rig();
  await refuses(desk.requestCard({ entries: [...two, two[0]] }, "agent", T0, signedSrc), "too_many_entries");
  await refuses(desk.requestCard({ entries: [{ job: "cbox.key.enroll", params: { key: "x" }, reason: "r" }] }, "agent", T0, signedSrc), "job_not_on_cards");
  await refuses(desk.requestCard({ entries: [{ job: "cf.dns.list", params: { zone: "evil.com" }, reason: "r" }] }, "agent", T0, signedSrc), "bad_params");
  await refuses(desk.requestCard({ entries: two, extra: 1 }, "agent", T0, signedSrc), "bad_card");
  await refuses(desk.requestCard({ entries: [{ ...two[0], reason: " " }] }, "agent", T0, signedSrc), "bad_reason");
  await refuses(desk.requestCard({ entries: [{ ...two[0], reason: "x".repeat(201) }] }, "agent", T0, signedSrc), "bad_reason");
  await refuses(desk.requestCard({ entries: two }, "agent", T0, {}), "not_signed");
  assert.equal(fr.records.length, 0);
  assert.ok(!calls.includes("cardOpen"));
});

test("a vault on another card version: POST /card refused, nothing recorded", async () => {
  const { desk, fr } = await rig({ apiVersion: 99 });
  await refuses(desk.requestCard({ entries: two }, "agent", T0, signedSrc), "vault_unavailable");
  assert.equal(fr.records.length, 0);
});

// ---- T13 + V4: one pending card per requester; a frozen card counts until its grants expire ----
test("one pending card per requester (T13); a partial freeze stops every grant and still counts for 10 minutes (V4)", async () => {
  const { desk, fr } = await rig();
  const a = await desk.requestCard({ entries: two }, "agent", T0, signedSrc);
  await refuses(desk.requestCard({ entries: two }, "agent", T0 + 1, signedSrc), "too_many_pending");
  await desk.stopCard(a.card.id, T0 + 2); // Ben's Stop frees the slot
  // Second card: the second entry's verdict is refused -> nothing sent, all grants stopped.
  let n = 0;
  fr.failIf = (r) => r.stage === "verdict" && ++n === 2;
  await refuses(desk.requestCard({ entries: two }, "agent", T0 + 3, signedSrc), "card_not_sent");
  fr.failIf = undefined;
  const frozen = [...(await (desk as unknown as { store: MemoryStore }).store.list<{ status: string; stopped?: string }>({ prefix: "card:" })).values()].find((c) => c.stopped === "card not sent")!;
  assert.equal(frozen.status, "stopped");
  for (const g of (frozen as unknown as { grants: string[] }).grants) assert.equal((await desk.grant(g)).status, "stopped");
  await refuses(desk.requestCard({ entries: two }, "agent", T0 + 4, signedSrc), "too_many_pending");
  // After the grants' 10 minutes, a new card is allowed.
  await desk.requestCard({ entries: two }, "agent", T0 + 10 * 60_000 + 4, signedSrc);
});

// ---- U6: single routes never reach a card's grants ----
test("the single-grant approve, approval options and collect refuse a card's grants (on_card)", async () => {
  const { desk } = await rig();
  const { grants } = await desk.requestCard({ entries: two }, "agent", T0, signedSrc);
  await refuses(desk.approvalOptions(grants[0].id, T0), "on_card");
  const r = await TEST_KEY.assert("AAAA", site.rpID, site.origin);
  await refuses(desk.approve(grants[0].id, r as never, T0), "on_card");
  await refuses(desk.collect(grants[0].id, "agent", T0, signedSrc), "on_card");
});

// ---- The tap's own checks ----
test("the tap: a replay, another card's challenge, a missing passkey secret, a changed c-box key are refused", async () => {
  const { desk, store } = await rig();
  const a = await desk.requestCard({ entries: [two[0]] }, "agent", T0, signedSrc);
  const b = await desk.requestCard({ entries: [two[0]] }, "agent2", T0, signedSrc);
  const oa = await desk.cardOptions(a.card.id, T0);
  const ra = await TEST_KEY.assert(oa.challenge, site.rpID, site.origin);
  await refuses(desk.approveCard(b.card.id, { ...ra, prf: PRF } as never, T0), "wrong_card");
  await refuses(tap(desk, b.card.id, T0, TEST_KEY, null), "prf_missing");
  // A challenge fetched just before the card expires, tapped just after: refused at the tap itself.
  const late = await desk.cardOptions(a.card.id, a.card.expires_at - 60_000);
  const lr = await TEST_KEY.assert(late.challenge, site.rpID, site.origin);
  await refuses(desk.approveCard(a.card.id, { ...lr, prf: PRF } as never, a.card.expires_at + 1), "card_expired");
  await store.put("cbox:rev", 5);
  await refuses(tap(desk, a.card.id), "cbox_key_changed");
  await store.put("cbox:rev", 0);
  await tap(desk, a.card.id);
  await refuses(tap(desk, a.card.id), "not_pending");
});

test("two taps at once on one card (Release Checklist 6.2): exactly one runs it; the other is refused", async () => {
  const { desk, vb, fr } = await rig();
  const { card, grants } = await desk.requestCard({ entries: [two[1]] }, "agent", T0, signedSrc);
  const o1 = await desk.cardOptions(card.id, T0);
  const o2 = await desk.cardOptions(card.id, T0);
  const r1 = await TEST_KEY.assert(o1.challenge, site.rpID, site.origin);
  const r2 = await TEST_KEY.assert(o2.challenge, site.rpID, site.origin);
  const out = await Promise.allSettled([desk.approveCard(card.id, { ...r1, prf: PRF } as never, T0), desk.approveCard(card.id, { ...r2, prf: PRF } as never, T0)]);
  assert.equal(out.filter((x) => x.status === "fulfilled").length, 1, JSON.stringify(out.map((x) => x.status === "rejected" ? String(x.reason) : "ok")));
  const no = out.find((x) => x.status === "rejected") as PromiseRejectedResult;
  assert.ok(no.reason instanceof DeskError && ["not_pending", "stale_counter"].includes(no.reason.code), String(no.reason));
  assert.deepEqual(vb.calls, ["cf.zone.read"], "the read ran once");
  assert.equal(fr.records.filter((x) => x.grant === grants[0].id && x.stage === "approval").length, 1);
});

test("an expired card's page says it expired, nothing ran, and what happens next -- with no tap or Stop offered", async () => {
  const { store, vault } = await rig();
  const desk = new CardDesk(store, site, { recorder: new FakeRecorder().send, vault: vault as never });
  const { card } = await desk.requestCard({ entries: two }, "agent", T0, signedSrc);
  const page = await (await route(new Request(`https://desk.example/approve/card/${card.id}`), store, { caller: "owner" }, card.expires_at + 1, vault as never)).text();
  assert.match(page, /expired before it was approved, so nothing ran/);
  assert.doesNotMatch(page, /id="go"|id="stop"/);
});

// ---- Stop at the first non-done ----
test("entry 1 fails: entry 2 never starts (not_run); entry 1's result is failed, entry 2 has no approval and no result", async () => {
  const { desk, fr, vb } = await rig({ runEntry: async () => ({ ok: false, error: "cloudflare_answered_500" }) });
  const { card, grants } = await desk.requestCard({ entries: [{ job: "cf.zone.read", params: ZONE, reason: "a" }, { job: "cf.dns.list", params: ZONE, reason: "b" }] }, "agent", T0, signedSrc);
  const r = await tap(desk, card.id);
  assert.deepEqual(r.entries.map((e) => e.state), ["failed", "not_run"]);
  assert.equal(r.stopped, "entry 1 failed");
  assert.deepEqual(fr.stages(grants[0].id), ["request", "verdict", "approval", "result"]);
  assert.equal(fr.records.find((x) => x.grant === grants[0].id && x.stage === "result")!.record.outcome, "failed");
  assert.deepEqual(fr.stages(grants[1].id), ["request", "verdict"], "entry 2 was never approved, so it gets no result");
  assert.equal(vb.calls.length, 0, "the default runEntry was replaced");
  assert.deepEqual(cardView(200, { report: r }).head, "Stopped");
});

test("entry 2's approval not recorded: entry 2 does not start and the card is stopped in the vault", async () => {
  const { desk, fr, vb } = await rig();
  const { card, grants } = await desk.requestCard({ entries: two }, "agent", T0, signedSrc);
  fr.failIf = (r) => r.stage === "approval" && r.grant === grants[1].id;
  const r = await tap(desk, card.id);
  assert.deepEqual(r.entries.map((e) => e.state), ["done", "not_run"]);
  assert.equal(vb.calls.length, 0);
  assert.equal((await vb.book.status(card.id)).stopped, "stopped by Ben", "the desk's stop closed the rest");
});

test("an unsigned receipt (older recorder): the vault would refuse it, so the desk does not start the entry", async () => {
  const { desk, vb, calls } = await rig({ signedReceipts: false });
  const { card } = await desk.requestCard({ entries: two }, "agent", T0, signedSrc);
  const r = await tap(desk, card.id);
  assert.deepEqual(r.entries.map((e) => e.state), ["not_run", "not_run"]);
  assert.ok(!calls.includes("cardRun"));
  assert.equal(vb.calls.length, 0);
});

test("the vault refuses to open (off switch): this tap started nothing, the card and its grants are stopped", async () => {
  const { desk, fr } = await rig({ jobs: [] });
  const { card, grants } = await desk.requestCard({ entries: two }, "agent", T0, signedSrc);
  const r = await tap(desk, card.id);
  assert.equal(r.status, "stopped");
  assert.match(r.stopped!, /^not opened: cards_off$/);
  assert.deepEqual(r.entries.map((e) => e.state), ["not_run", "not_run"]);
  for (const g of grants) assert.deepEqual(fr.stages(g.id), ["request", "verdict"]);
  for (const g of grants) assert.equal((await desk.grant(g.id)).status, "stopped");
});

test("cardOpen fails and the status read fails too, not with unknown_card: said as unclear, never as 'not opened' (6.1)", async () => {
  const { desk, vault, calls } = await rig({ jobs: [] });
  vault.cardStatus = async () => {
    throw new Error("network connection lost");
  };
  const { card } = await desk.requestCard({ entries: two }, "agent", T0, signedSrc);
  const r = await desk.approveCard(card.id, { ...(await TEST_KEY.assert((await desk.cardOptions(card.id, T0)).challenge, site.rpID, site.origin)), prf: PRF } as never, T0);
  assert.match(r.stopped!, /^unclear whether opened; nothing started: cards_off$/);
  assert.ok(!calls.includes("cardRun"));
});

test("the vault opened the card but its reply was lost: the desk reads the book and runs the card (U5 class 3)", async () => {
  const { desk, fail } = await rig();
  const { card } = await desk.requestCard({ entries: two }, "agent", T0, signedSrc);
  fail.cardOpen = 1;
  const r = await tap(desk, card.id);
  assert.deepEqual(r.entries.map((e) => e.state), ["done", "done"]);
});

// ---- U4 + V2: a lost reply after the vault settled; a lost status reply ----
test("cardRun's reply is lost after a done settle: the next read stores the answer, acks it, and records the result once (U4)", async () => {
  const { desk, fr, fail, vb } = await rig();
  const { card, grants } = await desk.requestCard({ entries: [two[1]] }, "agent", T0, signedSrc);
  fail.cardRun = 1;
  fail.cardStatus = 1; // ... and the finish right after the tap also loses its read: nothing stored, nothing acked
  const r = await tap(desk, card.id);
  assert.equal(r.entries[0].answer, undefined);
  assert.notEqual((await vb.book.status(card.id)).answers[0], undefined, "the vault still holds the answer (V2)");
  assert.deepEqual(fr.stages(grants[0].id), ["request", "verdict", "approval"]);
  const got = await desk.collectCard(card.id, "agent", T0 + 1000, signedSrc);
  assert.equal(got.entries[0].state, "done");
  assert.deepEqual(got.entries[0].answer, { ok: true, job: "cf.zone.read", data: { read: "benculbert.com" } });
  assert.deepEqual(fr.stages(grants[0].id), ["request", "verdict", "approval", "result"]);
  assert.equal((await vb.book.status(card.id)).answers[0], undefined, "acked after the desk stored it");
  await desk.collectCard(card.id, "agent", T0 + 2000, signedSrc);
  assert.equal(fr.records.filter((x) => x.grant === grants[0].id && x.stage === "result").length, 1, "recorded once");
});

// ---- V1: frozen result bytes ----
test("the recorder commits a result but the reply is lost: the next read resends identical bytes and gets the same receipt (V1)", async () => {
  const { desk, fr } = await rig();
  const { card, grants } = await desk.requestCard({ entries: [two[0]] }, "agent", T0, signedSrc);
  fr.loseAnswer.add("result");
  await tap(desk, card.id);
  const g1 = await desk.grant(grants[0].id);
  assert.equal(g1.recorded!.result, undefined);
  assert.ok(g1.result_body, "frozen before the first send");
  await desk.collectCard(card.id, "agent", T0 + 60_000, signedSrc); // a minute later: the bytes must not move
  const results = fr.sent.filter((b) => JSON.parse(b).stage === "result" && JSON.parse(b).grant === grants[0].id);
  assert.equal(results.length, 2);
  assert.equal(results[0], results[1]);
  assert.equal(JSON.parse(results[0]).at, T0, "the vault's settle time, not the caller's clock");
  const g2 = await desk.grant(grants[0].id);
  assert.equal(g2.receipts!.result!.sha256, (await desk.grant(grants[0].id)).receipts!.result!.sha256);
  assert.equal(fr.records.filter((x) => x.grant === grants[0].id && x.stage === "result").length, 1);
});

// ---- W1: an overdue dispatching entry; two concurrent finishes ----
test("overdue dispatching entry, lost recorder reply, two concurrent reads: every send carries identical bytes with at = deadline (W1)", async () => {
  let release!: () => void;
  const hang = new Promise<void>((r) => (release = r));
  const { desk, fr, vb } = await rig({ runEntry: async () => (await hang, { ok: true }) });
  const { card, grants } = await desk.requestCard({ entries: [{ job: "cf.zone.read", params: ZONE, reason: "a" }] }, "agent", T0, signedSrc);
  const running = tap(desk, card.id); // the tap's invocation stays inside the job (Safari closed, say)
  await until(async () => (await stateOf(vb, card.id)) === "dispatching");
  assert.equal((await vb.book.status(card.id)).entries[0].state, "dispatching", "checkpoint: the entry is out");
  const late = card.manifest.deadline + 1;
  fr.loseAnswer.add("result");
  await Promise.all([desk.collectCard(card.id, "agent", late, signedSrc), desk.collectCard(card.id, "agent", late, signedSrc)]);
  await desk.collectCard(card.id, "agent", late + 5, signedSrc);
  const results = fr.sent.filter((b) => JSON.parse(b).stage === "result");
  assert.ok(results.length >= 2);
  assert.ok(results.every((b) => b === results[0]), "identical bytes on every send");
  assert.deepEqual([JSON.parse(results[0]).outcome, JSON.parse(results[0]).at], ["unknown", card.manifest.deadline]);
  assert.equal(fr.records.filter((x) => x.grant === grants[0].id && x.stage === "result").length, 1);
  release();
  await running;
});

// ---- V3: the collect window ----
test("past the collect window: answers are neither stored nor returned, and the vault is not told to drop its copy (V3)", async () => {
  const { desk, vb, fail, calls } = await rig();
  const { card, grants } = await desk.requestCard({ entries: [two[0]] }, "agent", T0, signedSrc);
  fail.cardStatus = 1; // the read right after the tap is lost: the desk stores nothing, the vault keeps the answer
  await tap(desk, card.id);
  assert.equal((await desk.grant(grants[0].id)).result, undefined);
  const late = T0 + COLLECT_WINDOW_MS + 1; // the vault's own clock stays at T0, so it still shows the answer
  assert.notEqual(vb.book.status(card.id).answers[0], undefined);
  calls.length = 0;
  const got = await desk.collectCard(card.id, "agent", late, signedSrc);
  assert.equal(got.entries[0].answer, undefined);
  assert.equal(got.entries[0].answer_erased, true, "said plainly: no longer held");
  assert.equal((await desk.grant(grants[0].id)).result, undefined);
  assert.ok(!calls.includes("cardAck"), "the desk never stored it, so it never acks");
  assert.equal((await desk.grant(grants[0].id)).answer_erased, undefined, "nothing was restored and erased");
});

test("past the collect window: the desk's stored answer is erased and never restored (V3)", async () => {
  const { desk, vault } = await rig();
  vault.cardAck = async () => false; // the vault keeps its copy
  const { card, grants } = await desk.requestCard({ entries: [two[0]] }, "agent", T0, signedSrc);
  await tap(desk, card.id);
  assert.ok((await desk.grant(grants[0].id)).result !== undefined);
  const late = T0 + COLLECT_WINDOW_MS + 1;
  await desk.collectCard(card.id, "agent", late, signedSrc);
  assert.equal((await desk.grant(grants[0].id)).result, undefined);
  assert.equal((await desk.grant(grants[0].id)).answer_erased, true);
  const again = await desk.collectCard(card.id, "agent", late + 1, signedSrc);
  assert.equal(again.entries[0].answer, undefined);
  assert.equal((await desk.grant(grants[0].id)).result, undefined);
});

// ---- T15 / T5: Stop ----
test("Stop before the tap: nothing can be approved; Stop during entry 1: it runs to its answer, entry 2 never starts (T5)", async () => {
  const { desk } = await rig();
  const a = await desk.requestCard({ entries: two }, "agent", T0, signedSrc);
  const s = await desk.stopCard(a.card.id, T0);
  assert.equal(s.status, "stopped");
  await refuses(desk.cardOptions(a.card.id, T0), "not_pending");

  let release!: () => void;
  const hang = new Promise<void>((r) => (release = r));
  const r2 = await rig({ runEntry: async () => (await hang, { ok: true, data: {} }) });
  const b = await r2.desk.requestCard({ entries: [{ job: "cf.zone.read", params: ZONE, reason: "a" }, { job: "cf.dns.list", params: ZONE, reason: "b" }] }, "agent", T0, signedSrc);
  const running = tap(r2.desk, b.card.id);
  await until(async () => (await stateOf(r2.vb, b.card.id)) === "dispatching");
  assert.equal((await r2.vb.book.status(b.card.id)).entries[0].state, "dispatching", "checkpoint: Stop lands while entry 1 is out");
  await r2.desk.stopCard(b.card.id, T0);
  release();
  const out = await running;
  assert.deepEqual(out.entries.map((e) => e.state), ["done", "not_run"]);
  assert.equal(out.stopped, "stopped by Ben");
});

// ---- Routes and page ----
test("routes: POST /card answers card_refused with the code; Ben's page lists every job; Stop needs the page's origin", async () => {
  const { store, vault } = await rig();
  const hooks = (path: string, init: RequestInit, who: "agent" | "owner") => route(new Request(`https://desk.example${path}`, init), store, who === "agent" ? { caller: "agent", requester: "agent" } : { caller: "owner" }, T0, vault as never, async () => {}, new FakeRecorder().send);
  const bad = await hooks("/card", { method: "POST", body: JSON.stringify({ entries: [...two, two[0]] }) }, "agent");
  // Unsigned at the route: the signature check runs first.
  assert.deepEqual(await bad.json(), { error: "card_refused: no_cbox_key" });
  const asOwner = await hooks("/card", { method: "POST", body: "{}" }, "owner");
  assert.equal(asOwner.status, 403, "Ben's login cannot ask for a card");
  const notMine = await hooks("/approve/card/x", { method: "GET" }, "agent");
  assert.equal(notMine.status, 403, "the agent cannot open Ben's page");
  const desk = new CardDesk(store, site, { recorder: new FakeRecorder().send, vault: vault as never });
  const { card } = await desk.requestCard({ entries: two }, "agent", T0, signedSrc);
  const page = await (await hooks(`/approve/card/${card.id}`, { method: "GET" }, "owner")).text();
  assert.match(page, /Approve these 2 jobs\?/);
  assert.match(page, /echoes the word &quot;hello&quot;/);
  assert.match(page, /basic details of benculbert\.com/);
  assert.match(page, /stop at the first failure/);
  assert.match(page, /Stop works while this page is open/);
  const cross = await hooks(`/approve/card/${card.id}/stop`, { method: "POST", headers: { origin: "https://evil.example" } }, "owner");
  assert.equal(cross.status, 403);
  const ok = await hooks(`/approve/card/${card.id}/stop`, { method: "POST", headers: { origin: "https://desk.example" } }, "owner");
  assert.equal(((await ok.json()) as { report: { status: string } }).report.status, "stopped");
});

test("cardView: Done only when every job is done; unclear and refused words never claim success", () => {
  const rep = (...s: string[]) => ({ report: { entries: s.map((state, i) => ({ does: `job ${i}`, state })), stopped: "entry 1 failed" } });
  assert.equal(cardView(200, rep("done", "done")).head, "Done");
  assert.equal(cardView(200, rep("done", "unknown")).head, "Unclear");
  assert.equal(cardView(200, rep("failed", "not_run")).head, "Stopped");
  assert.equal(cardView(null, null).head, "Unclear");
  assert.equal(cardView(409, { error: "not_pending" }).head, "Not approved");
  assert.equal(cardView(200, { nope: 1 }).head, "Unclear");
  assert.deepEqual(cardView(200, rep("done", "not_run")).lines, ["1. job 0 -- Done", "2. job 1 -- Not run"]);
});

// ---- F9 (V5/W2): the tap invocation's subrequest count at the worst 2-entry workload ----
test("F9 count: Ben's tap at 2 entries makes at most 15 subrequests from the desk (recorder sends, each up to 2 tries, + vault calls)", async () => {
  const { desk, fr, calls } = await rig();
  const { card } = await desk.requestCard({ entries: [{ job: "cf.zone.read", params: ZONE, reason: "a" }, { job: "cf.dns.list", params: ZONE, reason: "b" }] }, "agent", T0, signedSrc);
  const sentBefore = fr.sent.length;
  calls.length = 0;
  await tap(desk, card.id);
  const recorderSends = fr.sent.length - sentBefore; // each send is one fetch, up to 2 with a retry (RECORD retry)
  const vaultCalls = calls.length; // each is one service-binding call
  const worst = recorderSends * 2 + vaultCalls;
  // Recorded on the card as the measured figure; asserted so a change that adds calls is seen.
  assert.deepEqual({ recorderSends, vaultCalls }, { recorderSends: 4, vaultCalls: 7 });
  assert.equal(worst, 15, "cardApi, cardOpen, 2 cardRun, cardStatus, 2 cardAck; 2 approvals + 2 results, each retried once at worst");
});
