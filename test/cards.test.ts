// The vault's card book (card 85818ab1; studio-os REFINE-85818ab1.md v2.2). Each safeguard is shown working, then
// refusing its unsafe case (instruction.control-must-refuse-unsafe-case); mutants that remove a check are in
// test/cards-mutants.test.ts. Real-runtime proofs (transactions, alarm, restart): test/cards.workerd.test.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ANSWER_HOLD_MS, BOOK_KEEP_MS, CARD_CAP, CARD_JOBS, CardBook, JOBS_VERSION } from "../vault/src/cards.ts";
import { VaultLogic } from "../vault/src/vault.ts";
import { approvalBody, cardBook, makeCard, openReq, PRF, runReq, TestRecorder } from "./cardsign.ts";
import { SoftKey } from "./softkey.ts";
import { TEST_PIN, signed } from "./vaultsign.ts";

const T = 1_800_000_000_000;
const ZONE = { zone: "benculbert.com" };
const two = (): [string, Record<string, string>][] => [["cf.zone.read", ZONE], ["cf.dns.list", ZONE]];
const refused = (code: string) => new RegExp(`^Error: ${code}$`);

// ---- Outcome 1/3/4: the happy path ----
test("one tap runs both entries in order; answers held; the card closes when the last is done", async () => {
  const { book, rec, calls, store } = await cardBook();
  const c = await makeCard(T, two());
  const v = await book.open(openReq(c));
  assert.deepEqual(v.entries.map((e) => e.state), ["waiting", "waiting"]);
  assert.equal((await book.run(await runReq(c, 0, rec))).state, "done");
  const last = await book.run(await runReq(c, 1, rec));
  assert.equal(last.state, "done");
  assert.deepEqual(calls, ["cf.zone.read", "cf.dns.list"]);
  assert.equal(last.card.closed_at, T);
  assert.equal(last.card.stopped, undefined);
  assert.deepEqual(Object.keys(last.card.answers), ["0", "1"]);
  assert.ok(!store.dump().includes(PRF), "the passkey secret is never stored (T14)");
});

test("test.echo on a card answers the word and touches nothing", async () => {
  const { book, rec, calls } = await cardBook();
  const c = await makeCard(T, [["test.echo", { word: "hello" }]]);
  await book.open(openReq(c));
  const r = await book.run(await runReq(c, 0, rec));
  assert.equal(r.state, "done");
  assert.deepEqual(r.card.answers[0], { ok: true, data: { echoed: "hello" } });
  assert.deepEqual(calls, []);
});

// ---- Outcome 2: cardOpen checks (a)-(g); each refusal leaves storage unchanged ----
type Book = Awaited<ReturnType<typeof cardBook>>;
async function openRefused(code: string, make: (b: Book) => Promise<unknown>, setup: (b: Book) => void = () => {}) {
  const b = await cardBook();
  setup(b);
  const before = b.store.dump();
  await assert.rejects(make(b) as Promise<unknown>, refused(code));
  assert.equal(b.store.dump(), before, `${code}: nothing written`);
}

test("open: wrong shape, extra argument, no pin", async () => {
  const c = await makeCard(T, two());
  await openRefused("wrong_shape", ({ book }) => book.open({ ...openReq(c), extra: 1 }));
  await openRefused("wrong_shape", ({ book }) => book.open(openReq(c), "old-arg"));
  await openRefused("wrong_shape", ({ book }) => book.open({ ...openReq(c), key_rev: -1 }));
  await openRefused("no_pin", ({ store, rec }) => new CardBook(store, async () => ({}), undefined, { recorderKey: rec.pub }).open(openReq(c)));
});

test("open (a)(b): a changed param, swapped order, an extra or missing grant, a duplicate grant id -> bad_card (T1, U1)", async () => {
  const c = await makeCard(T, two());
  const changed = { ...openReq(c), grants: [{ ...c.grants[0], params: { zone: "other.com" } }, c.grants[1]] };
  await openRefused("bad_card", ({ book }) => book.open(changed));
  await openRefused("bad_card", ({ book }) => book.open({ ...openReq(c), grants: [c.grants[1], c.grants[0]] }));
  await openRefused("bad_card", ({ book }) => book.open({ ...openReq(c), grants: [c.grants[0]] }));
  await openRefused("bad_card", ({ book }) => book.open({ ...openReq(c), manifest: { ...c.manifest, entries: ["0".repeat(64)] } }));
  // Grants hash correctly, but the manifest names another requester than the grants carry.
  await openRefused("bad_card", ({ book }) => book.open({ ...openReq(c), manifest: { ...c.manifest, requester: "someone" } }));
  // Two entries with one id: the manifest's hashes differ (params differ), but the id repeats.
  const dup = await makeCard(T, two());
  dup.grants[1] = { ...dup.grants[1], id: dup.grants[0].id };
  const { grantHash } = await import("../src/desk.ts");
  dup.manifest.entries[1] = await grantHash(dup.grants[1] as never);
  await openRefused("bad_card", ({ book }) => book.open(openReq(dup)));
});

test("open (c)(d): a tap over another hash, another passkey, or a grant hash -> bad_assertion", async () => {
  const c = await makeCard(T, two());
  await openRefused("bad_assertion", async ({ book }) => book.open(openReq(await makeCard(T, two(), { signHash: "ab".repeat(32) }))));
  await openRefused("bad_assertion", async ({ book }) => book.open(openReq(await makeCard(T, two(), { key: await SoftKey.create() }))));
  // Ben's tap for entry 1 alone (its grant hash) never opens the card that holds it.
  await openRefused("bad_assertion", async ({ book }) => book.open(openReq(await makeCard(T, two(), { signHash: c.hashes[0] }))));
  // The tap is checked against the manifest the vault recomputes: a card signed for another manifest fails.
  const other = await makeCard(T, two());
  await openRefused("bad_assertion", ({ book }) => book.open({ ...openReq(c), assertion: other.assertion }));
});

test("open (e): ineligible job, jobs version, cap, deadline past expiry + 15 min", async () => {
  await openRefused("job_not_on_cards", async ({ book }) => book.open(openReq(await makeCard(T, [["cbox.key.enroll", { key: "k" }]]))));
  // T16 (card 77ec1e64): JOBS_VERSION is 2 now that gh.repo.create is on cards; a card made under version 1 is refused.
  assert.equal(JOBS_VERSION, 2);
  await openRefused("version_changed", async ({ book }) => book.open(openReq(await makeCard(T, two(), { jobsVersion: 1 }))));
  const three = await makeCard(T, [...two(), ["test.echo", { word: "a" }]]);
  await openRefused("too_many_entries", ({ book }) => book.open(openReq(three)));
  assert.equal(CARD_CAP, 2);
  await openRefused("bad_card", async ({ book }) => book.open(openReq(await makeCard(T, two(), { deadline: T + 25 * 60_000 + 1 }))));
});

test("open (f)(g): card seen, grant used standalone, grant on another card, deadline passed, tap after the approve window", async () => {
  const c = await makeCard(T, two());
  await openRefused("grant_used", ({ book }) => book.open(openReq(c)), ({ store }) => store.data.set("used", new Map([[c.grants[1].id, c.grants[1].expires_at]])));
  await openRefused("grant_on_card", ({ book }) => book.open(openReq(c)), ({ store }) => store.data.set(`cardgrant:${c.grants[0].id}`, "other"));
  await openRefused("deadline_passed", async ({ book, clock }) => ((clock.now = c.manifest.deadline + 1), book.open(openReq(c))));
  await openRefused("too_late", async ({ book, clock }) => ((clock.now = c.grants[0].expires_at + 1), book.open(openReq(c))));
});

test("open replay (U5): the same tap returns the open book; another tap for that card id is card_seen", async () => {
  const { book, rec } = await cardBook();
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  await book.run(await runReq(c, 0, rec));
  const again = await book.open(openReq(c));
  assert.deepEqual(again.entries.map((e) => e.state), ["done", "waiting"], "after a claim: current states, nothing reset");
  const retap = await makeCard(T, two(), { card: c.manifest.card });
  await assert.rejects(book.open(openReq({ ...c, assertion: retap.assertion })), refused("bad_assertion"));
  // Same manifest, same card hash, another valid tap over it: card_seen, not a second book.
  const { b64url } = await import("../src/desk.ts");
  const { TEST_KEY, TEST_RP, TEST_ORIGIN } = await import("./vaultsign.ts");
  const ch = b64url(new Uint8Array([...crypto.getRandomValues(new Uint8Array(16)), ...c.cardHash.match(/../g)!.map((h) => parseInt(h, 16))]));
  const r2 = await TEST_KEY.assert(ch, TEST_RP, TEST_ORIGIN, { userVerified: true });
  const tap2 = { passkey_id: r2.id, authenticator_data: r2.response.authenticatorData, client_data_json: r2.response.clientDataJSON, signature: r2.response.signature };
  await assert.rejects(book.open({ ...openReq(c), assertion: tap2 }), refused("card_seen"));
});

// ---- Outcome 3: cardRun's receipt and approval checks (T2) ----
async function runRefused(code: string, req: (c: Awaited<ReturnType<typeof makeCard>>, rec: TestRecorder) => Promise<unknown>) {
  const { book, rec, calls, store } = await cardBook();
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  const before = store.dump();
  await assert.rejects(book.run(await req(c, rec)), refused(code));
  assert.equal(store.dump(), before, `${code}: the entry did not move`);
  assert.deepEqual(calls, []);
}

test("run: fabricated, wrong-key, other-grant, other-stage, tampered receipts -> bad_receipt", async () => {
  await runRefused("bad_receipt", async (c, rec) => ({ ...(await runReq(c, 0, rec)), receipt: { ...(await runReq(c, 0, rec)).receipt, sig: Buffer.alloc(64).toString("base64") } }));
  await runRefused("bad_receipt", async (c) => runReq(c, 0, await TestRecorder.create()));
  await runRefused("bad_receipt", async (c, rec) => runReq(c, 0, rec, { receipt: await rec.receipt(c.grants[1].id, "approval", approvalBody(c, 0)) }));
  await runRefused("bad_receipt", async (c, rec) => runReq(c, 0, rec, { receipt: await rec.receipt(c.grants[0].id, "request", approvalBody(c, 0)) }));
  await runRefused("bad_receipt", async (c, rec) => {
    const r = await runReq(c, 0, rec);
    return { ...r, receipt: { ...r.receipt, seq: r.receipt.seq + 1 } }; // a field changed after signing
  });
  await runRefused("bad_receipt", async (c, rec) => ({ ...(await runReq(c, 0, rec)), approval_body: approvalBody(c, 0, { approved_at: 2 }) })); // body != receipt sha
  await runRefused("bad_receipt", async (c, rec) => runReq(c, 0, rec, { receipt: { ...(await rec.receipt(c.grants[0].id, "approval", approvalBody(c, 0))), sig: undefined } as never }));
});

test("run: a receipted body that is not this card's card/v1 approval of this entry -> bad_approval (U1)", async () => {
  const other = await makeCard(T, two());
  await runRefused("bad_approval", (c, rec) => runReq(c, 0, rec, { body: approvalBody(c, 0, { manifest: other.manifest }) }));
  await runRefused("bad_approval", (c, rec) => runReq(c, 0, rec, { body: approvalBody(c, 0, { approval_kind: undefined }) }));
  await runRefused("bad_approval", (c, rec) => runReq(c, 0, rec, { body: approvalBody(c, 0, { grant_hash: c.hashes[1] }) }));
  await runRefused("bad_approval", (c, rec) => runReq(c, 0, rec, { body: approvalBody(c, 0, { stage: "result" }) }));
  await runRefused("bad_approval", (c, rec) => runReq(c, 0, rec, { body: "not json" }));
  // Entry 2 presented with entry 1's receipt and body.
  await runRefused("bad_receipt", async (c, rec) => ({ ...(await runReq(c, 0, rec)), index: 1 }));
});

test("run: shape -- an extra params key, a bad passkey secret, an old-shape call, an unknown card or index", async () => {
  await runRefused("wrong_shape", async (c, rec) => ({ ...(await runReq(c, 0, rec)), params: { zone: "x" } }));
  await runRefused("wrong_shape", async (c, rec) => runReq(c, 0, rec, { prf: "short" }));
  await runRefused("unknown_card", async (c, rec) => ({ ...(await runReq(c, 0, rec)), card: "c-nope-xxxx" }));
  await runRefused("bad_index", async (c, rec) => ({ ...(await runReq(c, 0, rec)), index: 2 }));
  const { book, rec } = await cardBook();
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  await assert.rejects(book.run(await runReq(c, 0, rec), "extra"), refused("wrong_shape"));
});

// ---- Outcome 3/4: the claim (T3, T4, T9, T10, U2) ----
test("T3: a valid signed receipt does not start an entry past the deadline (carried T2 from 586da182)", async () => {
  const { book, rec, clock, calls } = await cardBook();
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  const req = await runReq(c, 0, rec);
  clock.now = c.manifest.deadline + 1;
  await assert.rejects(book.run(req), refused("deadline_passed"));
  clock.now = c.manifest.deadline;
  assert.equal((await book.run(req)).state, "done", "at the deadline itself it may still start");
  assert.deepEqual(calls, ["cf.zone.read"]);
});

test("T4: entry 2 before entry 1 is out_of_order; entry 1 twice runs once; nothing after a failure or Stop", async () => {
  const { book, rec, calls } = await cardBook();
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  await assert.rejects(book.run(await runReq(c, 1, rec)), refused("out_of_order"));
  await book.run(await runReq(c, 0, rec));
  const twice = await book.run(await runReq(c, 0, rec));
  assert.equal(twice.state, "done");
  assert.deepEqual(calls, ["cf.zone.read"], "the second claim ran nothing (U5 class 2)");

  let fail = true;
  const f = await cardBook({ runEntry: async () => (fail ? { ok: false, error: "read_failed" } : { ok: true }) });
  const c2 = await makeCard(T, two());
  await f.book.open(openReq(c2));
  const first = await f.book.run(await runReq(c2, 0, f.rec));
  assert.equal(first.state, "failed");
  assert.equal(first.card.stopped, "entry 1 failed");
  assert.deepEqual(first.card.entries.map((e) => e.state), ["failed", "not_run"]);
  fail = false;
  assert.equal((await f.book.run(await runReq(c2, 1, f.rec))).state, "not_run", "a not_run entry is never claimed");

  const s = await cardBook();
  const c3 = await makeCard(T, two());
  await s.book.open(openReq(c3));
  await s.book.stop(c3.manifest.card);
  assert.equal((await s.book.run(await runReq(c3, 0, s.rec))).state, "not_run");
  assert.deepEqual(s.calls, []);
});

test("T4: a stopped card whose entry is still waiting refuses card_stopped; settled states never move back", async () => {
  const { book, rec, store } = await cardBook();
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  // Stopped by some path that left entry 1 waiting (e.g. older code): the claim still refuses.
  const b = store.kv.get<{ stopped?: string }>(`card:${c.manifest.card}`)!;
  store.kv.put(`card:${c.manifest.card}`, { ...b, stopped: "x" });
  await assert.rejects(book.run(await runReq(c, 0, rec)), refused("card_stopped"));
});

test("U2: emptying the vault's card list stops an already-open card (cards_off); the alarm still closes it", async () => {
  const { store, rec, clock } = await cardBook();
  const c = await makeCard(T, two());
  const on = new CardBook(store, async () => ({ ok: true }), TEST_PIN, { now: () => clock.now, recorderKey: rec.pub });
  await on.open(openReq(c));
  const off = new CardBook(store, async () => ({ ok: true }), TEST_PIN, { now: () => clock.now, recorderKey: rec.pub, jobs: [] });
  await assert.rejects(off.run(await runReq(c, 0, rec)), refused("cards_off"));
  await assert.rejects(off.open(openReq(await makeCard(T, two()))), refused("cards_off"), "Outcome 8: no new card opens");
  clock.now = c.manifest.deadline + 1;
  await off.alarm();
  assert.deepEqual(off.status(c.manifest.card).entries.map((e) => e.state), ["not_run", "not_run"]);
});

test("T9/T10: a jobs-version change or a c-box key change between entries refuses the next claim", async () => {
  const { store, rec, clock, book } = await cardBook();
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  await book.run(await runReq(c, 0, rec));
  const v2 = new CardBook(store, async () => ({ ok: true }), TEST_PIN, { now: () => clock.now, recorderKey: rec.pub, jobsVersion: JOBS_VERSION + 1 });
  await assert.rejects(v2.run(await runReq(c, 1, rec)), refused("version_changed"));
  await assert.rejects(book.run(await runReq(c, 1, rec, { key_rev: 2 })), refused("key_changed"), "the desk's key generation moved");
  store.kv.put("cbox_rev", 2);
  await assert.rejects(book.run(await runReq(c, 1, rec)), refused("key_changed"), "the vault's own record moved (setKeyRev)");
});

test("T16: the vault judges the deadline on its own clock, not the desk's", async () => {
  const { book, rec, clock } = await cardBook();
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  clock.now = c.manifest.deadline + 60_000; // the desk may think it is earlier; the vault does not ask
  await assert.rejects(book.run(await runReq(c, 0, rec)), refused("deadline_passed"));
});

// ---- Outcome 4: settle outcomes ----
test("a job that throws a vault refusal is failed; anything else unreadable is unknown; both stop the card", async () => {
  const { VaultError } = await import("../vault/src/seal.ts");
  for (const [thrown, want] of [[new VaultError("no_master_key"), "failed"], [new TypeError("boom"), "unknown"], [undefined, "unknown"]] as const) {
    const { book, rec } = await cardBook({ runEntry: async () => { if (thrown) throw thrown; return { maybe: 1 }; } });
    const c = await makeCard(T, two());
    await book.open(openReq(c));
    const r = await book.run(await runReq(c, 0, rec));
    assert.equal(r.state, want);
    assert.equal(r.card.stopped, `entry 1 ${want}`);
    assert.deepEqual(r.card.entries.map((e) => e.state), [want, "not_run"]);
    assert.ok(r.card.closed_at);
  }
});

// ---- T5: Stop while a claim is out ----
test("T5: Stop during entry 1's call -- entry 1 runs to its answer, entry 2 never starts, the card closes at the settle", async () => {
  let release!: () => void;
  let reached!: () => void;
  const inCall = new Promise<void>((r) => (reached = r));
  const { book, rec } = await cardBook({ runEntry: async () => (reached(), await new Promise<void>((r) => (release = r)), { ok: true }) });
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  const running = book.run(await runReq(c, 0, rec));
  await inCall; // checkpoint: the claim committed and the job is out
  const stopped = await book.stop(c.manifest.card);
  assert.deepEqual(stopped.entries.map((e) => e.state), ["dispatching", "not_run"]);
  assert.equal(stopped.closed_at, undefined, "not closed while an entry is out");
  release();
  const r = await running;
  assert.equal(r.state, "done");
  assert.equal(r.card.closed_at, T, "closed by the settle (fix: a done entry after Stop closes the card)");
  assert.equal(r.card.stopped, "stopped by Ben");
  await assert.rejects(book.run(await runReq(c, 1, rec)).then((x) => (x.state === "not_run" ? Promise.reject(new Error("card_stopped")) : x)), /card_stopped/);
});

test("Stop first: no entry starts; Stop again returns the same book", async () => {
  const { book, rec, calls } = await cardBook();
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  const a = await book.stop(c.manifest.card);
  const b = await book.stop(c.manifest.card);
  assert.deepEqual(a, b);
  assert.equal((await book.run(await runReq(c, 0, rec))).state, "not_run");
  assert.deepEqual(calls, []);
});

// ---- Outcome 5 / V3: the alarm ----
test("T6: an entry left dispatching (the desk never settles) is closed unknown by the alarm alone; a late settle is kept as late", async () => {
  let release!: () => void;
  let reached!: () => void;
  const inCall = new Promise<void>((r) => (reached = r));
  const { book, rec, clock, store } = await cardBook({ runEntry: async () => (reached(), await new Promise<void>((r) => (release = r)), { ok: true }) });
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  assert.equal(store.alarmAt, c.manifest.deadline + 1, "armed at open");
  const running = book.run(await runReq(c, 0, rec));
  await inCall;
  clock.now = c.manifest.deadline + 1;
  await book.alarm();
  const v = book.status(c.manifest.card);
  assert.deepEqual(v.entries.map((e) => e.state), ["unknown", "not_run"]);
  assert.equal(v.stopped, "deadline passed");
  assert.equal(v.closed_at, c.manifest.deadline + 1);
  release();
  const late = await running;
  assert.equal(late.state, "unknown");
  assert.equal(late.card.entries[0].late, "done");
  assert.equal(late.card.closed_at, c.manifest.deadline + 1, "closed_at is written once");
});

test("T7: two overlapping cards -- the later never postpones the earlier's close; the handler run twice changes nothing more", async () => {
  const { book, clock, store } = await cardBook();
  const early = await makeCard(T, two(), { deadline: T + 20 * 60_000 });
  const late = await makeCard(T, two(), { deadline: T + 25 * 60_000 });
  await book.open(openReq(early));
  await book.open(openReq(late));
  assert.equal(store.alarmAt, early.manifest.deadline + 1);
  clock.now = early.manifest.deadline + 1;
  await book.alarm();
  assert.ok(book.status(early.manifest.card).closed_at);
  assert.equal(book.status(late.manifest.card).closed_at, undefined);
  assert.equal(store.alarmAt, late.manifest.deadline + 1, "re-armed for the next card");
  const once = store.dump();
  await book.alarm();
  assert.equal(store.dump(), once, "idempotent");
});

test("V3: a completed, uncollected card loses its answers at closed_at + 5 min and its book at deadline + 7 days, with no request", async () => {
  const { book, rec, clock, store } = await cardBook();
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  await book.run(await runReq(c, 0, rec));
  await book.run(await runReq(c, 1, rec));
  assert.equal(store.alarmAt, T + ANSWER_HOLD_MS + 1, "the alarm wakes for the answers' expiry");
  clock.now = T + ANSWER_HOLD_MS;
  assert.equal(Object.keys(book.status(c.manifest.card).answers).length, 2);
  clock.now = store.alarmAt!;
  await book.alarm();
  assert.equal(store.kv.list({ prefix: "cardans:" }).length, 0);
  const v = book.status(c.manifest.card);
  assert.equal(v.held, false);
  assert.deepEqual(v.answers, {});
  assert.equal(store.alarmAt, c.manifest.deadline + BOOK_KEEP_MS + 1);
  clock.now = store.alarmAt!;
  await book.alarm();
  assert.throws(() => book.status(c.manifest.card), refused("unknown_card"));
  assert.equal(store.kv.list({ prefix: "cardgrant:" }).length, 0);
  assert.equal(store.alarmAt, null, "nothing left due");
  // T12: the same tap replayed after pruning is refused by its deadline.
  await assert.rejects(book.open(openReq(c)), refused("deadline_passed"));
});

test("V3: past the hold, status returns no answers even if one is still stored (alarm not yet run)", async () => {
  const { book, rec, clock } = await cardBook();
  const c = await makeCard(T, [["test.echo", { word: "hi" }]]);
  await book.open(openReq(c));
  await book.run(await runReq(c, 0, rec));
  clock.now = T + ANSWER_HOLD_MS + 1;
  assert.deepEqual(book.status(c.manifest.card).answers, {});
});

test("V2: ack deletes an answer only for a settled entry", async () => {
  const { book, rec, store } = await cardBook();
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  await book.run(await runReq(c, 0, rec));
  assert.equal(book.ack(c.manifest.card, 1), false, "entry 2 is not settled");
  assert.equal(book.ack(c.manifest.card, 0), true);
  assert.equal(store.kv.get(`cardans:${c.manifest.card}:0`), undefined);
  assert.equal(book.ack(c.manifest.card, 0), false, "a lost ack reply is harmless to repeat");
});

test("U7: a storage fault inside open's transaction leaves no card, only an early alarm that finds nothing due", async () => {
  const { book, store, clock } = await cardBook();
  const c = await makeCard(T, two());
  store.faultOn = "cards_due";
  await assert.rejects(book.open(openReq(c)), /injected storage fault/);
  assert.equal(store.kv.get(`card:${c.manifest.card}`), undefined);
  assert.equal(store.kv.get(`cardgrant:${c.grants[0].id}`), undefined, "rolled back together");
  assert.equal(store.alarmAt, c.manifest.deadline + 1, "armed before the commit");
  clock.now = store.alarmAt!;
  await book.alarm();
  assert.equal(store.alarmAt, null);
});

// ---- Outcome 6: neither route smuggles the other (T8) ----
test("T8: vault.run refuses a grant held by a card (card_grant), even with a valid tap for that grant", async () => {
  const { book, store } = await cardBook();
  const c = await makeCard(T, two());
  await book.open(openReq(c));
  const vault = new VaultLogic(store, async () => Response.json({ success: false }), () => T, TEST_PIN);
  const g = c.grants[0];
  const req = await signed(g.job, g.params, PRF, { id: g.id, expires_at: g.expires_at, requester: g.requester });
  await assert.rejects(vault.run(req), refused("card_grant"));
  assert.equal(store.kv.get("used"), undefined, "refused before admission: not recorded as used");
});

test("T8: a card tap never passes vault.run (it signs the card hash, not a grant hash)", async () => {
  const { store } = await cardBook();
  const c = await makeCard(T, two());
  const vault = new VaultLogic(store, async () => Response.json({ success: false }), () => T, TEST_PIN);
  await assert.rejects(vault.run({ grant: c.grants[0], assertion: c.assertion, prf: PRF }), refused("bad_assertion"));
});

test("the vault's card list matches the recorder's copied list", async () => {
  const { CARD_ELIGIBLE } = await import("../vault/src/cardcopy.ts");
  assert.deepEqual([...CARD_JOBS], [...CARD_ELIGIBLE]);
});
