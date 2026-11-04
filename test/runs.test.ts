// Runs, vault side (card ae6147e4 4a-2a). Each refusal and failure path asserts the exact words the agent
// and Ben get (REFINE-phase4a2.md E4, F2). The race, rollback and restart proofs run in the real runtime:
// test/runs.workerd.test.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { RUN_ELIGIBLE, RunBook, paramsHash, type OpRequest, type RunRecord, type RunStore } from "../vault/src/runs.ts";

const T0 = Date.UTC(2026, 10, 4, 12, 0, 0);
const ZONE_ID = "z".repeat(32);
const SECRET = "RUNKEY-PLANTED-VALUE-0123456789";
const ANSWER = "PLANTED-ANSWER-7f3a";

// Storage like a SQLite Durable Object's: values are copied in and out, and a throw inside a transaction
// rolls back every write in it. `fail` makes the next put to a key with that prefix throw.
function memStore() {
  const m = new Map<string, unknown>();
  const s = {
    fail: "" as string,
    map: m,
    kv: {
      get: <T>(k: string) => (m.has(k) ? (structuredClone(m.get(k)) as T) : undefined),
      put: <T>(k: string, v: T) => {
        if (s.fail && k.startsWith(s.fail)) {
          s.fail = "";
          throw new Error("storage fault");
        }
        m.set(k, structuredClone(v));
      },
      list: <T>(o?: { prefix?: string }) => [...m].filter(([k]) => k.startsWith(o?.prefix ?? "")).map(([k, v]) => [k, structuredClone(v)] as [string, T]),
    },
    transactionSync<T>(fn: () => T): T {
      const before = new Map(m);
      try {
        return fn();
      } catch (e) {
        m.clear();
        for (const [k, v] of before) m.set(k, v);
        throw e;
      }
    },
  };
  return s satisfies RunStore;
}

function seed(store: ReturnType<typeof memStore>, over: Partial<RunRecord> = {}, key = true) {
  const run: RunRecord = {
    id: "R1", generation: 1, state: "open", cards: ["card-a"], jobs: ["cf.zone.read", "cf.dns.list", "cf.audit.read"],
    account: "acct-frozen", zones: [{ name: "benculbert.com", id: ZONE_ID }], template: 1, deadline: T0 + 4 * 3600_000,
    budget: { max: 50, used: 0 }, key_rev: 3, opened_by: "g1", ...(key ? { run_key_id: "rk1" } : {}), ...over,
  };
  store.map.set("run:R1", run);
  store.map.set("cbox_rev", 3);
  if (key) store.map.set("runkey:R1", { id: "rk1", value: SECRET });
}

// Cloudflare stand-in: records each call; `hold` lets a test act while the call is out.
function fakeCf(opts: { status?: number; throws?: boolean; hold?: () => void } = {}) {
  const calls: { url: string; auth: string }[] = [];
  const fetchFn = async (input: string, init?: RequestInit) => {
    calls.push({ url: input, auth: String((init?.headers as Record<string, string>).authorization) });
    opts.hold?.();
    if (opts.throws) throw new Error("network down");
    if (opts.status) return Response.json({ success: false, errors: [{ message: "nope" }] }, { status: opts.status });
    return Response.json({ success: true, result: { id: ZONE_ID, name: "benculbert.com", status: ANSWER } });
  };
  return { calls, fetchFn };
}

const req = (over: Partial<OpRequest> = {}): OpRequest => ({ run: "R1", generation: 1, key_rev: 3, card: "card-a", job: "cf.zone.read", op: "op-00000001", params: { zone: "benculbert.com" }, ...over });

function setup(over: Partial<RunRecord> = {}, cf = fakeCf(), key = true, now = T0) {
  const store = memStore();
  seed(store, over, key);
  const clock = { now };
  return { store, cf, clock, book: new RunBook(store, cf.fetchFn, () => clock.now) };
}

test("a good op: one call with the run's key on the frozen zone id, answer released, one unit spent", async () => {
  const { book, cf, store } = setup();
  const r = await book.op(req());
  assert.equal(r.outcome, "done");
  assert.equal(r.agent, "done");
  assert.equal(r.ben, "run_op: run R1 op op-00000001: cf.zone.read done");
  assert.equal(cf.calls.length, 1);
  assert.equal(cf.calls[0].auth, `Bearer ${SECRET}`);
  assert.match(cf.calls[0].url, new RegExp(`/zones/${ZONE_ID}$`));
  const s = book.status("R1");
  assert.equal(s.run.budget.used, 1);
  assert.deepEqual(s.ops.map((o) => o.state), ["released"]);
  assert.equal((store.map.get("intent:R1:op-00000001") as { state: string }).state, "released");
});

test("the intent holds the hash of exactly the params that were checked and dispatched", async () => {
  const { book, cf, store } = setup();
  const params = { zone: "benculbert.com" };
  await book.op(req({ params }));
  const intent = store.map.get("intent:R1:op-00000001") as { params_hash: string };
  assert.equal(intent.params_hash, await paramsHash({ zone: "benculbert.com" }));
  assert.notEqual(intent.params_hash, await paramsHash({ zone: "other.com" }));
  assert.match(cf.calls[0].url, new RegExp(`/zones/${ZONE_ID}$`), "dispatched the zone that was hashed");
  assert.equal(book.status("R1").ops[0].params_hash, intent.params_hash);
});

// [request override, run override, key present, agent text, Ben text]
const refusals: [string, Partial<OpRequest>, Partial<RunRecord>, boolean, string, string][] = [
  ["unknown run", { run: "R9" }, {}, true, "refused: unknown_run", "refused: run request for unknown run R9"],
  ["run has no key", {}, {}, false, "refused: no_run_key", "refused: run R1 has no key"],
  ["card not on list", { card: "card-z" }, {}, true, "refused: card_not_in_run", "refused: card card-z is not in run R1"],
  ["job not on frozen list", { job: "cf.dns.list" }, { jobs: ["cf.zone.read"] }, true, "refused: job_not_in_run", "refused: job cf.dns.list is not in run R1"],
  ["job frozen but not run-eligible", { job: "cf.dns.txt.probe" }, { jobs: ["cf.dns.txt.probe"] }, true, "refused: job_not_in_run", "refused: job cf.dns.txt.probe is not in run R1"],
  ["zone outside the run", { params: { zone: "other.com" } }, {}, true, "refused: params_outside_run (zone)", "refused: run R1: zone outside the run"],
  ["extra param", { params: { zone: "benculbert.com", account: "x" } }, {}, true, "refused: params_outside_run (account)", "refused: run R1: account outside the run"],
  ["audit window too long", { job: "cf.audit.read", params: { since: "2026-10-01T00:00:00Z", until: "2026-11-04T00:00:00Z" } }, {}, true, "refused: params_outside_run (since)", "refused: run R1: since outside the run"],
  ["malformed op id", { op: "x" }, {}, true, "refused: params_outside_run (op)", "refused: run R1: op outside the run"],
  ["budget spent", {}, { budget: { max: 50, used: 50 } }, true, "refused: budget_spent (50 of 50 used)", "refused: run R1 budget spent"],
  ["past deadline", {}, { deadline: T0 }, true, "refused: run_ended (deadline 2026-11-04T12:00:00Z)", "refused: run R1 ended at 2026-11-04T12:00:00Z"],
  ["stopped", {}, { state: "stopped" }, true, "refused: run_stopped", "refused: run R1 is stopped"],
  ["finished", {}, { state: "finished" }, true, "refused: run_finished", "refused: run R1 is finished"],
  ["old generation", { generation: 0 }, {}, true, "refused: run_changed", "refused: run R1 changed since this request"],
  ["key revision the desk saw differs", { key_rev: 4 }, {}, true, "refused: cbox_key_changed", "refused: run R1: c-box key changed since the run opened"],
];
for (const [name, r, run, key, agent, ben] of refusals) {
  test(`refused, nothing called, nothing spent: ${name}`, async () => {
    const { book, cf, store } = setup(run, fakeCf(), key);
    const out = await book.op(req(r));
    assert.deepEqual({ outcome: out.outcome, agent: out.agent, ben: out.ben }, { outcome: "refused", agent, ben });
    assert.equal(cf.calls.length, 0);
    assert.equal([...store.map.keys()].filter((k) => k.startsWith("intent:")).length, 0);
  });
}

test("a run past its deadline is marked expired at its next touch", async () => {
  const { book } = setup({ deadline: T0 });
  await book.op(req());
  assert.equal(book.status("R1").run.state, "expired");
});

test("removing or replacing the c-box key in the vault refuses an open run's next op (D3)", async () => {
  const { book, cf } = setup();
  assert.equal(book.setKeyRev(4), 4);
  const out = await book.op(req());
  assert.equal(out.agent, "refused: cbox_key_changed");
  assert.equal(cf.calls.length, 0);
  assert.equal(book.setKeyRev(2), 4, "the revision never goes down");
});

test("the stored c-box key revision never goes down", () => {
  const { book, store } = setup();
  book.setKeyRev(4);
  book.setKeyRev(2);
  assert.equal(store.map.get("cbox_rev"), 4);
  assert.throws(() => book.setKeyRev(-1), /bad_key_rev/);
});

test("the same op id never dispatches twice; a new op id is a new unit", async () => {
  const { book, cf } = setup();
  await book.op(req());
  const again = await book.op(req());
  assert.equal(again.agent, "refused: op_replayed");
  assert.equal(again.ben, "refused: run R1: op op-00000001 sent twice");
  await book.op(req({ op: "op-00000002" }));
  assert.equal(cf.calls.length, 2);
  assert.equal(book.status("R1").run.budget.used, 2);
});

test("the last unit: the next op is refused budget_spent", async () => {
  const { book, cf } = setup({ budget: { max: 50, used: 49 } });
  assert.equal((await book.op(req())).outcome, "done");
  assert.equal((await book.op(req({ op: "op-00000002" }))).agent, "refused: budget_spent (50 of 50 used)");
  assert.equal(cf.calls.length, 1);
});

test("frozen resources: the zone id and account come from the run record, never the current zone list (D4)", async () => {
  const { book, cf } = setup({ zones: [{ name: "benculbert.com", id: "f".repeat(32) }] });
  await book.op(req());
  assert.match(cf.calls[0].url, new RegExp(`/zones/${"f".repeat(32)}$`));
  const audit = setup();
  await audit.book.op(req({ job: "cf.audit.read", params: { since: "2026-11-04T00:00:00Z", until: "2026-11-04T11:00:00Z" } }));
  assert.match(audit.cf.calls[0].url, /\/accounts\/acct-frozen\/audit_logs\?/);
});

// A stop, finish, expiry or key change while the call is out: the answer is withheld, never stored.
const during: [string, (b: RunBook, clock: { now: number }) => void, string, string][] = [
  ["stop", (b) => b.endRun("R1", "stopped"), "not returned: run stopped before the answer was released", "run R1 op op-00000001: answer withheld (stopped)"],
  ["finish", (b) => b.endRun("R1", "finished"), "not returned: run finished before the answer was released", "run R1 op op-00000001: answer withheld (finished)"],
  ["deadline", (_b, c) => (c.now = T0 + 5 * 3600_000), "not returned: run ended before the answer was released", "run R1 op op-00000001: answer withheld (ended)"],
  ["key change", (b) => b.setKeyRev(9), "not returned: c-box key changed before the answer was released", "run R1 op op-00000001: answer withheld (c-box key changed)"],
];
for (const [name, act, agent, ben] of during) {
  test(`${name} during the call: answer withheld and never stored`, async () => {
    const box: { book?: RunBook; clock?: { now: number } } = {};
    const s = setup({}, fakeCf({ hold: () => act(box.book!, box.clock!) }));
    Object.assign(box, { book: s.book, clock: s.clock });
    const out = await s.book.op(req());
    assert.deepEqual({ outcome: out.outcome, agent: out.agent, ben: out.ben }, { outcome: "not_returned", agent, ben });
    assert.ok(!JSON.stringify(out).includes(ANSWER));
    assert.ok(!JSON.stringify([...s.store.map]).includes(ANSWER), "the answer is never written to storage");
    assert.equal(s.book.status("R1").ops[0].state, "withheld");
  });
}

test("a stop after release does not take the answer back; the next op is refused", async () => {
  const { book } = setup();
  assert.equal((await book.op(req())).outcome, "done");
  assert.deepEqual(book.endRun("R1", "stopped"), { state: "stopped", generation: 2 });
  assert.equal((await book.op(req({ op: "op-00000002" }))).agent, "refused: run_stopped");
  assert.deepEqual(book.endRun("R1", "finished"), { state: "stopped", generation: 2 }, "ending twice changes nothing");
});

test("Cloudflare refused: failed with its status, unit spent, op closed", async () => {
  const { book } = setup({}, fakeCf({ status: 403 }));
  const out = await book.op(req());
  assert.equal(out.agent, "failed: cloudflare refused (403)");
  assert.equal(out.ben, "job_failed: run R1 op op-00000001: Cloudflare refused");
  const s = book.status("R1");
  assert.equal(s.run.budget.used, 1);
  assert.equal(s.ops[0].state, "failed");
  assert.equal(s.unresolved, 0);
});

test("no answer from Cloudflare: counts against the budget and stays unresolved", async () => {
  const { book } = setup({}, fakeCf({ throws: true }));
  const out = await book.op(req());
  assert.equal(out.agent, "failed: no answer from Cloudflare; this op counts against the budget");
  assert.equal(out.ben, "job_failed: run R1 op op-00000001: no answer");
  assert.equal(book.status("R1").unresolved, 1);
  assert.equal(book.status("R1").run.budget.used, 1);
});

test("admission storage fails: nothing called, nothing spent (rolled back)", async () => {
  const { book, cf, store } = setup();
  store.fail = "intent:";
  const out = await book.op(req());
  assert.equal(out.agent, "failed: vault storage error before the call; nothing was called");
  assert.equal(out.ben, "job_failed: run R1 op op-00000001: vault storage error, nothing called");
  assert.equal(cf.calls.length, 0);
  assert.equal(book.status("R1").run.budget.used, 0, "the budget write rolled back with the intent write");
});

test("release storage fails: answer withheld, op read back as not released", async () => {
  const s = setup({}, fakeCf({ hold: () => (s.store.fail = "intent:") }));
  const out = await s.book.op(req());
  assert.equal(out.agent, "failed: Cloudflare answered but the vault could not save the release; answer not returned");
  assert.equal(out.ben, "job_failed: run R1 op op-00000001: called, release not saved; answer withheld");
  assert.ok(!JSON.stringify(out).includes(ANSWER));
  assert.equal(s.book.status("R1").ops[0].state, "admitted", "read back: not released (shown unresolved)");
});

test("a release that cannot be saved writes nothing, not even the run's expiry", async () => {
  const s = setup({}, fakeCf({ hold: () => ((s.clock.now = T0 + 5 * 3600_000), (s.store.fail = "intent:")) }));
  const out = await s.book.op(req());
  assert.equal(out.outcome, "failed");
  assert.equal((s.store.map.get("run:R1") as RunRecord).state, "open", "the expiry write rolled back with the failed release");
  assert.equal((s.store.map.get("run:R1") as RunRecord).generation, 1);
});

test("a run's status never carries a key value", async () => {
  const { book } = setup();
  await book.op(req());
  const s = book.status("R1");
  assert.ok(!JSON.stringify(s).includes(SECRET));
  assert.equal(s.run.has_key, true);
  assert.throws(() => book.status("R9"), /unknown_run/);
  assert.throws(() => book.endRun("R9", "stopped"), /unknown_run/);
});

test("run-eligible jobs are exactly the three reads", () => {
  assert.deepEqual([...RUN_ELIGIBLE], ["cf.zone.read", "cf.dns.list", "cf.audit.read"]);
});
