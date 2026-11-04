// The run book's atomicity, proven in the real Durable Object runtime (REFINE-phase4a2.md D5): workerd from
// wrangler's own Miniflare, offline. Harness: test/workerd/runs-harness.ts.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

const dir = mkdtempSync(join(tmpdir(), "fd-runs-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const T = Date.now();
const run = (used: number) => ({
  id: "R1", generation: 1, state: "open", cards: ["card-a"], jobs: ["cf.zone.read"], account: "acct",
  zones: [{ name: "benculbert.com", id: "zone" }], template: 1, deadline: T + 3600_000,
  budget: { max: 50, used }, key_rev: 1, run_key_id: "rk1", opened_by: "g1",
});
const op = (id: string) => ({ run: "R1", generation: 1, key_rev: 1, card: "card-a", job: "cf.zone.read", op: id, params: { zone: "benculbert.com" } });

async function start(persist: string) {
  const out = join(dir, "bundle");
  await build({ entryPoints: [new URL("./workerd/runs-harness.ts", import.meta.url).pathname], bundle: true, format: "esm", platform: "neutral", external: ["cloudflare:workers"], outdir: out, logLevel: "silent" });
  const mf = new Miniflare(convertV4MiniflareOptions({
    modules: true, script: readFileSync(join(out, "runs-harness.js"), "utf8"), compatibilityDate: "2026-10-01",
    durableObjects: { BOX: { className: "HarnessBox", useSQLite: true } }, resourcePersistencePath: persist,
  }));
  const send = async (...cmds: { method: string; args: unknown[] }[]) => (await (await mf.dispatchFetch("http://x/", { method: "POST", body: JSON.stringify(cmds) })).json()) as any[];
  return { mf, send };
}

test("two ops race for the last unit: exactly one provider call, one intent, one increment; the loser is told budget_spent", { timeout: 60_000 }, async () => {
  const { mf, send } = await start(join(dir, "race"));
  try {
    await send({ method: "seed", args: [run(49), 1] });
    const results = await send({ method: "op", args: [op("op-race-0001")] }, { method: "op", args: [op("op-race-0002")] });
    assert.deepEqual(results.map((r) => r.agent).sort(), ["done", "refused: budget_spent (50 of 50 used)"]);
    const [s] = await send({ method: "status", args: [] });
    assert.equal(s.calls, 1);
    assert.equal(s.intents, 1);
    assert.equal(s.run.budget.used, 50);
  } finally {
    await mf.dispose();
  }
});

test("a fault between the budget write and the intent write leaves neither (real rollback)", { timeout: 60_000 }, async () => {
  const { mf, send } = await start(join(dir, "fault"));
  try {
    await send({ method: "seed", args: [run(10), 1] });
    await send({ method: "fault", args: ["intent:"] });
    const [r] = await send({ method: "op", args: [op("op-fault-001")] });
    assert.equal(r.agent, "failed: vault storage error before the call; nothing was called");
    const [s] = await send({ method: "status", args: [] });
    assert.equal(s.run.budget.used, 10);
    assert.equal(s.intents, 0);
    assert.equal(s.calls, 0);
  } finally {
    await mf.dispose();
  }
});

test("restart on persisted storage: budget and intents survive; the same op id is still refused", { timeout: 60_000 }, async () => {
  const persist = join(dir, "restart");
  const first = await start(persist);
  await first.send({ method: "seed", args: [run(0), 1] });
  assert.equal((await first.send({ method: "op", args: [op("op-restart-1")] }))[0].agent, "done");
  await first.mf.dispose();
  const second = await start(persist);
  try {
    const [s] = await second.send({ method: "status", args: [] });
    assert.equal(s.run.budget.used, 1);
    assert.deepEqual(s.ops.map((o: { op: string; state: string }) => [o.op, o.state]), [["op-restart-1", "released"]]);
    const [again] = await second.send({ method: "op", args: [op("op-restart-1")] });
    assert.equal(again.agent, "refused: op_replayed");
  } finally {
    await second.mf.dispose();
  }
});

test("reply lost after the release committed: the caller gets no answer, read-back finds the release saved", { timeout: 60_000 }, async () => {
  const { mf, send } = await start(join(dir, "lost"));
  try {
    await send({ method: "seed", args: [run(0), 1] });
    const [r] = await send({ method: "opReplyLost", args: [op("op-lost-0001")] });
    assert.deepEqual(Object.keys(r), ["error"]);
    assert.match(r.error, /reply lost/);
    assert.ok(!JSON.stringify(r).includes("benculbert.com"), "no part of the answer reached the caller");
    const [s] = await send({ method: "status", args: [] });
    assert.deepEqual(s.ops.map((o: { op: string; state: string }) => [o.op, o.state]), [["op-lost-0001", "released"]], "4a-2b shows this as released, not delivered");
    assert.equal(s.run.budget.used, 1);
  } finally {
    await mf.dispose();
  }
});
