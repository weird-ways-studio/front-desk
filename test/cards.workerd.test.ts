// The card book in the real Durable Object runtime (REFINE-85818ab1 Outcome 5, T5, T6, U3): workerd from wrangler's
// own Miniflare, offline. Harness: test/workerd/cards-harness.ts. Times are real (a 2-3 s deadline), so each test waits.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { makeCard, openReq, runReq, TestRecorder } from "./cardsign.ts";
import { TEST_PIN } from "./vaultsign.ts";

const dir = mkdtempSync(join(tmpdir(), "fd-cards-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const ZONE = { zone: "benculbert.com" };

async function start(persist: string) {
  const out = join(dir, "bundle");
  await build({ entryPoints: [new URL("./workerd/cards-harness.ts", import.meta.url).pathname], bundle: true, format: "esm", platform: "neutral", external: ["cloudflare:workers"], outdir: out, logLevel: "silent" });
  const mf = new Miniflare(convertV4MiniflareOptions({
    modules: true, script: readFileSync(join(out, "cards-harness.js"), "utf8"), compatibilityDate: "2026-10-01",
    durableObjects: { BOX: { className: "CardsBox", useSQLite: true } }, resourcePersistencePath: persist,
  }));
  const send = async (...cmds: { method: string; args: unknown[] }[]) => (await (await mf.dispatchFetch("http://x/", { method: "POST", body: JSON.stringify(cmds) })).json()) as any[];
  return { mf, send };
}
async function card(deadlineMs: number) {
  const t = Date.now();
  return makeCard(t, [["cf.zone.read", ZONE], ["cf.dns.list", ZONE]], { deadline: t + deadlineMs });
}
const until = async (f: () => Promise<boolean>, ms = 15_000) => {
  for (const end = Date.now() + ms; Date.now() < end; await sleep(200)) if (await f()) return;
  assert.fail("timed out waiting");
};

test("T6: a claimed entry whose job never answers is closed unknown by the alarm, with no further request", { timeout: 60_000 }, async () => {
  const rec = await TestRecorder.create();
  const { mf, send } = await start(join(dir, "t6"));
  try {
    await send({ method: "setup", args: [TEST_PIN, rec.pub, -1] });
    const c = await card(2_000);
    await send({ method: "open", args: [openReq(c)] });
    // The claim is sent and never comes back: the job hangs (Safari closed, the desk's call cancelled).
    void mf.dispatchFetch("http://x/", { method: "POST", body: JSON.stringify([{ method: "run", args: [await runReq(c, 0, rec)] }]) }).catch(() => {});
    await sleep(3_500); // past the deadline; nothing is sent meanwhile
    const [s] = await send({ method: "status", args: [c.manifest.card] }); // a read only: status() writes nothing
    assert.deepEqual(s.entries.map((e: { state: string }) => e.state), ["unknown", "not_run"]);
    assert.equal(s.stopped, "deadline passed");
    assert.equal(s.calls, 1);
  } finally {
    await mf.dispose();
  }
});

test("U3: a restart (the next build of the class on the same storage) with an open, claimed card: the stored alarm closes it", { timeout: 60_000 }, async () => {
  const rec = await TestRecorder.create();
  const persist = join(dir, "u3");
  const first = await start(persist);
  const c = await card(2_000);
  await first.send({ method: "setup", args: [TEST_PIN, rec.pub, -1] });
  await first.send({ method: "open", args: [openReq(c)] });
  void first.mf.dispatchFetch("http://x/", { method: "POST", body: JSON.stringify([{ method: "run", args: [await runReq(c, 0, rec)] }]) }).catch(() => {});
  await sleep(300);
  await first.mf.dispose(); // evicted mid-call
  await sleep(2_500); // the deadline passes while nothing runs
  const second = await start(persist);
  try {
    await until(async () => (await second.send({ method: "status", args: [c.manifest.card] }))[0].closed_at !== undefined);
    const [s] = await second.send({ method: "status", args: [c.manifest.card] });
    assert.deepEqual(s.entries.map((e: { state: string }) => e.state), ["unknown", "not_run"]);
  } finally {
    await second.mf.dispose();
  }
});

test("two claims of entry 1 at once: exactly one job call; the other returns the entry's current state", { timeout: 60_000 }, async () => {
  const rec = await TestRecorder.create();
  const { mf, send } = await start(join(dir, "race"));
  try {
    await send({ method: "setup", args: [TEST_PIN, rec.pub, 50] });
    const c = await card(60_000);
    await send({ method: "open", args: [openReq(c)] });
    const req = await runReq(c, 0, rec);
    const both = await send({ method: "run", args: [req] }, { method: "run", args: [req] });
    assert.deepEqual(both.map((r) => r.state).sort(), ["dispatching", "done"]);
    const [s] = await send({ method: "status", args: [c.manifest.card] });
    assert.equal(s.calls, 1);
  } finally {
    await mf.dispose();
  }
});

test("T5: Stop sent while entry 1's call is out -- entry 1 finishes, entry 2 never starts, the card closes", { timeout: 60_000 }, async () => {
  const rec = await TestRecorder.create();
  const { mf, send } = await start(join(dir, "stop"));
  try {
    await send({ method: "setup", args: [TEST_PIN, rec.pub, 300] });
    const c = await card(60_000);
    await send({ method: "open", args: [openReq(c)] });
    const running = send({ method: "run", args: [await runReq(c, 0, rec)] });
    await until(async () => (await send({ method: "status", args: [c.manifest.card] }))[0].entries[0].state === "dispatching", 5_000);
    const [stopped] = await send({ method: "stop", args: [c.manifest.card] }); // checkpoint: asserted to land mid-call
    assert.deepEqual(stopped.entries.map((e: { state: string }) => e.state), ["dispatching", "not_run"]);
    const [r] = await running;
    assert.equal(r.state, "done");
    assert.ok(r.card.closed_at);
    const [again] = await send({ method: "run", args: [await runReq(c, 1, rec)] });
    assert.equal(again.state, "not_run");
    const [s] = await send({ method: "status", args: [c.manifest.card] });
    assert.equal(s.calls, 1);
  } finally {
    await mf.dispose();
  }
});
