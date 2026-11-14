// Codex build r2 B: kept reach results reach Ben's phone from the PRODUCTION entry point -- the real src/index.ts
// (scheduled() -> FrontDesk) in workerd, triggered on each cron expression, with the production Pushover hook (outbound
// fetch caught here). The vault is a stand-in Worker on the VAULT binding that keeps one result and records acks.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { CRONS } from "../src/desk.ts";

const dir = mkdtempSync(join(tmpdir(), "fd-reachentry-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const desk = (async () => {
  await build({ entryPoints: [new URL("../src/index.ts", import.meta.url).pathname], bundle: true, format: "esm", platform: "neutral", mainFields: ["module", "main"], external: ["cloudflare:workers", "node:*"], outdir: dir, logLevel: "silent" });
  return readFileSync(join(dir, "index.js"), "utf8");
})();

// The stand-in vault: one kept final state ("expired"), acknowledged at most once; fetch() reports the acks.
const VAULT = `
import { WorkerEntrypoint } from "cloudflare:workers";
const acked = [];
const clean = { ok: true, tokens: 4, unexpected: [], stretched: [], missing: [], cleanup: [], github: { ok: true, changes: [] } };
export default class extends WorkerEntrypoint {
  async headcount() { return clean; }
  async ghReachNight() { return { state: "idle", done: 0, total: 0, code: null, calls: 0 }; }
  async ghReachStep() { return { state: "idle", done: 0, total: 0, code: null, calls: 0 }; }
  async ghReachResults() { return acked.includes("g1") ? [] : [{ id: "g1", kind: "acceptance", state: "expired" }]; }
  async ghReachAck(id) { acked.push(id); return true; }
  async fetch() { return Response.json(acked); }
}`;

async function start(phone: boolean) {
  const pushes: string[] = [];
  const outbound = async (req: Request) => {
    if (req.url.startsWith("https://api.pushover.net/")) {
      pushes.push(new URLSearchParams(await req.text()).get("message") ?? "");
      return Response.json({ status: 1 });
    }
    return new Response("ok"); // healthchecks ping
  };
  const mf = new Miniflare(convertV4MiniflareOptions({
    unsafeTriggerHandlers: true,
    workers: [
      {
        name: "desk", modules: true, script: await desk, compatibilityDate: "2026-10-01", compatibilityFlags: ["nodejs_compat"],
        durableObjects: { DESK: { className: "FrontDesk", useSQLite: true } }, serviceBindings: { VAULT: "vault" }, outboundService: outbound,
        bindings: { HC_HEADCOUNT_URL: "https://hc.example/ping/x", ...(phone ? { PUSHOVER_USER: "u".repeat(30), PUSHOVER_TOKEN: "t".repeat(30) } : {}) },
      },
      { name: "vault", modules: true, script: VAULT, compatibilityDate: "2026-10-01" },
    ],
  } as never));
  const fire = async (cron: string) => {
    await mf.dispatchFetch(`http://x/cdn-cgi/local/scheduled?cron=${encodeURIComponent(cron)}`);
    await new Promise((r) => setTimeout(r, 300)); // scheduled() hands the work to ctx.waitUntil
  };
  const acked = async () => (await (await (await mf.getWorker("vault")).fetch("http://x/")).json()) as string[];
  return { mf, pushes, fire, acked };
}

for (const [cron, what] of [[CRONS.headcount, "the scheduled headcount"], [CRONS.reach, "the night reach slice"]] as const) {
  test(`production entry: ${what} pushes a kept result through Pushover, then acknowledges it once`, { timeout: 60_000 }, async () => {
    const e = await start(true);
    try {
      await e.fire(cron);
      assert.ok(e.pushes.some((m) => /did not finish within 20 minutes/.test(m)), JSON.stringify(e.pushes));
      assert.deepEqual(await e.acked(), ["g1"]);
      await e.fire(cron);
      assert.equal(e.pushes.filter((m) => /did not finish within 20 minutes/.test(m)).length, 1, "pushed once");
    } finally {
      await e.mf.dispose();
    }
  });
}

test("production entry: with no phone set up, the scheduled headcount never acknowledges a kept result", { timeout: 60_000 }, async () => {
  const e = await start(false);
  try {
    await e.fire(CRONS.headcount);
    await e.fire(CRONS.reach);
    assert.deepEqual(await e.acked(), []);
  } finally {
    await e.mf.dispose();
  }
});
