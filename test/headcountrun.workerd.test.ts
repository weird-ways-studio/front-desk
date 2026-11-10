// Headcount runs (card build 5 6ab972c8) in the real Durable Object runtime: workerd from wrangler's own Miniflare,
// offline. Harness: test/workerd/headcountrun-harness.ts (the real Desk and route on real storage).
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { KEEP, judge } from "../src/headcountrun.ts";

const dir = mkdtempSync(join(tmpdir(), "fd-hcrun-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const H = 3600_000;

async function start(persist: string) {
  const out = join(dir, "bundle");
  await build({ entryPoints: [new URL("./workerd/headcountrun-harness.ts", import.meta.url).pathname], bundle: true, format: "esm", platform: "neutral", mainFields: ["module", "main"], external: ["cloudflare:workers", "node:*"], outdir: out, logLevel: "silent" });
  const mf = new Miniflare(convertV4MiniflareOptions({
    modules: true, script: readFileSync(join(out, "headcountrun-harness.js"), "utf8"), compatibilityDate: "2026-10-01",
    durableObjects: { BOX: { className: "Box", useSQLite: true } }, resourcePersistencePath: persist,
  }));
  const send = async (method: string, args: unknown[] = []) => (await (await mf.dispatchFetch("http://x/", { method: "POST", body: JSON.stringify({ method, args }) })).json()) as any;
  return { mf, send };
}

test("real storage: 17 runs keep the newest 14 in order, survive a restart, and only the agent reads them", { timeout: 60_000 }, async () => {
  const persist = join(dir, "p");
  const first = Date.now() - 16 * 24 * H - H;
  let { mf, send } = await start(persist);
  try {
    await send("runs", [first, KEEP + 3, 24]);
  } finally {
    await mf.dispose();
  }
  ({ mf, send } = await start(persist));
  try {
    const ok = await send("get", ["agent"]);
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.body.runs.map((r: { seq: number }) => r.seq), Array.from({ length: KEEP }, (_, i) => KEEP + 3 - i));
    assert.equal(ok.body.attempt.seq, KEEP + 3);
    assert.equal(judge(ok.body, Date.now()).verdict, "PASS");
    assert.equal(judge(ok.body, Date.now(), { after: first + 14.5 * 24 * H }).verdict, "PASS");
    assert.equal((await send("get", ["owner"])).status, 403);
    assert.equal((await send("get", ["unknown"])).status, 403);
  } finally {
    await mf.dispose();
  }
});
