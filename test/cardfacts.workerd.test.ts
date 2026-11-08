// Two runtime facts the card book (vault/src/cards.ts) relies on, checked in real workerd (REFINE-85818ab1 Open
// facts 2-3, resolved 2026-11-08). Harness: test/workerd/probe-harness.ts.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

const dir = mkdtempSync(join(tmpdir(), "fd-facts-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function start(className: string, persist: string) {
  await build({ entryPoints: [new URL("./workerd/probe-harness.ts", import.meta.url).pathname], bundle: true, format: "esm", platform: "neutral", external: ["cloudflare:workers"], outdir: dir, logLevel: "silent" });
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: readFileSync(join(dir, "probe-harness.js"), "utf8"), compatibilityDate: "2026-10-01", durableObjects: { BOX: { className, useSQLite: true } }, resourcePersistencePath: persist }));
  const send = async (method: string, ...args: unknown[]) => (await mf.dispatchFetch("http://x/", { method: "POST", body: JSON.stringify({ method, args }) })).json();
  return { mf, send };
}

test("fact 3: async storage and storage.kv share keys; a Map survives both ways (so cardOpen can read `used` in its transaction)", { timeout: 60_000 }, async () => {
  const a = await start("WithAlarm", join(dir, "maps"));
  try {
    assert.deepEqual(await a.send("maps"), { kv: [["g1", 5]], async: [["g2", 6]] });
  } finally {
    await a.mf.dispose();
  }
});

test("fact 2: an alarm due while older code (no alarm handler) runs is not lost: it fires once card-aware code returns", { timeout: 60_000 }, async () => {
  const p = join(dir, "alarm");
  let a = await start("WithAlarm", p);
  await a.send("arm", 1_000);
  await a.mf.dispose();
  const old = await start("NoAlarm", p);
  await sleep(2_500); // the alarm is now due while only the old class exists
  assert.equal(await old.send("x"), 0, "nothing ran it under the old class");
  await old.mf.dispose();
  a = await start("WithAlarm", p);
  try {
    for (let i = 0; i < 20 && (await a.send("fired")) === 0; i++) await sleep(250);
    assert.equal(await a.send("fired"), 1);
  } finally {
    await a.mf.dispose();
  }
});
