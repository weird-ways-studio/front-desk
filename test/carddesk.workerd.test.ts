// Card build 3 (85818ab1) Outcome 7, Codex build r1 R6: a card runs through the REAL runtime boundary -- the desk's
// CardDesk in a real Durable Object (test/workerd/carddesk-harness.ts) calling the real vault entry point
// (vault/src/index.ts) over a real service binding, with RPC serialization, the vault's VaultBox and its card book
// all unmodified. Only two values are swapped in the vault bundle: its passkey pin and recorder key become test
// ones (a test cannot sign as Ben's phone or the Observatory). workerd from wrangler's own Miniflare, offline.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build, type Plugin } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { SoftKey } from "./softkey.ts";
import { pinOf } from "./vaultsign.ts";

const dir = mkdtempSync(join(tmpdir(), "fd-carddesk-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const echo = (word: string) => ({ job: "test.echo", params: { word }, reason: `echo ${word}` });

/** Rewrites exactly one constant in one vault file; fails the build if the text is not found exactly once. */
function swap(file: RegExp, find: RegExp, replace: string): Plugin {
  return {
    name: `swap-${file.source}`,
    setup(b) {
      b.onLoad({ filter: file }, (args) => {
        const src = readFileSync(args.path, "utf8");
        if ((src.match(new RegExp(find.source, "g")) ?? []).length !== 1) throw new Error(`swap: ${find} not found once in ${args.path}`);
        return { contents: src.replace(find, replace), loader: "ts" };
      });
    },
  };
}

async function start() {
  const key = await SoftKey.createExportable();
  const pin = await pinOf(key);
  const rec = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const recPub = Buffer.from((await crypto.subtle.exportKey("raw", rec.publicKey)) as ArrayBuffer).toString("base64");
  const out = join(dir, `b${Math.random().toString(36).slice(2)}`);
  await build({
    entryPoints: [new URL("../vault/src/index.ts", import.meta.url).pathname], bundle: true, format: "esm", platform: "neutral", external: ["cloudflare:workers"], outdir: join(out, "vault"), logLevel: "silent",
    plugins: [
      swap(/vault\/src\/passkey\.ts$/, /export const PASSKEY_PIN: PasskeyPin \| undefined = \{[^}]*\};/, `export const PASSKEY_PIN: PasskeyPin | undefined = ${JSON.stringify(pin)};`),
      swap(/vault\/src\/cardcopy\.ts$/, /export const RECORDER_KEY = "[^"]*";/, `export const RECORDER_KEY = ${JSON.stringify(recPub)};`),
    ],
  });
  await build({ entryPoints: [new URL("./workerd/carddesk-harness.ts", import.meta.url).pathname], bundle: true, format: "esm", platform: "neutral", mainFields: ["module", "main"], external: ["cloudflare:workers", "node:*"], outdir: join(out, "desk"), logLevel: "silent" });
  const mf = new Miniflare(convertV4MiniflareOptions({
    workers: [
      { name: "desk", modules: true, script: readFileSync(join(out, "desk", "carddesk-harness.js"), "utf8"), compatibilityDate: "2026-10-01", compatibilityFlags: ["nodejs_compat"], durableObjects: { DESK: { className: "HarnessDesk", useSQLite: true } }, serviceBindings: { VAULT: "vault" } },
      { name: "vault", modules: true, script: readFileSync(join(out, "vault", "index.js"), "utf8"), compatibilityDate: "2026-10-01", durableObjects: { BOX: { className: "VaultBox", useSQLite: true } } },
    ],
  }));
  const send = async (...cmds: { method: string; args: unknown[] }[]) => (await (await mf.dispatchFetch("http://x/", { method: "POST", body: JSON.stringify(cmds) })).json()) as { ok?: any; error?: string }[];
  const one = async (method: string, ...args: unknown[]) => {
    const [r] = await send({ method, args });
    if (r.error) throw new Error(r.error);
    return r.ok;
  };
  await one("setup", await key.exported(), (await crypto.subtle.exportKey("jwk", rec.privateKey)) as JsonWebKey);
  return { mf, send, one };
}

test("real runtime: a two-entry card runs in order across the binding; the agent collects answers and signed receipts", { timeout: 45_000 }, async () => {
  const { mf, one } = await start();
  try {
    const card = await one("request", [echo("hello"), echo("world")]);
    const r = await one("tap", card.id);
    assert.deepEqual(r.entries.map((e: { state: string }) => e.state), ["done", "done"]);
    const got = await one("collect", card.id);
    assert.deepEqual(got.entries.map((e: { answer: unknown }) => e.answer), [{ ok: true, data: { echoed: "hello" } }, { ok: true, data: { echoed: "world" } }]);
    for (const e of got.entries) for (const s of ["request", "verdict", "approval", "result"]) assert.equal(typeof e.receipts[s]?.sig, "string", `${s} receipt signed`);
    const v = await one("vaultStatus", card.id);
    assert.deepEqual(v.entries.map((e: { state: string }) => e.state), ["done", "done"], "the real vault's own book agrees");
    assert.deepEqual(v.answers, {}, "the vault dropped its copies once the desk stored them");
  } finally {
    await mf.dispose();
  }
});

test("real runtime: Stop while entry 2's approval is being recorded -- entry 2 never starts in the vault", { timeout: 45_000 }, async () => {
  const { mf, send, one } = await start();
  try {
    const card = await one("request", [echo("hello"), echo("world")]);
    await one("pause", "approval", 2);
    const running = send({ method: "tap", args: [card.id] });
    for (let i = 0; i < 300 && !(await one("paused")); i++) await sleep(20);
    assert.equal(await one("paused"), true, "checkpoint: entry 1 done, entry 2's approval in flight");
    const s = await one("stop", card.id);
    assert.equal(s.stopped, "stopped by Ben");
    await one("release");
    const [r] = await running;
    assert.deepEqual(r.ok.entries.map((e: { state: string }) => e.state), ["done", "not_run"]);
    const v = await one("vaultStatus", card.id);
    assert.deepEqual(v.entries.map((e: { state: string }) => e.state), ["done", "not_run"]);
    assert.ok(v.closed_at !== undefined && v.stopped, "the vault closed the card as stopped");
  } finally {
    await mf.dispose();
  }
});

test("real runtime: Ben removes the c-box key mid-card -- the real vault is told, entry 2 never starts", { timeout: 45_000 }, async () => {
  const { mf, send, one } = await start();
  try {
    await one("putKey");
    const card = await one("request", [echo("hello"), echo("world")]);
    await one("pause", "approval", 2);
    const running = send({ method: "tap", args: [card.id] });
    for (let i = 0; i < 300 && !(await one("paused")); i++) await sleep(20);
    assert.equal(await one("removeKey"), "aaaa-bbbb-cccc-dddd");
    await one("release");
    const [r] = await running;
    assert.deepEqual(r.ok.entries.map((e: { state: string }) => e.state), ["done", "not_run"]);
    const ev = await one("events");
    assert.ok(!ev.some((e: string) => e.startsWith("vault_key_rev_unsent")), "setKeyRev reached the real vault");
    assert.ok(ev.some((e: string) => /card entry 2: c-box key changed/.test(e)));
  } finally {
    await mf.dispose();
  }
});

test("real runtime: entry 1's cardRun reply is lost after the vault settled it -- the card stops, and the next read recovers the answer", { timeout: 45_000 }, async () => {
  const { mf, one } = await start();
  try {
    const card = await one("request", [echo("hello"), echo("world")]);
    await one("loseNextRun", 1);
    const r = await one("tap", card.id);
    assert.deepEqual(r.entries.map((e: { state: string }) => e.state), ["done", "not_run"], "the vault's book is the truth: entry 1 did run");
    const got = await one("collect", card.id);
    assert.deepEqual(got.entries[0].answer, { ok: true, data: { echoed: "hello" } });
    assert.equal(typeof got.entries[0].receipts.result?.sig, "string", "its result was recorded");
  } finally {
    await mf.dispose();
  }
});
