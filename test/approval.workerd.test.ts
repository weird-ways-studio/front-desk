// The vault's once-only rule in the real Durable Object runtime (card bb86abf0, REFINE R1): workerd from
// wrangler's own Miniflare, offline. Harness: test/workerd/approval-harness.ts. A call that gets past the
// admission step stops at no_master_key (the harness vault holds no key); a second admission is already_used.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { TEST_PIN, signed } from "./vaultsign.ts";

const dir = mkdtempSync(join(tmpdir(), "fd-approval-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const T = 1_800_000_000_000;
const PRF = Buffer.from(new Uint8Array(32).fill(7)).toString("base64url");

async function start(persist: string) {
  const out = join(dir, "bundle");
  await build({ entryPoints: [new URL("./workerd/approval-harness.ts", import.meta.url).pathname], bundle: true, format: "esm", platform: "neutral", external: ["cloudflare:workers"], outdir: out, logLevel: "silent" });
  const mf = new Miniflare(convertV4MiniflareOptions({
    modules: true, script: readFileSync(join(out, "approval-harness.js"), "utf8"), compatibilityDate: "2026-10-01",
    durableObjects: { BOX: { className: "HarnessBox", useSQLite: true } }, resourcePersistencePath: persist,
  }));
  const send = async (...cmds: { method: string; args: unknown[] }[]) => (await (await mf.dispatchFetch("http://x/", { method: "POST", body: JSON.stringify(cmds) })).json()) as { ok?: any; error?: string }[];
  return { mf, send };
}

test("two calls at once for one signed grant: exactly one is admitted, nothing is called", { timeout: 60_000 }, async () => {
  const { mf, send } = await start(join(dir, "race"));
  try {
    const req = await signed("cf.zone.read", { zone: "benculbert.com" }, PRF, { expires_at: T });
    const results = await send({ method: "run", args: [req, TEST_PIN, T] }, { method: "run", args: [req, TEST_PIN, T] });
    assert.deepEqual(results.map((r) => r.error).sort(), ["already_used", "no_master_key"]);
    const [u] = await send({ method: "used", args: [] });
    assert.deepEqual(u.ok, { ids: [req.grant.id], calls: 0 });
  } finally {
    await mf.dispose();
  }
});

test("restart on persisted storage: the used list survives and the same grant is still refused", { timeout: 60_000 }, async () => {
  const persist = join(dir, "restart");
  const req = await signed("cf.zone.read", { zone: "benculbert.com" }, PRF, { expires_at: T });
  const first = await start(persist);
  try {
    assert.equal((await first.send({ method: "run", args: [req, TEST_PIN, T] }))[0].error, "no_master_key");
  } finally {
    await first.mf.dispose();
  }
  const second = await start(persist);
  try {
    assert.equal((await second.send({ method: "run", args: [req, TEST_PIN, T + 1000] }))[0].error, "already_used");
    // Safeguard working: a different grant is still admitted after the restart.
    const other = await signed("cf.zone.read", { zone: "benculbert.com" }, PRF, { expires_at: T });
    assert.equal((await second.send({ method: "run", args: [other, TEST_PIN, T + 1000] }))[0].error, "no_master_key");
  } finally {
    await second.mf.dispose();
  }
});

test("an old-shape call reaches the real vault as wrong_shape and uses nothing", { timeout: 60_000 }, async () => {
  const { mf, send } = await start(join(dir, "old"));
  try {
    const [r] = await send({ method: "run", args: ["cf.zone.read", TEST_PIN, T] });
    assert.equal(r.error, "wrong_shape");
    assert.deepEqual((await send({ method: "used", args: [] }))[0].ok, { ids: [], calls: 0 });
  } finally {
    await mf.dispose();
  }
});

// Across the real service binding (desk -> vault RPC), with the vault's own entry point vault/src/index.ts:
// the old call's extra arguments arrive, and refusal codes arrive as exactly those words (the desk matches
// them exactly, card bb86abf0 R6).
test("real vault entry point over RPC: version answer, old call refused wrong_shape, codes arrive exact", { timeout: 60_000 }, async () => {
  const out = join(dir, "vault-bundle");
  await build({ entryPoints: [new URL("../vault/src/index.ts", import.meta.url).pathname], bundle: true, format: "esm", platform: "neutral", external: ["cloudflare:workers"], outdir: out, logLevel: "silent" });
  const caller = `export default { async fetch(request, env) {
    const cmds = await request.json();
    return Response.json(await Promise.all(cmds.map((c) => env.VAULT[c.method](...c.args).then((r) => ({ ok: r }), (e) => ({ error: e.message, isError: e instanceof Error })))));
  } };`;
  const mf = new Miniflare(convertV4MiniflareOptions({
    workers: [
      { name: "caller", modules: true, script: caller, compatibilityDate: "2026-10-01", serviceBindings: { VAULT: "vault" } },
      { name: "vault", modules: true, script: readFileSync(join(out, "index.js"), "utf8"), compatibilityDate: "2026-10-01", durableObjects: { BOX: { className: "VaultBox", useSQLite: true } } },
    ],
  }));
  try {
    const send = async (...cmds: { method: string; args: unknown[] }[]) => (await (await mf.dispatchFetch("http://x/", { method: "POST", body: JSON.stringify(cmds) })).json()) as any[];
    const req = await signed("cf.zone.read", { zone: "benculbert.com" }, PRF, { expires_at: Date.now() + 60_000 });
    const [api, old, extra, unsigned] = await send(
      { method: "approvalApi", args: [] },
      { method: "run", args: ["cf.zone.read", { zone: "benculbert.com" }, PRF] },
      { method: "run", args: [req, "extra"] },
      { method: "run", args: [req] }, // signed by the test passkey, not the pinned one
    );
    assert.deepEqual(api, { ok: { version: 1 } });
    assert.deepEqual(old, { error: "wrong_shape", isError: true });
    assert.deepEqual(extra, { error: "wrong_shape", isError: true });
    assert.deepEqual(unsigned, { error: "bad_assertion", isError: true });
  } finally {
    await mf.dispose();
  }
});
