// Full-path budget evidence for the reach read (card N2 5fdbf2ce; spec 12.7; Codex build r1 #4): the desk's real Desk
// in a real Durable Object -> a real service binding -> the real vault entry point -> its Durable Object, in workerd
// from Miniflare (offline). The vault's outbound fetch goes to the counting fake GitHub (test/reachfake.ts), so each
// command's GitHub calls are the subrequests of the vault Durable Object's execution context; the desk's calls to the
// binding are counted in the desk harness. Workers Free allows 50 subrequests per invocation. Seams: clock and pin only
// (test/workerd/reach-vault-harness.ts). CPU time is not measured here (see CLAUDE.md, reach budget note).
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { SoftKey } from "./softkey.ts";
import { pinOf, signed } from "./vaultsign.ts";
import { pkcs8FromPem } from "../vault/src/github.ts";
import { APP, INST, fakeGitHub, pem } from "./reachfake.ts";

const DAY = Date.UTC(2026, 10, 14, 10, 0);
const LIMIT = 50;
const dir = mkdtempSync(join(tmpdir(), "fd-reach-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const bundles = (async () => {
  const opts = { bundle: true, format: "esm" as const, platform: "neutral" as const, mainFields: ["module", "main"], external: ["cloudflare:workers", "node:*"], logLevel: "silent" as const };
  await build({ ...opts, entryPoints: [new URL("./workerd/reach-vault-harness.ts", import.meta.url).pathname], outdir: join(dir, "vault") });
  await build({ ...opts, entryPoints: [new URL("./workerd/reach-harness.ts", import.meta.url).pathname], outdir: join(dir, "desk") });
  return { vault: readFileSync(join(dir, "vault", "reach-vault-harness.js"), "utf8"), desk: readFileSync(join(dir, "desk", "reach-harness.js"), "utf8") };
})();

async function start(repos: number) {
  const gh = fakeGitHub(repos);
  const outbound = async (req: Request) => gh.fetchFn(req.url, { method: req.method, headers: Object.fromEntries(req.headers), body: req.method === "GET" || req.method === "DELETE" ? undefined : await req.text() });
  const b = await bundles;
  const mf = new Miniflare(convertV4MiniflareOptions({
    workers: [
      { name: "desk", modules: true, script: b.desk, compatibilityDate: "2026-10-01", compatibilityFlags: ["nodejs_compat"], durableObjects: { DESK: { className: "ReachDesk", useSQLite: true } }, serviceBindings: { VAULT: "vault" } },
      { name: "vault", modules: true, script: b.vault, compatibilityDate: "2026-10-01", durableObjects: { BOX: { className: "ReachBox", useSQLite: true } }, outboundService: outbound },
    ],
  } as never));
  const one = async (method: string, ...args: unknown[]) => {
    const r = (await (await mf.dispatchFetch("http://x/", { method: "POST", body: JSON.stringify({ method, args }) })).json()) as { ok?: any; error?: string };
    if (r.error) throw new Error(r.error);
    return r.ok;
  };
  const key = await SoftKey.createExportable();
  await one("vault", "setTest", [DAY, await pinOf(key)]);
  await one("vault", "seed", [[["gh.app.headcount", { id: APP, slug: "wws-front-desk-headcount", key: pkcs8FromPem(pem), installation: INST }]]]);
  // Runs one command and returns it with the GitHub calls it caused (the vault Durable Object's subrequests).
  const counted = async (method: string, ...args: unknown[]) => {
    gh.calls.length = 0;
    const out = await one(method, ...args);
    return { ...out, github_calls: gh.calls.length };
  };
  const tapSigned = async () => {
    const { changes, ...bound } = await one("vault", "ghReachPreview", []);
    return counted("tap", await signed("gh.reach.baseline", { changes: changes.join("\n") || "none", ...bound }, "B".repeat(43), { key }));
  };
  return { mf, gh, one, counted, tapSigned };
}

const within = (what: string, r: { github_calls: number; desk_calls: number }) => {
  assert.ok(r.github_calls <= LIMIT, `${what}: ${r.github_calls} GitHub calls`);
  assert.ok(r.desk_calls <= LIMIT, `${what}: ${r.desk_calls} desk calls`);
};

test("real runtime budget: 18 repos in one slice, 36 in two, 37 refused; verify completion; the tap; a probe-cleanup failure", { timeout: 120_000 }, async (t) => {
  const seen: Record<string, { github: number; desk: number }> = {};
  const note = (what: string, r: { github_calls: number; desk_calls: number }) => {
    within(what, r);
    seen[what] = { github: r.github_calls, desk: r.desk_calls };
  };
  const a = await start(18);
  try {
    const s = await a.counted("step", "demand");
    assert.equal(s.progress.state, "complete");
    note("demand slice, 18 repos", s);
    const tap = await a.tapSigned();
    assert.equal(tap.result.ok, true, JSON.stringify(tap.result));
    note("approval tap, three probes", tap);
    const v = await a.counted("step");
    assert.deepEqual([v.progress.state, v.progress.acceptance, v.pushes.length], ["complete", "accepted", 0], "a 43-call slice leaves delivery to the next call");
    note("verify completion slice, 18 repos", v);
    const deliver = await a.counted("step");
    assert.equal(deliver.pushes.length, 1);
    note("next step, delivering 'recorded'", deliver);
    assert.ok((await a.one("log")).some((l: string) => /^reach_step: complete 18\/18 calls 43$/.test(l)), "the log line carries the call count");
  } finally {
    await a.mf.dispose();
  }
  const b = await start(36);
  try {
    const s1 = await b.counted("step", "demand");
    assert.equal(s1.progress.state, "open");
    note("36 repos, slice 1", s1);
    const s2 = await b.counted("step");
    assert.equal(s2.progress.state, "complete");
    note("36 repos, slice 2", s2);
  } finally {
    await b.mf.dispose();
  }
  const c = await start(37);
  try {
    const s = await c.counted("step", "demand");
    assert.equal(s.progress.code, "reach_over_budget");
    note("37 repos, refused", s);
  } finally {
    await c.mf.dispose();
  }
  const d = await start(2);
  try {
    await d.counted("step", "demand");
    d.gh.faults.grantWrite = "repository_hooks";
    d.gh.faults.deleteFail = "500";
    const tap = await d.tapSigned();
    assert.equal(tap.result.ok, false);
    note("tap, granted probe key not proven deleted", tap);
    const after = await d.counted("step");
    assert.equal(after.pushes.length, 1, "the unrevoked key is pushed");
    note("next step, delivering it", after);
  } finally {
    await d.mf.dispose();
  }
  t.diagnostic(JSON.stringify(seen));
  assert.deepEqual(seen, {
    "demand slice, 18 repos": { github: 43, desk: 1 },
    "approval tap, three probes": { github: 3, desk: 1 },
    "verify completion slice, 18 repos": { github: 43, desk: 1 },
    "next step, delivering 'recorded'": { github: 0, desk: 3 },
    "36 repos, slice 1": { github: 43, desk: 1 },
    "36 repos, slice 2": { github: 42, desk: 1 },
    "37 repos, refused": { github: 6, desk: 2 },
    "tap, granted probe key not proven deleted": { github: 5, desk: 1 },
    "next step, delivering it": { github: 0, desk: 3 },
  });
});
