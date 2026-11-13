// Card 139071ea, vault side (studio-os REFINE-139071ea-cf-keys-in-results.md v2.1, evidence E1 items 1-3 and 6):
// every answer of the five jobs that open the Cloudflare master carries `cf` -- the key ids Cloudflare positively
// confirmed this tap made and deleted, or "unknown" when any attempted change did not resolve.
import { test } from "node:test";
import assert from "node:assert/strict";
import { signedRun, testVault } from "./vaultsign.ts";
import { MemoryStore } from "../src/desk.ts";
import { Cloudflare, CF_LIST_MAX, effectsField, newEffects } from "../vault/src/cloudflare.ts";
import { HELPER_PREFIX, OLD_HEADCOUNT_DELETES, VaultLogic } from "../vault/src/vault.ts";
import { b64url } from "../vault/src/seal.ts";

const ACCOUNT = "a".repeat(32);
const ZONE_ID = "b".repeat(32);
const ZONE = "benculbert.com";
const PARENT = "P".repeat(40);
const NOW = Date.UTC(2026, 10, 13, 12, 0, 0);
const PRF = b64url(new Uint8Array(32).fill(7));
const hexId = (n: number) => n.toString(16).padStart(32, "0");
const TOKENS = `/accounts/${ACCOUNT}/tokens`;

type Rule = { method: string; path: RegExp; times?: number; respond: (real: () => Promise<Response>) => Response | Promise<Response> };

// A fake Cloudflare with real-shaped key ids (32 hex). `rules` answer first, each up to `times` (default 1); a rule may
// run the real action (`real()`) and then answer something else, e.g. a key made whose answer is lost.
function fakeCloudflare() {
  const tokens: { id: string; name?: string; policies?: any[] }[] = [{ id: "t0" }, { id: "t1" }];
  const values = new Map<string, string>(); // value -> id
  const listOnly = new Set<string>();
  const rules: Rule[] = [];
  const calls: { method: string; path: string }[] = [];
  let n = 0x100;
  const ok = (result: unknown) => Response.json({ success: true, result });
  const bad = (status: number, message: string) => Response.json({ success: false, errors: [{ message }] }, { status });
  const real = async (method: string, path: string, token: string, body: any): Promise<Response> => {
    if (path === "/accounts") return ok([{ id: ACCOUNT }]);
    if (path === `${TOKENS}/verify`) return ok({ id: "t0", status: "active" });
    if (path === `${TOKENS}/permission_groups`)
      return ok([
        { id: "zone-r", name: "Zone Read", scopes: ["com.cloudflare.api.account.zone"] },
        { id: "dns-r", name: "DNS Read", scopes: ["com.cloudflare.api.account.zone"] },
        { id: "acct-set-r", name: "Account Settings Read", scopes: ["com.cloudflare.api.account"] },
        { id: "tok-r", name: "Account API Tokens Read", scopes: ["com.cloudflare.api.account"] },
      ]);
    if (method === "POST" && path === TOKENS) {
      if (listOnly.has(token)) return bad(403, "Unauthorized to access requested resource");
      const id = hexId(++n);
      const value = `V${n}`.padEnd(40, "v");
      tokens.push({ id, name: body?.name, policies: body?.policies });
      values.set(value, id);
      if (body?.policies?.[0]?.permission_groups?.every((g: { id: string }) => g.id === "tok-r")) listOnly.add(value);
      return ok({ id, value });
    }
    if (method === "DELETE" && path.startsWith(`${TOKENS}/`)) {
      const id = path.split("/").pop()!;
      const at = tokens.findIndex((t) => t.id === id);
      if (at < 0) return bad(404, "not found");
      tokens.splice(at, 1);
      return ok({ id });
    }
    if (path.startsWith(`${TOKENS}?`)) {
      const u = new URL(`https://x${path}`);
      const page = Number(u.searchParams.get("page"));
      const per = Number(u.searchParams.get("per_page"));
      return ok(tokens.slice((page - 1) * per, page * per));
    }
    if (path === `/zones?name=${ZONE}`) return ok([{ id: ZONE_ID, name: ZONE }]);
    if (path === `/zones/${ZONE_ID}`) return ok({ id: ZONE_ID, name: ZONE, status: "active", paused: false, type: "full", plan: { name: "Free" }, name_servers: ["a.ns"] });
    if (path.startsWith(`/zones/${ZONE_ID}/dns_records?`)) return ok([]);
    if (path.startsWith(`/accounts/${ACCOUNT}/audit_logs?`)) return ok([]);
    return bad(404, `unexpected ${method} ${path}`);
  };
  const fetchFn = async (input: string, init?: RequestInit) => {
    const url = new URL(input);
    const path = url.pathname.replace("/client/v4", "") + url.search;
    const method = init?.method ?? "GET";
    const token = String((init?.headers as Record<string, string>).authorization).replace("Bearer ", "");
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path });
    const rule = rules.find((r) => r.method === method && r.path.test(path) && (r.times ?? 1) > 0);
    if (rule) {
      rule.times = (rule.times ?? 1) - 1;
      return rule.respond(() => real(method, path, token, body));
    }
    return real(method, path, token, body);
  };
  return { fetchFn, tokens, rules, calls };
}

// A store whose put can be made to fail, to show a confirmed change survives a storage failure after it (E1.3).
class FlakyStore extends MemoryStore {
  failPut?: (key: string, value: unknown) => boolean;
  override async put<T>(key: string, value: T) {
    if (this.failPut?.(key, value)) throw new Error("storage write failed");
    return super.put(key, value);
  }
}

async function fresh() {
  const cf = fakeCloudflare();
  const store = new FlakyStore();
  const vault = testVault(store, cf.fetchFn, () => NOW);
  await vault.setup(PARENT);
  return { cf, store, vault };
}
const AUDIT = { since: "2026-11-13T10:00:00Z", until: "2026-11-13T11:00:00Z" };
const run = (vault: VaultLogic, job: string, params: Record<string, string> = {}) => signedRun(vault, job, params, PRF) as Promise<any>;
const read = (vault: VaultLogic, job = "cf.dns.list") => run(vault, job, job === "cf.audit.read" ? AUDIT : { zone: ZONE });
const madeIds = (cf: ReturnType<typeof fakeCloudflare>) => (cf.tokens as { id: string }[]).map((t) => t.id);

test("E1.1 read jobs: cf lists every helper key made and deleted, in order; zone jobs two of each, the change log one", async () => {
  for (const [job, count] of [["cf.dns.list", 2], ["cf.zone.read", 2], ["cf.audit.read", 1]] as const) {
    const { vault } = await fresh();
    const r = await read(vault, job);
    assert.equal(r.ok, true, `${job}: ${JSON.stringify(r)}`);
    assert.equal(r.cf.made.length, count, job);
    assert.deepEqual(r.cf.made, r.minted.map((m: { id: string }) => m.id), "the ids Cloudflare confirmed, in order");
    assert.deepEqual(r.cf.deleted, r.cf.made, "each helper deleted inside the tap");
  }
});

test("E1.1 headcount setup: the new key is made; a previous one deleted; a wrongly made must-fail key listed and deleted", async () => {
  const { vault, cf } = await fresh();
  const first = await run(vault, "cf.token.headcount.setup");
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.deepEqual(first.cf, { made: [first.key_id], deleted: [] });
  const second = await run(vault, "cf.token.headcount.setup");
  assert.deepEqual(second.cf, { made: [second.key_id], deleted: [first.key_id] }, "the replaced key is a confirmed delete");
  // Cloudflare wrongly lets the list-only key mint (T6): that create is this tap's too, then the probe and the new key go.
  const { vault: v, cf: c } = await fresh();
  let posts = 0;
  c.rules.push({
    method: "POST", path: /tokens$/, times: 2,
    respond: async (realCall) => {
      if (++posts === 1) return realCall(); // the headcount key itself
      const id = hexId(0xbeef); // the must-fail mint, made as Cloudflare wrongly would
      c.tokens.push({ id });
      return Response.json({ success: true, result: { id, value: "W".repeat(40) } });
    },
  });
  const fx = { r: await run(v, "cf.token.headcount.setup") };
  assert.equal(fx.r.ok, false);
  assert.equal(fx.r.mint_error, "headcount key could mint");
  assert.deepEqual(fx.r.cf.made, [fx.r.key_id, hexId(0xbeef)]);
  assert.deepEqual(fx.r.cf.deleted, [hexId(0xbeef), fx.r.key_id], "probe key deleted, then the new key that could mint");
});

test("E1.1 cf.token.accept: a leftover helper deleted by the sweep is listed; a sweep 404 or failure is not", async () => {
  const { vault, cf, store } = await fresh();
  const seed = async (id: string) => {
    cf.tokens.push({ id, name: `${HELPER_PREFIX}old` });
    await store.put("helpers", [{ name: `${HELPER_PREFIX}old`, purpose: "test", until: "2026-11-13T11:00:00Z", id }]);
  };
  const other = hexId(0xabc);
  cf.tokens.push({ id: other, name: "kept", policies: [{ effect: "allow", resources: { [`com.cloudflare.api.account.${ACCOUNT}`]: "*" }, permission_groups: [{ id: "zone-r", name: "Zone Read" }] }] });
  await run(vault, "cf.token.headcount.setup");
  const accept = () => run(vault, "cf.token.accept", { ids: other, scopes: "x" });

  await seed(hexId(0xa1));
  assert.deepEqual((await accept()).cf, { made: [], deleted: [hexId(0xa1)] }, "sweep delete confirmed");

  await seed(hexId(0xa2));
  cf.rules.push({ method: "DELETE", path: /a2$/, respond: () => Response.json({ success: false, errors: [{ message: "gone" }] }, { status: 404 }) });
  assert.deepEqual((await accept()).cf, { made: [], deleted: [] }, "a 404 is closed, never a delete");

  await seed(hexId(0xa3));
  cf.rules.push({ method: "DELETE", path: /a3$/, respond: () => Response.json({ success: false, errors: [] }, { status: 500 }) });
  assert.equal((await accept()).cf, "unknown", "a failed sweep delete is unresolved");
});

test("E1.1 failure points of a read: mint refused, use fails, delete fails", async () => {
  {
    const { vault, cf } = await fresh();
    cf.rules.push({ method: "POST", path: /tokens$/, respond: () => Response.json({ success: false, errors: [{ message: "no" }] }, { status: 403 }) });
    const r = await read(vault);
    assert.equal(r.ok, false);
    assert.deepEqual(r.cf, { made: [], deleted: [] }, "a recognized refusal: nothing changed, nothing listed");
  }
  {
    const { vault, cf } = await fresh();
    cf.rules.push({ method: "GET", path: /dns_records/, respond: () => Response.json({ success: false, errors: [] }, { status: 500 }) });
    const r = await read(vault);
    assert.equal(r.ok, false);
    assert.equal(r.cf.made.length, 2, "a failed tap still lists what it did");
    assert.deepEqual(r.cf.deleted, r.cf.made);
  }
  {
    const { vault, cf } = await fresh();
    cf.rules.push({ method: "DELETE", path: /tokens\//, times: 9, respond: () => Response.json({ success: false, errors: [] }, { status: 500 }) });
    assert.equal((await read(vault)).cf, "unknown", "a delete that failed may still have happened");
  }
});

// What Cloudflare answers to one key create (E1.2). "listed" = confirmed; "closed" = refused, nothing listed; "unknown".
const CREATE_CASES: [string, () => Response, "listed" | "closed" | "unknown"][] = [
  ["200 not JSON", () => new Response("<html>", { status: 200 }), "unknown"],
  ["200 {}", () => Response.json({}), "unknown"],
  ["200 no success", () => Response.json({ result: { id: hexId(0xe1), value: "x" } }), "unknown"],
  ["200 success false", () => Response.json({ success: false, result: { id: hexId(0xe1), value: "x" } }), "unknown"],
  ["200 id not hex", () => Response.json({ success: true, result: { id: "minted1", value: "x" } }), "unknown"],
  ["200 no value", () => Response.json({ success: true, result: { id: hexId(0xe1) } }), "unknown"],
  ["200 array", () => Response.json([]), "unknown"],
  ["502 {}", () => Response.json({}, { status: 502 }), "unknown"],
  ["500 success false", () => Response.json({ success: false }, { status: 500 }), "unknown"],
  ["409 success false", () => Response.json({ success: false }, { status: 409 }), "unknown"],
  ["408 success false", () => Response.json({ success: false }, { status: 408 }), "unknown"],
  ["403 not JSON", () => new Response("denied", { status: 403 }), "unknown"],
  ["403 no success", () => Response.json({ errors: [] }, { status: 403 }), "unknown"],
  ...([400, 401, 403, 429] as const).map((s): [string, () => Response, "closed"] => [`${s} success false`, () => Response.json({ success: false, errors: [] }, { status: s }), "closed"]),
  ["200 confirmed", () => Response.json({ success: true, result: { id: hexId(0xe1), value: "x" } }), "listed"],
];

test("E1.2 a create counts only when confirmed; only a recognized refusal closes it", async () => {
  for (const [label, answer, want] of CREATE_CASES) {
    const fx = newEffects();
    const cf = new Cloudflare("T", async () => answer(), fx);
    await cf.create(TOKENS, {}).catch(() => undefined);
    const got = effectsField(fx);
    if (want === "listed") assert.deepEqual(got, { made: [hexId(0xe1)], deleted: [] }, label);
    else if (want === "closed") assert.deepEqual(got, { made: [], deleted: [] }, label);
    else assert.equal(got, "unknown", label);
  }
});

test("E1.2 a delete: the same id or no echo is listed; another id, odd envelopes and 5xx are unknown; 404 refused is closed", async () => {
  const id = hexId(0xd1);
  const cases: [string, () => Response, "listed" | "closed" | "unknown"][] = [
    ["echo same", () => Response.json({ success: true, result: { id } }), "listed"],
    ["no echo", () => Response.json({ success: true, result: null }), "listed"],
    ["no result", () => Response.json({ success: true }), "listed"],
    ["echo other", () => Response.json({ success: true, result: { id: hexId(0xd2) } }), "unknown"],
    ["echo not a string", () => Response.json({ success: true, result: { id: 5 } }), "unknown"],
    ["200 {}", () => Response.json({}), "unknown"],
    ["200 not JSON", () => new Response("", { status: 200 }), "unknown"],
    ["502 {}", () => Response.json({}, { status: 502 }), "unknown"],
    ["404 success false", () => Response.json({ success: false }, { status: 404 }), "closed"],
    ["404 not JSON", () => new Response("nope", { status: 404 }), "unknown"],
    ["403 success false", () => Response.json({ success: false }, { status: 403 }), "closed"],
  ];
  for (const [label, answer, want] of cases) {
    const fx = newEffects();
    await new Cloudflare("T", async () => answer(), fx).remove(ACCOUNT, id).catch(() => undefined);
    const got = effectsField(fx);
    if (want === "listed") assert.deepEqual(got, { made: [], deleted: [id] }, label);
    else if (want === "closed") assert.deepEqual(got, { made: [], deleted: [] }, label);
    else assert.equal(got, "unknown", label);
  }
});

test("E1.2 a thrown fetch, or an unresolved attempt followed by a confirmed and a refused one, stays unknown", async () => {
  const thrown = newEffects();
  await assert.rejects(new Cloudflare("T", async () => { throw new Error("network"); }, thrown).create(TOKENS, {}), /network/);
  assert.equal(effectsField(thrown), "unknown");

  const answers = [Response.json({}, { status: 502 }), Response.json({ success: true, result: { id: hexId(1), value: "x" } }), Response.json({ success: false }, { status: 403 })];
  const fx = newEffects();
  const cf = new Cloudflare("T", async () => answers.shift()!, fx);
  for (let i = 0; i < 3; i++) await cf.create(TOKENS, {}).catch(() => undefined);
  assert.deepEqual(fx.made, [hexId(1)]);
  assert.equal(effectsField(fx), "unknown", "a later success never clears an earlier uncertainty");
});

test("E1.2 callers keep their behavior: a create or delete still throws or returns exactly as call() did", async () => {
  const fx = newEffects();
  const cf = new Cloudflare("T", async () => Response.json({ success: false, errors: [{ code: 9109, message: "no" }] }, { status: 403 }), fx);
  await assert.rejects(cf.create(TOKENS, {}), /^VaultError: cf_403\[9109\]: no$|cf_403\[9109\]: no/);
  const odd = new Cloudflare("T", async () => Response.json({}), newEffects());
  assert.equal(await odd.remove(ACCOUNT, hexId(1)), undefined, "an empty 200 still returns, as before; only cf differs");
  await assert.rejects(new Cloudflare("T", async () => Response.json({})).create(TOKENS, {}), /no_effects_record/, "no change without a record");
});

test("E1.3 a confirmed create then a helper-storage failure: the id is kept in cf", async () => {
  const { vault, store } = await fresh();
  store.failPut = (key, value) => key === "helpers" && (value as { id?: string }[]).some((h) => h.id);
  const r = await read(vault, "cf.audit.read");
  assert.equal(r.ok, false);
  assert.notEqual(r.cf, "unknown");
  assert.equal(r.cf.made.length, 1, "the key exists, so it is listed; never a complete-looking list without it");
});

test("E1.3 a confirmed delete then a cleanup-storage failure: the delete is kept", async () => {
  const { vault, store } = await fresh();
  store.failPut = (key, value) => key === "helpers" && (value as unknown[]).length === 0;
  const r = await read(vault, "cf.audit.read");
  assert.equal(r.cf.made.length, 1);
  assert.deepEqual(r.cf.deleted, r.cf.made);
});

test("E1.3 a failure after a successful sweep keeps the sweep's delete", async () => {
  const { vault, cf, store } = await fresh();
  const old = hexId(0xa9);
  cf.tokens.push({ id: old, name: `${HELPER_PREFIX}old` });
  await store.put("helpers", [{ name: `${HELPER_PREFIX}old`, purpose: "test", until: "2026-11-13T11:00:00Z", id: old }]);
  cf.rules.push({ method: "GET", path: /permission_groups/, respond: () => Response.json({ success: false }, { status: 500 }) });
  const r = await read(vault);
  assert.equal(r.ok, false);
  assert.deepEqual(r.cf, { made: [], deleted: [old] });
});

test("E1.6 a 20-key retired backlog drains over three setups; each tap's lists stay within the bound", async () => {
  const { vault, cf, store } = await fresh();
  await run(vault, "cf.token.headcount.setup");
  const hc = (await store.get<any>("headcount"))!;
  const backlog = Array.from({ length: 19 }, (_, i) => hexId(0xf00 + i));
  backlog.forEach((id) => cf.tokens.push({ id }));
  await store.put("headcount", { ...hc, retired: backlog });
  const sizes: number[] = [];
  for (let i = 0; i < 3; i++) {
    const r = await run(vault, "cf.token.headcount.setup");
    assert.notEqual(r.cf, "unknown");
    assert.ok(r.cf.deleted.length <= 12 && r.cf.made.length <= 2, JSON.stringify(r.cf));
    sizes.push(r.cf.deleted.length);
  }
  assert.deepEqual(sizes, [OLD_HEADCOUNT_DELETES, OLD_HEADCOUNT_DELETES, 6], "20, then 12 + the new key's predecessor, then the rest");
  assert.deepEqual((await store.get<any>("headcount")).retired, [], "drained");
  assert.ok(backlog.every((id) => !madeIds(cf).includes(id)));
});

test("E1.6 the bound: over CF_LIST_MAX in either list signs unknown, never a cut list", () => {
  const ids = Array.from({ length: CF_LIST_MAX + 1 }, (_, i) => hexId(i + 1));
  assert.notEqual(effectsField({ made: [], deleted: ids.slice(0, CF_LIST_MAX), open: 0 }), "unknown");
  assert.equal(effectsField({ made: [], deleted: ids, open: 0 }), "unknown");
  assert.equal(effectsField({ made: ids, deleted: [], open: 0 }), "unknown");
  assert.equal(effectsField({ made: [], deleted: [], open: 1 }), "unknown");
});

test("E1.1 headcount replace with one stuck old key: the tap signs unknown and the key stays on retired", async () => {
  const { vault, cf, store } = await fresh();
  const first = await run(vault, "cf.token.headcount.setup");
  cf.rules.push({ method: "DELETE", path: new RegExp(`${first.key_id}$`), respond: () => Response.json({ success: false, errors: [] }, { status: 500 }) });
  const second = await run(vault, "cf.token.headcount.setup");
  assert.equal(second.cf, "unknown", "a delete that failed may still have happened");
  assert.deepEqual((await store.get<any>("headcount")).retired, [first.key_id]);
});

// Codex r1 (build) fix-now: the E1.1 failure points for every applicable master job, and the issued-key sweep.
const USE_PATH: Record<string, RegExp> = { "cf.dns.list": /dns_records/, "cf.zone.read": new RegExp(`/zones/${ZONE_ID}$`), "cf.audit.read": /audit_logs/ };
const fail = (status: number, success: boolean | undefined = false) => () => Response.json(success === undefined ? {} : { success, errors: [] }, { status });

test("E1.1 every read job: mint refused -> empty lists; use fails -> lists what it did; delete fails -> unknown", async () => {
  for (const job of Object.keys(USE_PATH)) {
    {
      const { vault, cf } = await fresh();
      cf.rules.push({ method: "POST", path: /tokens$/, respond: fail(403) });
      const r = await read(vault, job);
      assert.equal(r.ok, false, job);
      assert.deepEqual(r.cf, { made: [], deleted: [] }, `${job}: refused mint`);
    }
    {
      const { vault, cf } = await fresh();
      cf.rules.push({ method: "GET", path: USE_PATH[job], respond: fail(500) });
      const r = await read(vault, job);
      assert.equal(r.ok, false, job);
      // The fake numbers keys from 0x101 in creation order; no other key is made in a fresh vault.
      const helpers = job === "cf.audit.read" ? [hexId(0x101)] : [hexId(0x101), hexId(0x102)];
      assert.deepEqual(r.cf, { made: helpers, deleted: helpers }, `${job}: use failed, every helper made and still deleted`);
    }
    {
      const { vault, cf } = await fresh();
      cf.rules.push({ method: "DELETE", path: /tokens\//, times: 9, respond: fail(500) });
      assert.equal((await read(vault, job)).cf, "unknown", `${job}: delete failed`);
    }
  }
});

test("E1.1 headcount setup: mint refused -> empty lists; list fails -> the new key made and deleted; must-fail mint 500 -> unknown", async () => {
  {
    const { vault, cf } = await fresh();
    cf.rules.push({ method: "POST", path: /tokens$/, respond: fail(403) });
    const r = await run(vault, "cf.token.headcount.setup");
    assert.equal(r.ok, false);
    assert.deepEqual(r.cf, { made: [], deleted: [] });
  }
  {
    const { vault, cf } = await fresh();
    cf.rules.push({ method: "GET", path: /tokens\?/, respond: fail(500) });
    const r = await run(vault, "cf.token.headcount.setup");
    assert.equal(r.ok, false);
    assert.deepEqual(r.cf, { made: [r.key_id], deleted: [r.key_id] }, "a key that could not list is deleted, and both are named");
  }
  {
    const { vault, cf } = await fresh();
    let posts = 0;
    cf.rules.push({ method: "POST", path: /tokens$/, times: 2, respond: (realCall) => (++posts === 1 ? realCall() : fail(500)()) });
    const r = await run(vault, "cf.token.headcount.setup");
    assert.equal(r.ok, false);
    assert.equal(r.cf, "unknown", "a 500 on the must-fail mint may have made a key");
  }
});

test("E1.1 sweepIssued: an expired handed-out key deleted is listed; a refused 404 is not; a 500 is unknown", async () => {
  const old = hexId(0xc1);
  const cases: [string, Rule | undefined, unknown][] = [
    ["deleted", undefined, "listed"],
    ["404", { method: "DELETE", path: /c1$/, respond: fail(404) }, "closed"],
    ["500", { method: "DELETE", path: /c1$/, respond: fail(500) }, "unknown"],
  ];
  for (const [label, rule, want] of cases) {
    for (const job of ["cf.zone.read", "cf.token.headcount.setup"]) {
      const { vault, cf, store } = await fresh();
      cf.tokens.push({ id: old });
      await store.put("master", { ...(await store.get<any>("master")), issued: [{ id: old, expires_on: "2026-11-13T11:00:00Z" }] });
      if (rule) cf.rules.push({ ...rule }); // a fresh copy: a rule counts down its own uses
      const r = job === "cf.zone.read" ? await read(vault, job) : await run(vault, job);
      if (want === "unknown") {
        assert.equal(r.cf, "unknown", `${job} ${label}`);
        continue;
      }
      // Exact lists: the read makes and deletes two helpers (0x101, 0x102); headcount setup makes one key (0x101).
      const own = job === "cf.zone.read" ? { made: [hexId(0x101), hexId(0x102)], deleted: [hexId(0x101), hexId(0x102)] } : { made: [hexId(0x101)], deleted: [] };
      const swept = want === "listed" ? [old] : [];
      assert.deepEqual(r.cf, { made: own.made, deleted: [...swept, ...own.deleted] }, `${job} ${label}`);
    }
  }
});
