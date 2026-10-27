import { generateKeyPairSync } from "node:crypto";
// @ts-ignore -- plain JS client, tested here as the c-box runs it
import { signRequest } from "../scripts/agent.mjs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { callerOf, route, VERSION, type Caller } from "../src/routes.ts";
import { Desk, MemoryStore } from "../src/desk.ts";
import { SoftKey } from "./softkey.ts";

const base = "https://desk.example";
// Each route gets the caller it needs, as the Worker would after Access (index.ts).
const callerFor = (path: string, init?: RequestInit): Caller =>
  path.startsWith("/request") || path.startsWith("/collect") ? "agent" : "owner";
const call = (store: MemoryStore, path: string, init?: RequestInit, caller = callerFor(path, init)) =>
  route(new Request(base + path, init), store, { caller, requester: caller === "agent" ? AGENT : undefined });
const AGENT = "c-box agent (test)";

test("health answers with the version", async () => {
  const res = await call(new MemoryStore(), "/health");
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, version: VERSION });
});

test("unknown paths are 404", async () => {
  assert.equal((await call(new MemoryStore(), "/")).status, 404);
  assert.equal((await call(new MemoryStore(), "/health", { method: "POST" })).status, 404);
});

test("every response says do not index, do not cache, no framing", async () => {
  for (const path of ["/health", "/nope", "/log", "/enroll"]) {
    const res = await call(new MemoryStore(), path);
    assert.equal(res.headers.get("x-robots-tag"), "noindex, nofollow");
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.match(res.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  }
});

test("approval page refuses until a passkey is enrolled", async () => {
  const store = new MemoryStore();
  const res = await call(store, "/request", { method: "POST", body: JSON.stringify({ job: "test.echo", params: { word: "hi" }, reason: "x" }) });
  const { id } = (await res.json()) as { id: string };
  assert.equal((await call(store, `/approve/${id}`)).status, 409);
});

test("over HTTP: enroll, ask, approve, collect; page shows stored grant, quotes agent escaped", async () => {
  const store = new MemoryStore();
  const key = await SoftKey.create();
  const enrollHtml = await (await call(store, "/enroll")).text();
  const regOpts = JSON.parse(enrollHtml.match(/const opts=(\{.*?\});\n/)![1]);
  const reg = await call(store, "/enroll", { method: "POST", body: JSON.stringify(await key.register(regOpts, base)) });
  assert.equal(reg.status, 200);
  const reason = "<script>alert(1)</script> please";
  const asked = await call(store, "/request", { method: "POST", body: JSON.stringify({ job: "test.echo", params: { word: "hi" }, reason }) });
  const { id } = (await asked.json()) as { id: string };
  const pageHtml = await (await call(store, `/approve/${id}`)).text();
  assert.ok(pageHtml.includes('Test only: echo the word &quot;hi&quot;'));
  assert.ok(pageHtml.includes("&lt;script&gt;alert(1)&lt;/script&gt; please"));
  assert.ok(!pageHtml.includes("<script>alert(1)"));
  const opts = JSON.parse(pageHtml.match(/const opts=(\{.*?\});\n/)![1]);
  const ok = await call(store, `/approve/${id}`, { method: "POST", body: JSON.stringify(await key.assert(opts.challenge, "desk.example", base)) });
  assert.equal(ok.status, 200);
  const c = await call(store, `/collect/${id}`, { method: "POST" });
  assert.deepEqual(await c.json(), { ok: true, result: { echoed: "hi" } });
});

test("collect before approval is refused over HTTP too", async () => {
  const store = new MemoryStore();
  const res = await call(store, "/request", { method: "POST", body: JSON.stringify({ job: "test.echo", params: { word: "hi" }, reason: "x" }) });
  const { id } = (await res.json()) as { id: string };
  const c = await call(store, `/collect/${id}`, { method: "POST" });
  assert.equal(c.status, 403);
  assert.deepEqual(await c.json(), { error: "not_approved" });
});

test("agent text is escaped on the log page", async () => {
  const store = new MemoryStore();
  await call(store, "/request", { method: "POST", body: JSON.stringify({ job: "test.echo", params: { word: "hi" }, reason: "<img src=x onerror=alert(1)>" }) });
  const body = await (await call(store, "/log")).text();
  assert.ok(!body.includes("<img src=x"));
  assert.ok(body.includes("&lt;img src=x"));
});

test("owner routes refuse the agent and unknown callers, and log it", async () => {
  const store = new MemoryStore();
  for (const caller of ["agent", "unknown"] as const) {
    for (const [path, init] of [["/enroll"], ["/enroll", { method: "POST", body: "{}" }], ["/log"], ["/approve/x"], ["/approve/x", { method: "POST", body: "{}" }]] as [string, RequestInit?][]) {
      const res = await call(store, path, init, caller);
      assert.equal(res.status, 403, `${caller} ${path}`);
      assert.deepEqual(await res.json(), { error: "not_owner" });
    }
  }
  const log = await new Desk(store, { origin: base, rpID: "desk.example" }).readLog();
  assert.equal(log.filter((e) => e.event === "refused" && /needs owner/.test(e.detail ?? "")).length, 10);
});

test("agent routes refuse Ben and unknown callers", async () => {
  for (const caller of ["owner", "unknown"] as const) {
    const asked = await call(new MemoryStore(), "/request", { method: "POST", body: JSON.stringify({ job: "test.echo", params: { word: "hi" }, reason: "x" }) }, caller);
    assert.equal(asked.status, 403);
    assert.deepEqual(await asked.json(), { error: "not_agent" });
    assert.equal((await call(new MemoryStore(), "/collect/x", { method: "POST" }, caller)).status, 403);
  }
});

test("health needs no caller", async () => {
  assert.equal((await call(new MemoryStore(), "/health", undefined, "unknown")).status, 200);
});

const access = (identity: unknown): ExecutionContext["access"] => ({
  aud: "test-aud",
  getIdentity: async () => {
    if (identity instanceof Error) throw identity;
    return identity as CloudflareAccessIdentity | undefined;
  },
});

test("owner only when Access signed in OWNER_EMAIL", async () => {
  assert.equal(await callerOf(access({ email: " Ben@Example.com " }), "ben@example.com"), "owner");
  assert.equal(await callerOf(access({ email: "someone@example.com" }), "ben@example.com"), "unknown");
  assert.equal(await callerOf(undefined, "ben@example.com"), "unknown", "no Access login");
  assert.equal(await callerOf(access({ email: "ben@example.com" }), undefined), "unknown", "OWNER_EMAIL unset");
  assert.equal(await callerOf(access({ email: "" }), ""), "unknown", "both empty");
  assert.equal(await callerOf(access(undefined), "ben@example.com"), "unknown", "no identity, e.g. a service token");
  assert.equal(await callerOf(access({ common_name: "abc.access" }), "ben@example.com"), "unknown");
  assert.equal(await callerOf(access(new Error("down")), "ben@example.com"), "unknown");
});

test("caller refusals are bounded: 20 log rows a day plus one notice, the rest only counted", async () => {
  const store = new MemoryStore();
  for (let i = 0; i < 25; i++) assert.equal((await call(store, "/log", undefined, "unknown")).status, 403);
  const desk = new Desk(store, { origin: base, rpID: "desk.example" });
  const rows = (await desk.readLog()).filter((e) => e.event === "refused");
  assert.equal(rows.length, 21);
  assert.match(rows[20].detail ?? "", /more caller refusals today/);
  assert.deepEqual([...(await desk.refusalCounts()).values()], [25]);
});

test("garbled passkey answers are refused and logged, not a server error", async () => {
  const store = new MemoryStore();
  for (const path of ["/enroll", "/approve/x"]) {
    const res = await call(store, path, { method: "POST", body: "not json" });
    assert.equal(res.status, 400, path);
    assert.deepEqual(await res.json(), { error: "bad_json" });
  }
  const details = (await new Desk(store, { origin: base, rpID: "desk.example" }).readLog()).map((e) => e.detail);
  assert.deepEqual(details, ["enroll: bad_json", "approve: bad_json"]);
});

test("a synchronous throw from getIdentity still ends as unknown", async () => {
  const bad = { aud: "x", getIdentity: () => { throw new Error("sync"); } } as unknown as ExecutionContext["access"];
  assert.equal(await callerOf(bad, "ben@example.com"), "unknown");
});

// PRF check (PR3b-2b step 1): Ben's passkey must give the same secret on every tap.
async function enrolled() {
  const store = new MemoryStore();
  const key = await SoftKey.create();
  const enrollHtml = await (await call(store, "/enroll")).text();
  const regOpts = JSON.parse(enrollHtml.match(/const opts=(\{.*?\});\n/)![1]);
  await call(store, "/enroll", { method: "POST", body: JSON.stringify(await key.register(regOpts, base)) });
  return { store, key };
}
const checkOpts = async (store: MemoryStore) =>
  JSON.parse((await (await call(store, "/prf-check")).text()).match(/const opts=(\{.*?\});\n/)![1]);
const prfOut = (fill: number) => Buffer.from(new Uint8Array(32).fill(fill)).toString("base64url");
const check = (store: MemoryStore, body: unknown) => call(store, "/prf-check", { method: "POST", body: JSON.stringify(body) });

test("PRF check: same secret twice gives the same fingerprint; a different secret does not", async () => {
  const { store, key } = await enrolled();
  const prints: string[] = [];
  for (const fill of [7, 7, 8]) {
    const opts = await checkOpts(store);
    const res = await check(store, { credential: await key.assert(opts.challenge, "desk.example", base), prf: prfOut(fill) });
    assert.equal(res.status, 200);
    prints.push(((await res.json()) as { fingerprint: string }).fingerprint);
  }
  assert.equal(prints[0], prints[1]);
  assert.notEqual(prints[0], prints[2]);
  const rows = (await new Desk(store, { origin: base, rpID: "desk.example" }).readLog()).filter((e) => e.event === "prf_check");
  assert.equal(rows.length, 3);
  assert.match(rows[0].detail!, new RegExp(`^PASS: fingerprint ${prints[0]}`));
});

test("PRF check: salt is the check label's hash, never shared with anything else", async () => {
  const { store } = await enrolled();
  const opts = await checkOpts(store);
  const want = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("front-desk prf-check v1"))).toString("base64url");
  assert.equal(opts.prfSalt, want);
});

test("PRF check: no PRF output is a logged FAIL with what the browser returned", async () => {
  const { store, key } = await enrolled();
  const opts = await checkOpts(store);
  const res = await check(store, { credential: await key.assert(opts.challenge, "desk.example", base), prf: null, prf_info: '["enabled"]' });
  assert.equal(res.status, 422);
  assert.deepEqual(await res.json(), { error: "prf_missing" });
  const log = await new Desk(store, { origin: base, rpID: "desk.example" }).readLog();
  assert.match(log.at(-1)!.detail!, /^FAIL: no usable PRF output \(\["enabled"\]\)/);
  // A PRF output must be 32 bytes; anything shorter is not one.
  const o2 = await checkOpts(store);
  const short = await check(store, { credential: await key.assert(o2.challenge, "desk.example", base), prf: Buffer.from(new Uint8Array(16)).toString("base64url") });
  assert.equal(short.status, 422);
});

test("PRF check: needs a valid passkey answer to its own one-time challenge", async () => {
  const { store, key } = await enrolled();
  // Replay of a used challenge.
  const opts = await checkOpts(store);
  const answer = await key.assert(opts.challenge, "desk.example", base);
  assert.equal((await check(store, { credential: answer, prf: prfOut(1) })).status, 200);
  assert.deepEqual(await (await check(store, { credential: answer, prf: prfOut(1) })).json(), { error: "challenge_used" });
  // A challenge made for an approval cannot be spent here.
  const asked = await call(store, "/request", { method: "POST", body: JSON.stringify({ job: "test.echo", params: { word: "hi" }, reason: "x" }) });
  const { id } = (await asked.json()) as { id: string };
  const aOpts = JSON.parse((await (await call(store, `/approve/${id}`)).text()).match(/const opts=(\{.*?\});\n/)![1]);
  const wrong = await check(store, { credential: await key.assert(aOpts.challenge, "desk.example", base), prf: prfOut(1) });
  assert.deepEqual(await wrong.json(), { error: "unknown_challenge" });
  // A passkey that is not enrolled.
  const stranger = await SoftKey.create();
  const o2 = await checkOpts(store);
  assert.deepEqual(await (await check(store, { credential: await stranger.assert(o2.challenge, "desk.example", base), prf: prfOut(1) })).json(), { error: "unknown_passkey" });
  // Garbage body.
  assert.deepEqual(await (await check(store, { prf: prfOut(1) })).json(), { error: "bad_response" });
});

test("PRF check: owner only", async () => {
  const { store } = await enrolled();
  for (const caller of ["agent", "unknown"] as const) {
    assert.equal((await call(store, "/prf-check", undefined, caller)).status, 403);
    assert.equal((await call(store, "/prf-check", { method: "POST", body: "{}" }, caller)).status, 403);
  }
});

// Vault jobs and master key setup (PR3b-2b step 2). A fake vault records what it is asked.
function fakeVault(stored = false) {
  const calls: { op: string; args: unknown[] }[] = [];
  return {
    calls,
    async status() {
      return stored ? { stored: true, pending: false, token_id: "t1" } : { stored: false, pending: false };
    },
    async run(job: string, params: Record<string, string>, prf: string) {
      calls.push({ op: "run", args: [job, params, prf] });
      return { ok: true, zone: "example.com", after: 0 } as any;
    },
  };
}
const callV = (store: MemoryStore, vault: ReturnType<typeof fakeVault>, path: string, init?: RequestInit, caller = callerFor(path, init)) =>
  route(new Request(base + path, init), store, { caller, requester: caller === "agent" ? AGENT : undefined }, Date.now(), vault);
const ZONE = "benculbert.com";
const optsIn = async (res: Response) => JSON.parse((await res.text()).match(/const opts=(\{.*?\});\n/)![1]);

async function askProbe(store: MemoryStore, vault: ReturnType<typeof fakeVault>) {
  const asked = await callV(store, vault, "/request", { method: "POST", body: JSON.stringify({ job: "cf.dns.txt.probe", params: { zone: ZONE }, reason: "prove the vault" }) });
  assert.equal(asked.status, 201);
  return ((await asked.json()) as { id: string }).id;
}

test("vault job: approval page asks for the master-key secret; the job runs once at approval", async () => {
  const { store, key } = await enrolled();
  const vault = fakeVault(true);
  const id = await askProbe(store, vault);
  const opts = await optsIn(await callV(store, vault, `/approve/${id}`));
  const salt = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("front-desk master-key v1"))).toString("base64url");
  assert.equal(opts.prfSalt, salt);
  const answer = { ...(await key.assert(opts.challenge, "desk.example", base)), prf: prfOut(5) };
  const ok = await callV(store, vault, `/approve/${id}`, { method: "POST", body: JSON.stringify(answer) });
  assert.equal(ok.status, 200);
  assert.deepEqual(((await ok.json()) as any).result, { ok: true, zone: "example.com", after: 0 });
  assert.deepEqual(vault.calls, [{ op: "run", args: ["cf.dns.txt.probe", { zone: ZONE }, prfOut(5)] }]);
  // Replaying the same answer runs nothing more.
  assert.equal((await callV(store, vault, `/approve/${id}`, { method: "POST", body: JSON.stringify(answer) })).status, 409);
  assert.equal(vault.calls.length, 1);
  const c = await callV(store, vault, `/collect/${id}`, { method: "POST" });
  assert.deepEqual(((await c.json()) as any).result, { ok: true, zone: "example.com", after: 0 });
  const events = (await new Desk(store, { origin: base, rpID: "desk.example" }).readLog()).map((e) => e.event);
  assert.deepEqual(events.slice(-5), ["requested", "approved", "job_done", "refused", "collected"]);
});

test("vault job: no passkey secret means not approved and the vault is never called", async () => {
  const { store, key } = await enrolled();
  const vault = fakeVault(true);
  const id = await askProbe(store, vault);
  const opts = await optsIn(await callV(store, vault, `/approve/${id}`));
  const res = await callV(store, vault, `/approve/${id}`, { method: "POST", body: JSON.stringify(await key.assert(opts.challenge, "desk.example", base)) });
  assert.deepEqual(await res.json(), { error: "prf_missing" });
  assert.equal(vault.calls.length, 0);
  assert.equal((await new Desk(store, { origin: base, rpID: "desk.example" }).grant(id)).status, "pending");
});

test("vault job: a zone not on the studio list is refused at the request", async () => {
  const { store } = await enrolled();
  for (const zone of ["example.com", "evil.benculbert.com", ""]) {
    const res = await callV(store, fakeVault(), "/request", { method: "POST", body: JSON.stringify({ job: "cf.dns.txt.probe", params: { zone }, reason: "r" }) });
    assert.deepEqual(await res.json(), { error: "bad_params" });
  }
});

test("vault job: a result that is not ok is logged as job_failed with the full evidence", async () => {
  const { store, key } = await enrolled();
  const vault = fakeVault(true);
  vault.run = async () => ({ ok: false, error: "token delete failed: x", minted: [{ id: "m1", deleted: false }] }) as any;
  const id = await askProbe(store, vault);
  const opts = await optsIn(await callV(store, vault, `/approve/${id}`));
  await callV(store, vault, `/approve/${id}`, { method: "POST", body: JSON.stringify({ ...(await key.assert(opts.challenge, "desk.example", base)), prf: prfOut(5) }) });
  const row = (await new Desk(store, { origin: base, rpID: "desk.example" }).readLog()).at(-1)!;
  assert.equal(row.event, "job_failed");
  assert.match(row.detail!, /"deleted":false/);
});

test("vault job: a collect while the vault is still working is refused, and the grant is collected once", async () => {
  const { store, key } = await enrolled();
  const vault = fakeVault(true);
  const id = await askProbe(store, vault);
  let during: Response | undefined;
  const run = vault.run.bind(vault);
  vault.run = async (...args) => {
    during = await callV(store, vault, `/collect/${id}`, { method: "POST" });
    return run(...args);
  };
  const opts = await optsIn(await callV(store, vault, `/approve/${id}`));
  const answer = { ...(await key.assert(opts.challenge, "desk.example", base)), prf: prfOut(5) };
  assert.equal((await callV(store, vault, `/approve/${id}`, { method: "POST", body: JSON.stringify(answer) })).status, 200);
  assert.deepEqual(await during!.json(), { error: "not_ready" });
  const first = await callV(store, vault, `/collect/${id}`, { method: "POST" });
  assert.equal(((await first.json()) as any).result.zone, "example.com");
  assert.deepEqual(await (await callV(store, vault, `/collect/${id}`, { method: "POST" })).json(), { error: "already_collected" });
});

// Minted key for the agent (PR3b-2b step 3), only for requests signed with the c-box key.
const SECRET = "S".repeat(40);
const CBOX = "203.0.113.7";
function cboxKey() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { pem: privateKey.export({ type: "pkcs8", format: "pem" }) as string, spki: publicKey.export({ type: "spki", format: "der" }).toString("base64url") };
}
type Signing = { pem?: string; ip?: string; time?: number; now?: number; headers?: Record<string, string> };
const agentPost = (store: MemoryStore, vault: ReturnType<typeof fakeVault>, path: string, body: unknown, o: Signing = {}) => {
  const text = JSON.stringify(body);
  const now = o.now ?? Date.now();
  const headers: Record<string, string> = { ...(o.ip ? { "cf-connecting-ip": o.ip } : {}), ...(o.pem ? signRequest(o.pem, "POST", path, text, o.time ?? now) : {}), ...o.headers };
  return route(new Request(base + path, { method: "POST", headers, body: text }), store, { caller: "agent", requester: AGENT }, now, vault);
};
const askKey = (store: MemoryStore, vault: ReturnType<typeof fakeVault>, params: Record<string, string>, o: Signing) =>
  agentPost(store, vault, "/request", { job: "cf.token.zone.read", params, reason: "read the zone" }, o);
async function approveAs(store: MemoryStore, vault: ReturnType<typeof fakeVault>, key: SoftKey, id: string, prf?: string) {
  const opts = await optsIn(await callV(store, vault, `/approve/${id}`));
  const answer = { ...(await key.assert(opts.challenge, "desk.example", base)), ...(prf ? { prf } : {}) };
  return callV(store, vault, `/approve/${id}`, { method: "POST", body: JSON.stringify(answer) });
}
async function askEnroll(store: MemoryStore, spki: string) {
  const res = await agentPost(store, fakeVault(true), "/request", { job: "cbox.key.enroll", params: { key: spki }, reason: "new c-box key" });
  assert.equal(res.status, 201);
  return ((await res.json()) as { id: string }).id;
}
async function withCboxKey() {
  const e = await enrolled();
  const k = cboxKey();
  const ok = await approveAs(e.store, fakeVault(true), e.key, await askEnroll(e.store, k.spki));
  assert.equal(ok.status, 200);
  return { ...e, cbox: k };
}
const desk = (store: MemoryStore) => new Desk(store, { origin: base, rpID: "desk.example" });

test("c-box key: Ben enrolls it by Face ID; the screen shows its fingerprint and when to say no", async () => {
  const { store, key } = await enrolled();
  const k = cboxKey();
  const id = await askEnroll(store, k.spki);
  const fp = (await desk(store).grant(id)).params.fingerprint;
  assert.match(fp, /^([0-9a-f]{4}-){3}[0-9a-f]{4}$/);
  const page = await (await callV(store, fakeVault(true), `/approve/${id}`)).text();
  assert.match(page, new RegExp(`fingerprint ${fp}\\. Requests signed`));
  assert.match(page, /Only approve if the agent just showed you this same fingerprint/);
  assert.equal((await approveAs(store, fakeVault(true), key, id)).status, 200);
  assert.equal((await desk(store).cboxKey())!.fingerprint, fp);
  assert.ok(!(await (await callV(store, fakeVault(true), "/cbox-key")).text()).includes("No c-box key"));
  // Not a P-256 public key: refused at the request.
  for (const bad of ["x", "A".repeat(122), Buffer.alloc(91).toString("base64url")]) {
    const r = await agentPost(store, fakeVault(true), "/request", { job: "cbox.key.enroll", params: { key: bad }, reason: "r" });
    assert.deepEqual(await r.json(), { error: "bad_params" });
  }
});

test("c-box key: one enrollment waits at a time; one asked before a removal (or any other change) is refused as stale", async () => {
  const { store, key, cbox } = await withCboxKey();
  const old = (await desk(store).cboxKey())!.fingerprint;
  const a = await askEnroll(store, cboxKey().spki);
  assert.match(await (await callV(store, fakeVault(true), `/approve/${a}`)).text(), new RegExp(`REPLACING key ${old}`));
  const again = await agentPost(store, fakeVault(true), "/request", { job: "cbox.key.enroll", params: { key: cboxKey().spki }, reason: "r" });
  assert.deepEqual(await again.json(), { error: "enroll_pending" });
  // Ben removes the key, so "a" was asked about a state that no longer exists.
  await callV(store, fakeVault(true), "/cbox-key", { method: "POST", headers: { origin: base } });
  assert.deepEqual(await (await approveAs(store, fakeVault(true), key, a)).json(), { error: "stale_enroll" });
  assert.equal(await desk(store).cboxKey(), undefined);
  // enroll -> remove -> none again: an old request made when there was no key is still stale.
  const e = await enrolled();
  const first = await askEnroll(e.store, cboxKey().spki);
  // (expire the first so a second may be asked)
  const g = await desk(e.store).grant(first);
  await e.store.put(`grant:${first}`, { ...g, expires_at: 0 });
  const second = await askEnroll(e.store, cboxKey().spki);
  await e.store.put(`grant:${first}`, g);
  assert.equal((await approveAs(e.store, fakeVault(true), e.key, second)).status, 200);
  await callV(e.store, fakeVault(true), "/cbox-key", { method: "POST", headers: { origin: base } });
  assert.deepEqual(await (await approveAs(e.store, fakeVault(true), e.key, first)).json(), { error: "stale_enroll" });
  void cbox;
});

test("requests waiting for Ben are capped per requester", async () => {
  const { store, cbox } = await withCboxKey();
  for (let i = 0; i < 3; i++) assert.equal((await askKey(store, fakeVault(true), { zone: ZONE, minutes: "5" }, { ip: CBOX, pem: cbox.pem })).status, 201);
  assert.deepEqual(await (await askKey(store, fakeVault(true), { zone: ZONE, minutes: "5" }, { ip: CBOX, pem: cbox.pem })).json(), { error: "too_many_pending" });
});

test("minted key: a key request from before Ben removed or replaced the c-box key cannot be approved or collected", async () => {
  const { store, key, cbox } = await withCboxKey();
  const vault = fakeVault(true);
  vault.run = async () => ({ ok: true, zone: ZONE, key: { id: "k1", expires_on: "x", ip: CBOX, value: SECRET } }) as any;
  // Approve after removal: refused, the vault is never called.
  const { id } = (await (await askKey(store, vault, { zone: ZONE, minutes: "5" }, { ip: CBOX, pem: cbox.pem })).json()) as { id: string };
  await callV(store, vault, "/cbox-key", { method: "POST", headers: { origin: base } });
  assert.deepEqual(await (await approveAs(store, vault, key, id, prfOut(5))).json(), { error: "cbox_key_changed" });
  // Removal while the vault is minting: the secret is dropped, never stored or collected.
  const k2 = cboxKey();
  assert.equal((await approveAs(store, vault, key, await askEnroll(store, k2.spki))).status, 200);
  const { id: id2 } = (await (await askKey(store, vault, { zone: ZONE, minutes: "5" }, { ip: CBOX, pem: k2.pem })).json()) as { id: string };
  vault.run = async () => {
    await callV(store, vault, "/cbox-key", { method: "POST", headers: { origin: base } });
    return { ok: true, zone: ZONE, key: { id: "k2", expires_on: "x", ip: CBOX, value: SECRET } } as any;
  };
  await approveAs(store, vault, key, id2, prfOut(5));
  assert.ok(!JSON.stringify(await desk(store).grant(id2)).includes(SECRET), "dropped");
  // Replaced after approval: the new key cannot collect the old grant.
  const k3 = cboxKey();
  assert.equal((await approveAs(store, vault, key, await askEnroll(store, k3.spki))).status, 200);
  assert.deepEqual(await (await agentPost(store, vault, `/collect/${id2}`, {}, { ip: CBOX, pem: k3.pem })).json(), { error: "cbox_key_changed" });
});

test("minted key: two signed collects at the same moment -- only one gets the secret (Codex architecture r2)", async () => {
  const { store, key, cbox } = await withCboxKey();
  const vault = fakeVault(true);
  vault.run = async () => ({ ok: true, zone: ZONE, key: { id: "k1", expires_on: "x", ip: CBOX, value: SECRET } }) as any;
  const { id } = (await (await askKey(store, vault, { zone: ZONE, minutes: "5" }, { ip: CBOX, pem: cbox.pem })).json()) as { id: string };
  await approveAs(store, vault, key, id, prfOut(5));
  const both = await Promise.all([1, 2].map((n) => agentPost(store, vault, `/collect/${id}`, { n }, { ip: CBOX, pem: cbox.pem }).then((r) => r.text())));
  assert.equal(both.filter((t) => t.includes(SECRET)).length, 1, both.join(" | "));
});

test("c-box key: a key request is refused unsigned, with another key, too old, replayed, or before any key is enrolled -- each logged", async () => {
  const e = await enrolled();
  const params = { zone: ZONE, minutes: "5" };
  assert.deepEqual(await (await askKey(e.store, fakeVault(true), params, { ip: CBOX, pem: cboxKey().pem })).json(), { error: "no_cbox_key" });
  const { store, cbox } = await withCboxKey();
  const now = Date.now();
  const cases: [Signing, string][] = [
    [{ ip: CBOX }, "not_signed"],
    [{ ip: CBOX, pem: cboxKey().pem }, "bad_signature"],
    [{ ip: CBOX, pem: cbox.pem, time: now - 61_000, now }, "signature_expired"],
    [{ ip: CBOX, pem: cbox.pem, time: now + 61_000, now }, "signature_expired"],
  ];
  for (const [o, error] of cases) assert.deepEqual(await (await askKey(store, fakeVault(true), params, o)).json(), { error }, error);
  // The same signed request twice (a captured copy) is refused, and so is a copy whose signature was
  // altered into another valid one (ECDSA malleability: s -> n - s).
  const body = { job: "cf.token.zone.read", params, reason: "read the zone" };
  const sig = signRequest(cbox.pem, "POST", "/request", JSON.stringify(body), now);
  assert.equal((await agentPost(store, fakeVault(true), "/request", body, { ip: CBOX, headers: sig, now })).status, 201);
  assert.deepEqual(await (await agentPost(store, fakeVault(true), "/request", body, { ip: CBOX, headers: sig, now })).json(), { error: "signature_replayed" });
  const raw = Buffer.from(sig["x-cbox-signature"], "base64url");
  const n = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
  const flipped = Buffer.concat([raw.subarray(0, 32), Buffer.from((n - BigInt("0x" + raw.subarray(32).toString("hex"))).toString(16).padStart(64, "0"), "hex")]);
  const twin = { ...sig, "x-cbox-signature": flipped.toString("base64url") };
  assert.deepEqual(await (await agentPost(store, fakeVault(true), "/request", body, { ip: CBOX, headers: twin, now })).json(), { error: "signature_replayed" });
  // A signature over another body does not carry over.
  const other = signRequest(cbox.pem, "POST", "/request", JSON.stringify({ job: "cf.token.zone.read", params: { zone: ZONE, minutes: "1" }, reason: "read the zone" }));
  assert.deepEqual(await (await askKey(store, fakeVault(true), params, { ip: CBOX, headers: other })).json(), { error: "bad_signature" });
  const details = (await desk(store).readLog()).filter((l) => l.event === "refused").map((l) => l.detail);
  for (const code of ["not_signed", "bad_signature", "signature_expired", "signature_replayed"]) {
    assert.ok(details.includes(`cf.token.zone.read: ${code}`), code);
  }
});

test("minted key: pinned to the address Cloudflare saw, not one the agent names; Ben sees it on the approval screen", async () => {
  const { store, cbox } = await withCboxKey();
  const res = await askKey(store, fakeVault(true), { zone: ZONE, minutes: "10", ip: "198.51.100.66" }, { ip: CBOX, pem: cbox.pem });
  assert.equal(res.status, 201);
  const { id } = (await res.json()) as { id: string };
  assert.deepEqual((await desk(store).grant(id)).params, { zone: ZONE, minutes: "10", ip: CBOX });
  const page = await (await callV(store, fakeVault(true), `/approve/${id}`)).text();
  assert.match(page, /TEST key/);
  assert.match(page, /not its DNS, not its settings/);
  assert.match(page, /expires after 10 minutes and works only from the c-box \(203\.0\.113\.7\)/);
});

test("minted key: refused over 15 minutes, for another zone, or with no usable address", async () => {
  const { store, cbox } = await withCboxKey();
  for (const [params, ip] of [
    [{ zone: ZONE, minutes: "16" }, CBOX],
    [{ zone: ZONE, minutes: "015" }, CBOX],
    [{ zone: "example.com", minutes: "5" }, CBOX],
    [{ zone: ZONE, minutes: "5" }, "2001:db8::1"],
    [{ zone: ZONE, minutes: "5" }, undefined],
  ] as const) {
    assert.deepEqual(await (await askKey(store, fakeVault(true), params, { ip, pem: cbox.pem })).json(), { error: "bad_params" }, JSON.stringify([params, ip]));
  }
});

test("minted key: the secret reaches only a signed collect from the pinned address, once, never Ben's screen or the log", async () => {
  const { store, key, cbox } = await withCboxKey();
  const vault = fakeVault(true);
  vault.run = async () => ({ ok: true, zone: ZONE, key: { id: "k1", expires_on: "2026-10-27T03:00:00Z", ip: CBOX, value: SECRET } }) as any;
  const { id } = (await (await askKey(store, vault, { zone: ZONE, minutes: "10" }, { ip: CBOX, pem: cbox.pem })).json()) as { id: string };
  const shown = await (await approveAs(store, vault, key, id, prfOut(5))).text();
  assert.ok(!shown.includes(SECRET), "not on Ben's screen");
  assert.match(shown, /"id":"k1"/);
  assert.deepEqual(await (await agentPost(store, vault, `/collect/${id}`, {}, { ip: CBOX })).json(), { error: "not_signed" });
  assert.deepEqual(await (await agentPost(store, vault, `/collect/${id}`, {}, { ip: "198.51.100.66", pem: cbox.pem })).json(), { error: "address_changed" });
  const got = (await (await agentPost(store, vault, `/collect/${id}`, {}, { ip: CBOX, pem: cbox.pem })).json()) as any;
  assert.equal(got.result.key.value, SECRET, "the agent gets it");
  assert.ok(!JSON.stringify(await desk(store).readLog()).includes(SECRET), "never logged");
  assert.ok(!JSON.stringify(await desk(store).grant(id)).includes(SECRET), "erased from storage after collect");
  assert.deepEqual(await (await agentPost(store, vault, `/collect/${id}`, {}, { ip: CBOX, pem: cbox.pem })).json(), { error: "already_collected" });
});

test("minted key: a secret nobody collects is erased once the collect window has passed", async () => {
  const { store, key, cbox } = await withCboxKey();
  const vault = fakeVault(true);
  vault.run = async () => ({ ok: true, zone: ZONE, key: { id: "k1", expires_on: "x", ip: CBOX, value: SECRET } }) as any;
  const { id } = (await (await askKey(store, vault, { zone: ZONE, minutes: "5" }, { ip: CBOX, pem: cbox.pem })).json()) as { id: string };
  await approveAs(store, vault, key, id, prfOut(5));
  assert.ok(JSON.stringify(await desk(store).grant(id)).includes(SECRET), "held for the agent meanwhile");
  assert.ok((await store.list({ prefix: "sig:" })).size > 0);
  const later = Date.now() + 6 * 60_000;
  await askKey(store, vault, { zone: ZONE, minutes: "5" }, { ip: CBOX, pem: cbox.pem, now: later, time: later });
  assert.ok(!JSON.stringify(await desk(store).grant(id)).includes(SECRET), "erased at the next request after the window");
  assert.equal((await store.list({ prefix: "sig:" })).size, 1, "old signed messages dropped; only the newest is kept");
});

test("c-box key: Ben removes it from his phone (lost or stolen box); then every key request is refused", async () => {
  const { store, cbox } = await withCboxKey();
  const v = fakeVault(true);
  assert.equal((await callV(store, v, "/cbox-key", { method: "POST", headers: { origin: "https://evil.example" } })).status, 403);
  assert.equal((await callV(store, v, "/cbox-key", { method: "POST" }, "agent")).status, 403, "the agent cannot remove or read it");
  const gone = await callV(store, v, "/cbox-key", { method: "POST", headers: { origin: base } });
  assert.equal(gone.status, 200);
  assert.match(await (await callV(store, v, "/cbox-key")).text(), /No c-box key is enrolled/);
  assert.deepEqual(await (await askKey(store, v, { zone: ZONE, minutes: "5" }, { ip: CBOX, pem: cbox.pem })).json(), { error: "no_cbox_key" });
  assert.ok((await desk(store).readLog()).some((l) => l.event === "cbox_key_removed"));
});

test("c-box key: removed while a signature is being checked -- the request is still refused", async () => {
  const { store, cbox } = await withCboxKey();
  let reads = 0;
  const racing = Object.create(store) as MemoryStore;
  racing.get = async <T,>(k: string) => (k === "cbox:key" && ++reads > 1 ? (null as T) : store.get<T>(k));
  const res = await askKey(racing, fakeVault(true), { zone: ZONE, minutes: "5" }, { ip: CBOX, pem: cbox.pem });
  assert.deepEqual(await res.json(), { error: "no_cbox_key" });
});
