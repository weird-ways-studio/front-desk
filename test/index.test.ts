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
      return stored ? { stored: true, token_id: "t1" } : { stored: false };
    },
    async setup(prf: string, parent: string) {
      calls.push({ op: "setup", args: [prf, parent] });
      if (parent === "bad") throw new Error("not_a_token");
      stored = true;
      return { token_id: "t1", recovery_key: "aaaa-bbbb" };
    },
    async run(job: string, params: Record<string, string>, prf: string) {
      calls.push({ op: "run", args: [job, params, prf] });
      return { zone: "example.com", after: 0, minted_token_deleted: true } as any;
    },
  };
}
const callV = (store: MemoryStore, vault: ReturnType<typeof fakeVault>, path: string, init?: RequestInit, caller = callerFor(path, init)) =>
  route(new Request(base + path, init), store, { caller, requester: caller === "agent" ? AGENT : undefined }, Date.now(), vault);
const ZONE_ID = "b".repeat(32);
const optsIn = async (res: Response) => JSON.parse((await res.text()).match(/const opts=(\{.*?\});\n/)![1]);

async function askProbe(store: MemoryStore, vault: ReturnType<typeof fakeVault>) {
  const asked = await callV(store, vault, "/request", { method: "POST", body: JSON.stringify({ job: "cf.dns.txt.probe", params: { zone_id: ZONE_ID }, reason: "prove the vault" }) });
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
  assert.deepEqual(((await ok.json()) as any).result, { zone: "example.com", after: 0, minted_token_deleted: true });
  assert.deepEqual(vault.calls, [{ op: "run", args: ["cf.dns.txt.probe", { zone_id: ZONE_ID }, prfOut(5)] }]);
  // Replaying the same answer runs nothing more.
  assert.equal((await callV(store, vault, `/approve/${id}`, { method: "POST", body: JSON.stringify(answer) })).status, 409);
  assert.equal(vault.calls.length, 1);
  const c = await callV(store, vault, `/collect/${id}`, { method: "POST" });
  assert.deepEqual(((await c.json()) as any).result, { zone: "example.com", after: 0, minted_token_deleted: true });
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

test("vault job: a bad zone id is refused at the request", async () => {
  const { store } = await enrolled();
  const res = await callV(store, fakeVault(), "/request", { method: "POST", body: JSON.stringify({ job: "cf.dns.txt.probe", params: { zone_id: "x" }, reason: "r" }) });
  assert.deepEqual(await res.json(), { error: "bad_params" });
});

test("master key setup: owner and passkey with secret; token goes to the vault; paper key returned once", async () => {
  const { store, key } = await enrolled();
  const vault = fakeVault();
  assert.equal((await callV(store, vault, "/setup-master", undefined, "agent")).status, 403);
  const opts = await optsIn(await callV(store, vault, "/setup-master"));
  const salt = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("front-desk master-key v1"))).toString("base64url");
  assert.equal(opts.prfSalt, salt);
  const res = await callV(store, vault, "/setup-master", {
    method: "POST",
    body: JSON.stringify({ ...(await key.assert(opts.challenge, "desk.example", base)), prf: prfOut(5), parent: "tok" }),
  });
  assert.deepEqual(await res.json(), { ok: true, token_id: "t1", recovery_key: "aaaa-bbbb" });
  assert.deepEqual(vault.calls, [{ op: "setup", args: [prfOut(5), "tok"] }]);
  const log = await new Desk(store, { origin: base, rpID: "desk.example" }).readLog();
  assert.equal(log.at(-1)!.event, "master_key_stored");
  assert.ok(!JSON.stringify(log).includes("aaaa-bbbb"), "the paper key is never logged");
  assert.deepEqual(await (await callV(store, vault, "/setup-master")).json(), { error: "already_stored" });
});

test("master key setup refuses: no secret, a stranger's passkey, a vault refusal (logged)", async () => {
  const { store, key } = await enrolled();
  const vault = fakeVault();
  const post = async (body: (challenge: string) => Promise<unknown>) => {
    const opts = await optsIn(await callV(store, vault, "/setup-master"));
    return callV(store, vault, "/setup-master", { method: "POST", body: JSON.stringify(await body(opts.challenge)) });
  };
  assert.deepEqual(await (await post(async (ch) => key.assert(ch, "desk.example", base))).json(), { error: "prf_missing" });
  const stranger = await SoftKey.create();
  assert.deepEqual(await (await post(async (ch) => ({ ...(await stranger.assert(ch, "desk.example", base)), prf: prfOut(5), parent: "tok" }))).json(), { error: "unknown_passkey" });
  assert.equal(vault.calls.length, 0);
  assert.deepEqual(await (await post(async (ch) => ({ ...(await key.assert(ch, "desk.example", base)), prf: prfOut(5), parent: "bad" }))).json(), { error: "not_a_token" });
  const log = await new Desk(store, { origin: base, rpID: "desk.example" }).readLog();
  assert.match(log.at(-1)!.detail!, /^master key setup: not_a_token/);
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
