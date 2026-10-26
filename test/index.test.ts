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
