import { test } from "node:test";
import assert from "node:assert/strict";
import { route, VERSION } from "../src/routes.ts";
import { MemoryStore } from "../src/desk.ts";
import { SoftKey } from "./softkey.ts";

const base = "https://desk.example";
const call = (store: MemoryStore, path: string, init?: RequestInit) => route(new Request(base + path, init), store);

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
