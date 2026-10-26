import { test } from "node:test";
import assert from "node:assert/strict";
import { handle, VERSION } from "../src/index.ts";

test("health answers with the version", async () => {
  const res = handle(new Request("https://fd.example/health"));
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, version: VERSION });
});

test("anything else is 404", () => {
  assert.equal(handle(new Request("https://fd.example/")).status, 404);
  assert.equal(handle(new Request("https://fd.example/health", { method: "POST" })).status, 404);
});

test("every response says do not index and do not cache", () => {
  for (const path of ["/health", "/nope"]) {
    const res = handle(new Request("https://fd.example" + path));
    assert.equal(res.headers.get("x-robots-tag"), "noindex, nofollow");
    assert.equal(res.headers.get("cache-control"), "no-store");
  }
});
