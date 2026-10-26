import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { MemoryStore } from "../src/desk.ts";
import { MASTER_LABEL, RECOVERY_LABEL, open, seal, b64url, fromB64url } from "../vault/src/seal.ts";
import { PROBE_TOKEN_MS, VaultLogic } from "../vault/src/vault.ts";

const ACCOUNT = "a".repeat(32);
const ZONE_ID = "b".repeat(32);
const ZONE = "benculbert.com";
const PARENT = "P".repeat(40);
const NOW = Date.UTC(2026, 9, 26, 23, 0, 0);
const prf = (fill: number) => b64url(new Uint8Array(32).fill(fill));
type Fail = "accounts2" | "accounts0" | "inactive" | "existing" | "add" | "verifyRead" | "recordDelete" | "tokenDelete" | "list" | "newToken" | "staysListed";

// A fake Cloudflare API: answers the calls the vault makes and records each with the token used.
// `fail` makes one step go wrong, to show what the vault does then.
function fakeCloudflare(fail?: Fail, baseline = 3) {
  const calls: { method: string; path: string; token: string; body?: any }[] = [];
  let records: { id: string }[] = fail === "existing" ? [{ id: "old" }] : [];
  const tokens = Array.from({ length: baseline }, (_, i) => ({ id: `t${i}` }));
  const live = new Map<string, string>(); // minted value -> id
  let n = 0;
  let finds = 0;
  const ok = (result: unknown) => Response.json({ success: true, result });
  const bad = (status: number, message: string) => Response.json({ success: false, errors: [{ message }] }, { status });
  const fetchFn = async (input: string, init?: RequestInit) => {
    const url = new URL(input);
    const path = url.pathname.replace("/client/v4", "") + url.search;
    const method = init?.method ?? "GET";
    const token = String((init?.headers as Record<string, string>).authorization).replace("Bearer ", "");
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path, token, body });
    if (path === "/accounts") return ok(fail === "accounts0" ? [] : fail === "accounts2" ? [{ id: ACCOUNT }, { id: "c".repeat(32) }] : [{ id: ACCOUNT }]);
    if (path === `/accounts/${ACCOUNT}/tokens/verify`) return ok({ id: "t0", status: fail === "inactive" ? "disabled" : "active" });
    if (path === `/accounts/${ACCOUNT}/tokens/permission_groups`)
      return ok([
        { id: "dns-w", name: "DNS Write", scopes: ["com.cloudflare.api.account.zone"] },
        { id: "zone-r", name: "Zone Read", scopes: ["com.cloudflare.api.account.zone"] },
        { id: "acct-dns", name: "DNS Write", scopes: ["com.cloudflare.api.account"] },
      ]);
    if (method === "POST" && path === `/accounts/${ACCOUNT}/tokens`) {
      const id = `minted${++n}`;
      tokens.push({ id });
      live.set(`V${n}`.padEnd(40, "v"), id);
      return ok({ id, value: `V${n}`.padEnd(40, "v") });
    }
    if (method === "DELETE" && path.startsWith(`/accounts/${ACCOUNT}/tokens/`)) {
      if (fail === "tokenDelete") return bad(500, "delete broke");
      const id = path.split("/").pop()!;
      tokens.splice(tokens.findIndex((t) => t.id === id), 1);
      return ok({ id });
    }
    if (path.startsWith(`/accounts/${ACCOUNT}/tokens?`)) {
      if (fail === "list" && n > 0) return bad(500, "list broke");
      const page = Number(url.searchParams.get("page"));
      const per = Number(url.searchParams.get("per_page"));
      const all = fail === "newToken" && n > 0 ? [...tokens, { id: "surprise" }] : tokens;
      return ok(all.slice((page - 1) * per, page * per));
    }
    if (path === `/zones?name=${ZONE}`) return ok([{ id: ZONE_ID, name: ZONE }]);
    if (method === "GET" && path.startsWith(`/zones/${ZONE_ID}/dns_records?`)) {
      finds++;
      if (fail === "verifyRead" && finds === 2) return bad(500, "read broke");
      return ok(records);
    }
    if (method === "POST" && path === `/zones/${ZONE_ID}/dns_records`) {
      if (fail === "add") return bad(500, "nope");
      records.push({ id: "rec1" });
      return ok({ id: "rec1" });
    }
    if (method === "DELETE" && path === `/zones/${ZONE_ID}/dns_records/rec1`) {
      if (fail === "recordDelete") return bad(500, "record delete broke");
      if (fail !== "staysListed") records = records.filter((r) => r.id !== "rec1");
      return ok({ id: "rec1" });
    }
    return bad(404, `unexpected ${method} ${path}`);
  };
  return { calls, fetchFn, live, records: () => records };
}

async function stored(fail?: Fail, baseline = 3) {
  const cf = fakeCloudflare(fail, baseline);
  const store = new MemoryStore();
  const vault = new VaultLogic(store, cf.fetchFn, () => NOW);
  const out = await vault.setup(prf(7), PARENT);
  cf.calls.length = 0;
  return { store, vault, out, cf };
}
const probe = (vault: VaultLogic) => vault.run("cf.dns.txt.probe", { zone: ZONE }, prf(7));

test("seal: opens with the same secret and label only; an altered box never opens", async () => {
  const secret = fromB64url(prf(1));
  const box = await seal(secret, MASTER_LABEL, "hello");
  assert.equal(await open(secret, MASTER_LABEL, box), "hello");
  await assert.rejects(open(fromB64url(prf(2)), MASTER_LABEL, box), /wrong_secret/);
  await assert.rejects(open(secret, RECOVERY_LABEL, box), /wrong_secret/);
  const flipped = fromB64url(box.data);
  flipped[0] ^= 1;
  await assert.rejects(open(secret, MASTER_LABEL, { ...box, data: b64url(flipped) }), /wrong_secret/);
});

test("setup: checks the token with Cloudflare, seals it twice, records the token baseline, returns the paper key once", async () => {
  const { store, out, vault } = await stored(undefined, 60);
  assert.equal(out.token_id, "t0");
  assert.match(out.recovery_key, /^([0-9a-f]{4}-){15}[0-9a-f]{4}$/);
  const master = (await store.get<any>("master"))!;
  assert.ok(!JSON.stringify(master).includes(PARENT), "token never stored in the clear");
  assert.equal(await open(fromB64url(prf(7)), MASTER_LABEL, master.by_passkey), PARENT);
  const paper = Uint8Array.from(out.recovery_key.replace(/-/g, "").match(/../g)!, (h) => parseInt(h, 16));
  assert.equal(await open(paper, RECOVERY_LABEL, master.by_recovery), PARENT, "the paper key opens the same store");
  assert.equal(master.baseline.length, 60, "every page of tokens is in the baseline");
  assert.deepEqual(await vault.status(), { stored: true, token_id: "t0" });
  await assert.rejects(vault.setup(prf(7), PARENT), /already_stored/);
});

test("setup refuses: not a token, no single account, inactive token, bad passkey secret", async () => {
  const fresh = (fail?: Fail) => new VaultLogic(new MemoryStore(), fakeCloudflare(fail).fetchFn, () => NOW);
  await assert.rejects(fresh().setup(prf(7), "short"), /not_a_token/);
  await assert.rejects(fresh("accounts2").setup(prf(7), PARENT), /account_unclear/);
  await assert.rejects(fresh("accounts0").setup(prf(7), PARENT), /account_unclear/);
  await assert.rejects(fresh("inactive").setup(prf(7), PARENT), /token_not_active/);
  await assert.rejects(fresh().setup(b64url(new Uint8Array(16)), PARENT), /bad_secret/);
});

test("probe: zone found with a read key, record added then removed with a one-zone key, both keys deleted, audit clean", async () => {
  const { vault, cf } = await stored(undefined, 60);
  const r = await probe(vault);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual([r.before, r.added, r.seen_after_add, r.removed, r.after], [0, true, true, true, 0]);
  assert.deepEqual(r.minted, [{ id: "minted1", deleted: true }, { id: "minted2", deleted: true }]);
  assert.deepEqual(r.audit, { tokens: 60, minted_still_listed: [], new_since_setup: [] });
  const mints = cf.calls.filter((c) => c.method === "POST" && c.path.endsWith("/tokens"));
  for (const m of mints) {
    assert.equal(m.token, PARENT);
    assert.equal(Date.parse(m.body.expires_on), NOW + PROBE_TOKEN_MS);
  }
  assert.deepEqual(mints[0].body.policies[0].permission_groups, [{ id: "zone-r" }], "the finding key can only read");
  assert.deepEqual(Object.keys(mints[1].body.policies[0].resources), [`com.cloudflare.api.account.zone.${ZONE_ID}`], "the editing key covers one zone");
  // Zone and DNS calls use minted keys, never the master key.
  for (const c of cf.calls.filter((c) => c.path.startsWith("/zones"))) assert.notEqual(c.token, PARENT);
});

test("probe refuses before any Cloudflare call: wrong passkey secret, unknown job, zone not on the list, no master key", async () => {
  const { vault, cf } = await stored();
  await assert.rejects(vault.run("cf.dns.txt.probe", { zone: ZONE }, prf(8)), /wrong_secret/);
  await assert.rejects(vault.run("cf.access.edit", { zone: ZONE }, prf(7)), /job_not_offered/);
  await assert.rejects(vault.run("cf.dns.txt.probe", { zone: "example.com" }, prf(7)), /zone_not_offered/);
  assert.equal(cf.calls.length, 0);
  const empty = new VaultLogic(new MemoryStore(), cf.fetchFn, () => NOW);
  await assert.rejects(probe(empty), /no_master_key/);
});

// Every way a step can go wrong: not ok, keys still deleted, the record never left behind
// when the vault could remove it, and the evidence kept.
for (const [fail, check] of [
  ["existing", (r: any, cf: any) => { assert.equal(r.error, "probe_record_exists"); assert.equal(r.added, false); assert.equal(cf.records().length, 1, "the existing record is left alone"); }],
  ["add", (r: any) => { assert.match(r.error, /^cf_500: nope/); assert.equal(r.added, false); }],
  ["verifyRead", (r: any, cf: any) => { assert.match(r.error, /read broke/); assert.equal(r.removed, true); assert.equal(cf.records().length, 0, "the record is removed even though the check failed"); }],
  ["recordDelete", (r: any, cf: any) => { assert.match(r.error, /record delete broke/); assert.equal(r.removed, false); assert.equal(cf.records().length, 1); }],
  ["tokenDelete", (r: any) => { assert.match(r.error, /token delete failed/); assert.ok(r.minted.every((t: any) => !t.deleted)); assert.ok(r.audit.minted_still_listed.length > 0); }],
  ["list", (r: any) => { assert.match(r.audit.error, /list broke/); assert.equal(r.removed, true, "job evidence kept beside the audit failure"); }],
  ["staysListed", (r: any) => { assert.equal(r.removed, true); assert.equal(r.after, 1, "Cloudflare said deleted but still lists it"); assert.equal(r.error, undefined); }],
  ["newToken", (r: any) => { assert.deepEqual(r.audit.new_since_setup, ["surprise"]); assert.equal(r.error, undefined); }],
] as const) {
  test(`probe when ${fail} goes wrong: not ok, evidence kept`, async () => {
    const { vault, cf } = await stored(fail);
    const r = await probe(vault);
    assert.equal(r.ok, false);
    if (fail !== "tokenDelete") assert.ok(r.minted.every((t) => t.deleted), "minted keys are always deleted");
    check(r, cf);
  });
}

test("the vault loads no libraries: every import is a file beside it or the runtime", () => {
  for (const f of readdirSync("vault/src")) {
    const src = readFileSync(`vault/src/${f}`, "utf8");
    // Both "import x from 'y'" and a bare "import 'y'".
    for (const [, spec] of src.matchAll(/(?:^|\n)\s*(?:import|export)\s+(?:[^"';()=]*?\sfrom\s+)?["']([^"']+)["']/g)) {
      assert.ok(spec === "cloudflare:workers" || /^\.\/[a-z]+\.ts$/.test(spec), `${f} imports ${spec}`);
    }
    assert.ok(!/\bimport\s*\(/.test(src), `${f} has a dynamic import`);
  }
});
