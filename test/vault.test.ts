import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { MemoryStore } from "../src/desk.ts";
import { MASTER_LABEL, RECOVERY_LABEL, open, seal, b64url, fromB64url } from "../vault/src/seal.ts";
import { PROBE_TOKEN_MS, VaultLogic } from "../vault/src/vault.ts";

const ACCOUNT = "a".repeat(32);
const ZONE = "b".repeat(32);
const PARENT = "P".repeat(40);
const MINTED = "M".repeat(40);
const NOW = Date.UTC(2026, 9, 26, 23, 0, 0);
const prf = (fill: number) => b64url(new Uint8Array(32).fill(fill));

// A fake Cloudflare API: answers the calls the vault makes, records each one with the token used.
function fakeCloudflare(opts: { accounts?: number; tokenStatus?: string; existing?: number; failAdd?: boolean } = {}) {
  const calls: { method: string; path: string; token: string; body?: any }[] = [];
  let records: { id: string; content: string }[] = Array.from({ length: opts.existing ?? 0 }, (_, i) => ({ id: `old${i}`, content: "x" }));
  const tokens = [{ id: "parent-id" }, { id: "other" }];
  const ok = (result: unknown) => Response.json({ success: true, result });
  const fetchFn = async (input: string, init?: RequestInit) => {
    const url = new URL(input);
    const path = url.pathname.replace("/client/v4", "") + url.search;
    const method = init?.method ?? "GET";
    const token = String((init?.headers as Record<string, string>).authorization).replace("Bearer ", "");
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path, token, body });
    if (path === "/accounts") return ok(Array.from({ length: opts.accounts ?? 1 }, (_, i) => ({ id: i ? "c".repeat(32) : ACCOUNT })));
    if (path === `/accounts/${ACCOUNT}/tokens/verify`) return ok({ id: "parent-id", status: opts.tokenStatus ?? "active" });
    if (path === `/accounts/${ACCOUNT}/tokens/permission_groups`)
      return ok([
        { id: "dns-w", name: "DNS Write", scopes: ["com.cloudflare.api.account.zone"] },
        { id: "zone-r", name: "Zone Read", scopes: ["com.cloudflare.api.account.zone"] },
        { id: "acct-dns", name: "DNS Write", scopes: ["com.cloudflare.api.account"] },
      ]);
    if (method === "POST" && path === `/accounts/${ACCOUNT}/tokens`) {
      tokens.push({ id: "minted-id" });
      return ok({ id: "minted-id", value: MINTED });
    }
    if (method === "DELETE" && path === `/accounts/${ACCOUNT}/tokens/minted-id`) {
      tokens.splice(tokens.findIndex((t) => t.id === "minted-id"), 1);
      return ok({ id: "minted-id" });
    }
    if (path.startsWith(`/accounts/${ACCOUNT}/tokens?`)) return ok(tokens);
    if (path === `/zones/${ZONE}`) return ok({ name: "example.com" });
    if (method === "GET" && path.startsWith(`/zones/${ZONE}/dns_records?`)) return ok(records);
    if (method === "POST" && path === `/zones/${ZONE}/dns_records`) {
      if (opts.failAdd) return Response.json({ success: false, errors: [{ message: "nope" }] }, { status: 500 });
      records.push({ id: "rec1", content: body.content });
      return ok({ id: "rec1" });
    }
    if (method === "DELETE" && path === `/zones/${ZONE}/dns_records/rec1`) {
      records = records.filter((r) => r.id !== "rec1");
      return ok({ id: "rec1" });
    }
    return Response.json({ success: false, errors: [{ message: `unexpected ${method} ${path}` }] }, { status: 404 });
  };
  return { calls, fetchFn };
}

async function stored(cf = fakeCloudflare()) {
  const store = new MemoryStore();
  const vault = new VaultLogic(store, cf.fetchFn, () => NOW);
  const out = await vault.setup(prf(7), PARENT);
  cf.calls.length = 0;
  return { store, vault, out, cf };
}

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

test("setup: checks the token with Cloudflare, seals it twice, returns the paper key once", async () => {
  const { store, out, vault } = await stored();
  assert.equal(out.token_id, "parent-id");
  assert.match(out.recovery_key, /^([0-9a-f]{4}-){15}[0-9a-f]{4}$/);
  const master = (await store.get<any>("master"))!;
  assert.ok(!JSON.stringify(master).includes(PARENT), "token never stored in the clear");
  assert.equal(await open(fromB64url(prf(7)), MASTER_LABEL, master.by_passkey), PARENT);
  const paper = Uint8Array.from(out.recovery_key.replace(/-/g, "").match(/../g)!, (h) => parseInt(h, 16));
  assert.equal(await open(paper, RECOVERY_LABEL, master.by_recovery), PARENT, "the paper key opens the same store");
  assert.deepEqual(await vault.status(), { stored: true, token_id: "parent-id" });
  await assert.rejects(vault.setup(prf(7), PARENT), /already_stored/);
});

test("setup refuses: not a token, no single account, inactive token, bad passkey secret", async () => {
  const fresh = (cf = fakeCloudflare()) => new VaultLogic(new MemoryStore(), cf.fetchFn, () => NOW);
  await assert.rejects(fresh().setup(prf(7), "short"), /not_a_token/);
  await assert.rejects(fresh(fakeCloudflare({ accounts: 2 })).setup(prf(7), PARENT), /account_unclear/);
  await assert.rejects(fresh(fakeCloudflare({ accounts: 0 })).setup(prf(7), PARENT), /account_unclear/);
  await assert.rejects(fresh(fakeCloudflare({ tokenStatus: "disabled" })).setup(prf(7), PARENT), /token_not_active/);
  await assert.rejects(fresh().setup(b64url(new Uint8Array(16)), PARENT), /bad_secret/);
});

test("probe: 5-minute key for one zone, record added then removed, key deleted and gone from the list", async () => {
  const { vault, cf } = await stored();
  const r = await vault.run("cf.dns.txt.probe", { zone_id: ZONE }, prf(7));
  assert.deepEqual(
    { ...r },
    {
      zone: "example.com",
      record: "_front-desk-probe.example.com",
      before: 0,
      seen_after_add: true,
      after: 0,
      minted_token_id: "minted-id",
      minted_token_deleted: true,
      minted_token_in_list: false,
      tokens_in_account: 2,
    },
  );
  const mint = cf.calls.find((c) => c.method === "POST" && c.path.endsWith("/tokens"))!;
  assert.equal(mint.token, PARENT);
  assert.deepEqual(Object.keys(mint.body.policies[0].resources), [`com.cloudflare.api.account.zone.${ZONE}`]);
  assert.deepEqual(mint.body.policies[0].permission_groups, [{ id: "dns-w" }, { id: "zone-r" }]);
  assert.equal(Date.parse(mint.body.expires_on), NOW + PROBE_TOKEN_MS);
  // DNS calls use the minted key, never the master key.
  for (const c of cf.calls.filter((c) => c.path.startsWith("/zones/"))) assert.equal(c.token, MINTED);
});

test("probe refuses before any Cloudflare call: wrong passkey secret, unknown job, bad zone, no master key", async () => {
  const { vault, cf } = await stored();
  await assert.rejects(vault.run("cf.dns.txt.probe", { zone_id: ZONE }, prf(8)), /wrong_secret/);
  await assert.rejects(vault.run("cf.access.edit", { zone_id: ZONE }, prf(7)), /job_not_offered/);
  await assert.rejects(vault.run("cf.dns.txt.probe", { zone_id: "../accounts" }, prf(7)), /bad_params/);
  assert.equal(cf.calls.length, 0);
  const empty = new VaultLogic(new MemoryStore(), cf.fetchFn, () => NOW);
  await assert.rejects(empty.run("cf.dns.txt.probe", { zone_id: ZONE }, prf(7)), /no_master_key/);
});

test("probe: an existing probe record is left alone, and the minted key is still deleted", async () => {
  const { vault, cf } = await stored(fakeCloudflare({ existing: 1 }));
  const r = await vault.run("cf.dns.txt.probe", { zone_id: ZONE }, prf(7));
  assert.equal(r.error, "probe_record_exists");
  assert.ok(!cf.calls.some((c) => c.method === "POST" && c.path.endsWith("/dns_records")));
  assert.equal(r.minted_token_deleted, true);
  assert.equal(r.minted_token_in_list, false);
});

test("probe: a failure mid-job still deletes the minted key", async () => {
  const { vault } = await stored(fakeCloudflare({ failAdd: true }));
  const r = await vault.run("cf.dns.txt.probe", { zone_id: ZONE }, prf(7));
  assert.match(r.error!, /^cf_500: nope/);
  assert.equal(r.minted_token_deleted, true);
  assert.equal(r.minted_token_in_list, false);
});

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
