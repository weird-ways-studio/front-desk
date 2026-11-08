import { test } from "node:test";
import { signedRun, testVault } from "./vaultsign.ts";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { MemoryStore } from "../src/desk.ts";
import { MASTER_LABEL, RECOVERY_LABEL, open, seal, b64url, fromB64url } from "../vault/src/seal.ts";
import { PENDING_MS, PROBE_TOKEN_MS, TOKENS_READ, VaultLogic, type CfAcceptResult, type Headcount, type HeadcountSetupResult, type ReadResult, HELPER_PREFIX, RESULT_MAX_BYTES, SWEEP_DELETES } from "../vault/src/vault.ts";
import { handleSetup } from "../vault/src/setup.ts";

const ACCOUNT = "a".repeat(32);
const ZONE_ID = "b".repeat(32);
const ZONE = "benculbert.com";
const PARENT = "P".repeat(40);
const NOW = Date.UTC(2026, 9, 26, 23, 0, 0);
const prf = (fill: number) => b64url(new Uint8Array(32).fill(fill));
type Fail = "accounts2" | "accounts0" | "inactive" | "tokenDelete" | "list" | "newToken" | "offboxAllowed" | "offboxBroken" | "offboxOther403" | "hcCanMint" | "hcMint500" | "hcNoGroup" | "hcOldStays" | "lostMint";

const GROUP_NAMES: Record<string, string> = { "dns-w": "DNS Write", "zone-r": "Zone Read", "dns-r": "DNS Read", "acct-set-r": "Account Settings Read", "acct-dns": "DNS Write", "tok-r": "Account API Tokens Read", "tok-r-zone": "API Tokens Read" };

// A fake Cloudflare API: answers the calls the vault makes and records each with the token used.
// `fail` makes one step go wrong, to show what the vault does then.
function fakeCloudflare(fail?: Fail, baseline = 3) {
  const calls: { method: string; path: string; token: string; body?: any }[] = [];
  const records: { id: string }[] = [];
  const tokens: { id: string; name?: string; expires_on?: string; policies?: any[] }[] = Array.from({ length: baseline }, (_, i) => ({ id: `t${i}` }));
  const listOnly = new Set<string>(); // minted values that hold only the API Tokens Read group
  const hcOld: { stuck?: string } = {}; // a headcount key whose delete fails (hcOldStays)
  const live = new Map<string, string>(); // minted value -> id
  const pinned = new Map<string, string>(); // minted value -> the one address it works from
  let n = 0;
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
        { id: "dns-r", name: "DNS Read", scopes: ["com.cloudflare.api.account.zone"] },
        { id: "acct-set-r", name: "Account Settings Read", scopes: ["com.cloudflare.api.account"] },
        { id: "acct-dns", name: "DNS Write", scopes: ["com.cloudflare.api.account"] },
        ...(fail === "hcNoGroup" ? [] : [{ id: "tok-r", name: "Account API Tokens Read", scopes: ["com.cloudflare.api.account"] }]),
        { id: "tok-r-zone", name: "API Tokens Read", scopes: ["com.cloudflare.api.account.zone"] },
      ]);
    if (method === "POST" && path === `/accounts/${ACCOUNT}/tokens`) {
      if (!body?.policies?.length || !body.policies[0].permission_groups?.length) return bad(400, "policies required");
      if (listOnly.has(token) && fail === "hcMint500") return bad(500, "internal error");
      if (listOnly.has(token) && fail !== "hcCanMint") return bad(403, "Unauthorized to access requested resource");
      const id = `minted${++n}`;
      const named = (body.policies as any[]).map((p) => ({ ...p, permission_groups: p.permission_groups.map((g: { id: string }) => ({ id: g.id, name: GROUP_NAMES[g.id] })) }));
      tokens.push({ id, name: body?.name, expires_on: body?.expires_on, policies: named });
      // The token exists, but the answer never reaches the vault (lost on the way back).
      if (fail === "lostMint" && n === 1) return bad(502, "bad gateway");
      if (body?.policies?.[0]?.permission_groups?.every((g: { id: string }) => g.id === "tok-r")) listOnly.add(`V${n}`.padEnd(40, "v"));
      live.set(`V${n}`.padEnd(40, "v"), id);
      const cidr = body?.condition?.request_ip?.in?.[0];
      if (cidr) pinned.set(`V${n}`.padEnd(40, "v"), cidr);
      return ok({ id, value: `V${n}`.padEnd(40, "v") });
    }
    if (method === "DELETE" && path.startsWith(`/accounts/${ACCOUNT}/tokens/`)) {
      if (fail === "tokenDelete") return bad(500, "delete broke");
      if (fail === "hcOldStays" && hcOld.stuck && path.endsWith(`/${hcOld.stuck}`)) return bad(500, "delete broke");
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
    // The vault calls from Cloudflare's network, never the pinned c-box address.
    if (method === "GET" && path === `/zones/${ZONE_ID}`) {
      if (pinned.has(token) && fail === "offboxBroken") return bad(500, "internal error");
      if (pinned.has(token) && fail === "offboxOther403") return bad(403, "Authentication error");
      if (pinned.has(token) && fail !== "offboxAllowed") return bad(403, "Cannot use the access token from location: 104.28.0.1");
      return ok({ id: ZONE_ID, name: ZONE, status: "active", paused: false, type: "full", plan: { name: "Free Website" }, name_servers: ["a.ns", "b.ns"], owner: { email: "x" } });
    }
    if (method === "GET" && path.startsWith(`/accounts/${ACCOUNT}/audit_logs?`)) {
      return ok([{ when: "2026-11-02T10:00:00Z", action: { type: "update", result: true }, actor: { email: "ben@example.com", ip: "198.51.100.1" }, resource: { type: "zone", id: ZONE_ID }, metadata: { big: "x" } }]);
    }
    if (method === "GET" && path.startsWith(`/zones/${ZONE_ID}/dns_records?`)) {
      return ok(records);
    }
    return bad(404, `unexpected ${method} ${path}`);
  };
  return { calls, fetchFn, live, pinned, tokens, listOnly, hcOld, records: () => records };
}

async function stored(fail?: Fail, baseline = 3) {
  const cf = fakeCloudflare(fail, baseline);
  const store = new MemoryStore();
  const clock = { now: NOW };
  const vault = testVault(store, cf.fetchFn, () => clock.now);
  const out = await vault.setup(PARENT);
  cf.calls.length = 0;
  return { store, vault, out, cf, clock };
}
// The generic vault job for unlock and audit tests: a read (cf.dns.txt.probe was cut, card c653a0fd).
const probe = (vault: VaultLogic, secret = prf(7)) => signedRun(vault, "cf.zone.read", { zone: ZONE }, secret) as Promise<ReadResult>;

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

test("setup: checks the token with Cloudflare, holds it under a one-time key, returns the paper key once", async () => {
  const { store, out, vault } = await stored(undefined, 60);
  assert.equal(out.token_id, "t0");
  assert.match(out.recovery_key, /^([0-9a-f]{4}-){15}[0-9a-f]{4}$/);
  const master = (await store.get<any>("master"))!;
  assert.ok(!JSON.stringify(master).includes(PARENT), "token never stored in the clear");
  assert.equal(master.by_passkey, undefined, "not locked to the passkey until Ben's first tap");
  const paper = Uint8Array.from(out.recovery_key.replace(/-/g, "").match(/../g)!, (h) => parseInt(h, 16));
  assert.equal(await open(paper, RECOVERY_LABEL, master.by_recovery), PARENT, "the paper key opens the same store");
  assert.equal(master.baseline.length, 60, "every page of tokens is in the baseline");
  assert.deepEqual(await vault.status(), { stored: false, pending: true, token_id: "t0" });
  await assert.rejects(vault.setup(PARENT), /already_stored/);
});

test("first Face ID tap locks the key to the passkey and forgets the one-time key; after that only that secret opens it", async () => {
  const { store, vault } = await stored();
  const first = await probe(vault);
  assert.deepEqual(first.master, { token_id: "t0", locked_to_passkey_now: true });
  const master = (await store.get<any>("master"))!;
  assert.equal(master.pending, undefined);
  assert.equal(await open(fromB64url(prf(7)), MASTER_LABEL, master.by_passkey), PARENT);
  assert.deepEqual(await vault.status(), { stored: true, pending: false, token_id: "t0" });
  assert.equal((await probe(vault)).master.locked_to_passkey_now, false);
  await assert.rejects(probe(vault, prf(8)), /wrong_secret/);
});

test("two first taps at once: only one locks the key, and the other cannot replace it", async () => {
  const { store, vault } = await stored();
  const results = await Promise.allSettled([probe(vault, prf(1)), probe(vault, prf(2))]);
  const won = results.filter((r) => r.status === "fulfilled" && (r.value as ReadResult).master.locked_to_passkey_now);
  const lost = results.filter((r) => r.status === "rejected" && /already_locked/.test(String(r.reason)));
  assert.equal(won.length, 1);
  assert.equal(lost.length, 1);
  const winner = results[0].status === "fulfilled" ? 1 : 2;
  const master = (await store.get<any>("master"))!;
  assert.equal(await open(fromB64url(prf(winner)), MASTER_LABEL, master.by_passkey), PARENT);
  await assert.rejects(open(fromB64url(prf(3 - winner)), MASTER_LABEL, master.by_passkey), /wrong_secret/);
});

test("a setup nobody confirms within 30 minutes lapses, is erased from storage, and can be done again", async () => {
  const { store, vault, clock } = await stored();
  clock.now += PENDING_MS + 1;
  assert.deepEqual(await vault.status(), { stored: false, pending: false });
  assert.equal(await store.get("master"), null, "the one-time key and sealed token are gone, not just ignored");
  await assert.rejects(probe(vault), /no_master_key/);
  assert.equal((await vault.setup(PARENT)).token_id, "t0");
});

test("setup refuses: not a token, no single account, inactive token", async () => {
  const fresh = (fail?: Fail) => testVault(new MemoryStore(), fakeCloudflare(fail).fetchFn, () => NOW);
  await assert.rejects(fresh().setup("short"), /not_a_token/);
  await assert.rejects(fresh("accounts2").setup(PARENT), /account_unclear/);
  await assert.rejects(fresh("accounts0").setup(PARENT), /account_unclear/);
  await assert.rejects(fresh("inactive").setup(PARENT), /token_not_active/);
});

test("vault refuses before any Cloudflare call: wrong passkey secret, unknown or cut job, zone not on the list, no master key", async () => {
  const { vault, cf } = await stored();
  await probe(vault); // locks the key to prf(7)
  cf.calls.length = 0;
  // A secret that is not 32 bytes is refused at the shape check, before the grant is used (card bb86abf0).
  await assert.rejects(probe(vault, b64url(new Uint8Array(16))), /wrong_shape/);
  await assert.rejects(probe(vault, prf(8)), /wrong_secret/);
  await assert.rejects(signedRun(vault, "cf.access.edit", { zone: ZONE }, prf(7)), /job_not_offered/);
  // Cut 2026-11-08 (card c653a0fd): the DNS-write test job is no longer offered by the vault.
  await assert.rejects(signedRun(vault, "cf.dns.txt.probe", { zone: ZONE }, prf(7)), /job_not_offered/);
  await assert.rejects(signedRun(vault, "cf.zone.read", { zone: "example.com" }, prf(7)), /zone_not_offered/);
  assert.equal(cf.calls.length, 0);
  const empty = testVault(new MemoryStore(), cf.fetchFn, () => NOW);
  await assert.rejects(probe(empty), /no_master_key/);
});

// Every way a read job's bookkeeping can go wrong (moved here from the cut cf.dns.txt.probe, card c653a0fd).
test("read job when a short key will not delete: not ok, no answer handed on, the key stays listed", async () => {
  const r = await probe((await stored("tokenDelete")).vault);
  assert.equal(r.ok, false);
  assert.match(r.error ?? "", /token delete failed/);
  assert.ok(r.minted.every((t) => !t.deleted));
  assert.ok(r.audit.minted_still_listed.length > 0);
  assert.equal(r.data, undefined, "an answer is handed on only when the whole job checked out");
});

test("read job when the token list fails: not ok, no answer handed on, the reason kept", async () => {
  const r = await probe((await stored("list")).vault);
  assert.equal(r.ok, false);
  assert.match(r.audit.error ?? "", /list broke/);
  assert.ok(r.minted.every((t) => t.deleted), "minted keys are still deleted");
  assert.equal(r.data, undefined);
});

test("read job when an unknown key appears: the read stands and the evidence names the key (the nightly count alarms on it)", async () => {
  const r = await probe((await stored("newToken")).vault);
  assert.deepEqual(r.audit.new_since_setup, ["surprise"]);
  assert.equal(r.ok, true);
});

// The vault's own setup page (vault/src/setup.ts).
const VAULT = "https://vault.example";
const form = (token: string, origin = VAULT) =>
  new Request(`${VAULT}/setup`, { method: "POST", headers: { origin, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token }) });

const readJob = (vault: VaultLogic, job: string, params: Record<string, string>) => signedRun(vault, job, params, prf(7)) as Promise<ReadResult>;
const WINDOW = { since: "2026-10-24T00:00:00Z", until: "2026-10-26T00:00:00Z" };
const minted = (cf: ReturnType<typeof fakeCloudflare>) => cf.calls.filter((c) => c.method === "POST" && c.path.endsWith("/tokens"));

test("read jobs: each reads with short keys of a fixed policy, deletes them, and returns only the answer (no key)", async () => {
  const cases = [
    ["cf.zone.read", { zone: ZONE }, { [`com.cloudflare.api.account.zone.${ZONE_ID}`]: "*" }, "zone-r"],
    ["cf.dns.list", { zone: ZONE }, { [`com.cloudflare.api.account.zone.${ZONE_ID}`]: "*" }, "dns-r"],
    ["cf.audit.read", WINDOW, { [`com.cloudflare.api.account.${ACCOUNT}`]: "*" }, "acct-set-r"],
  ] as const;
  for (const [job, params, resources, group] of cases) {
    const { store, vault, cf } = await stored();
    const r = await readJob(vault, job, params);
    assert.equal(r.ok, true, `${job}: ${JSON.stringify(r)}`);
    assert.ok(r.data !== undefined, job);
    const reader = minted(cf).at(-1)!;
    assert.deepEqual(reader.body.policies, [{ effect: "allow", resources, permission_groups: [{ id: group }] }], job);
    assert.equal(reader.body.expires_on, new Date(NOW + PROBE_TOKEN_MS).toISOString().replace(/\.\d{3}Z$/, "Z"), job);
    assert.ok(reader.body.name.startsWith(HELPER_PREFIX), job);
    // Every short key (the zone finder too) is made with the master, lives PROBE_TOKEN_MS, and has a fixed policy;
    // zone and audit calls never use the master itself (moved from the cut probe test, Codex c653a0fd r1).
    const expiry = new Date(NOW + PROBE_TOKEN_MS).toISOString().replace(/\.\d{3}Z$/, "Z");
    for (const m of minted(cf)) {
      assert.equal(m.token, PARENT, `${job}: short keys are made with the master`);
      assert.equal(m.body.expires_on, expiry, `${job}: every short key expires after ${PROBE_TOKEN_MS} ms`);
      assert.ok(m.body.name.startsWith(HELPER_PREFIX), job);
    }
    if (job !== "cf.audit.read") assert.deepEqual(minted(cf)[0].body.policies[0].permission_groups, [{ id: "zone-r" }], `${job}: the zone finder can only read`);
    const reads = cf.calls.filter((c) => c.path.startsWith("/zones") || c.path.includes("/audit_logs"));
    assert.ok(reads.length > 0, job);
    for (const c of reads) assert.notEqual(c.token, PARENT, `${job}: ${c.method} ${c.path} uses a short key, never the master`);
    assert.ok(r.minted.length >= 1 && r.minted.every((t) => t.deleted), `${job}: every short key deleted`);
    assert.ok(minted(cf).every((c) => !cf.tokens.some((t) => t.name === c.body.name)), `${job}: none left at Cloudflare`);
    assert.ok(![...cf.live.keys()].some((v) => JSON.stringify(r).includes(v)), `${job}: no key value in the result`);
    assert.deepEqual(await store.get("helpers"), [], `${job}: nothing left to clean up`);
  }
  const { vault } = await stored();
  assert.deepEqual((await readJob(vault, "cf.zone.read", { zone: ZONE })).data, { id: ZONE_ID, name: ZONE, status: "active", paused: false, type: "full", plan: "Free Website", name_servers: ["a.ns", "b.ns"] });
  assert.deepEqual((await readJob(vault, "cf.audit.read", WINDOW)).data, [{ when: "2026-11-02T10:00:00Z", action: "update", result: true, actor: "ben@example.com", ip: "198.51.100.1", resource: `zone ${ZONE_ID}` }]);
});

test("read jobs: the vault itself refuses another zone, a bad window, extra power, and the retired key job -- before any Cloudflare call", async () => {
  const { vault, cf } = await stored();
  await assert.rejects(readJob(vault, "cf.dns.list", { zone: "example.com" }), /zone_not_offered/);
  await assert.rejects(readJob(vault, "cf.zone.read", {}), /zone_not_offered/);
  for (const w of [
    { since: "2026-11-01T00:00:00Z", until: "2026-11-08T00:00:01Z" }, // over 7 days
    { since: "2026-11-03T00:00:00Z", until: "2026-11-01T00:00:00Z" }, // backwards
    { since: "2026-10-26T00:00:00Z", until: "2026-10-28T00:00:00Z" }, // ends in the future (NOW is 2026-10-26 23:00)
    { since: "2026-11-01", until: "2026-11-02" },
    { since: "2026-11-01T00:00:00.000Z", until: "2026-11-02T00:00:00Z" },
    {},
  ]) {
    await assert.rejects(readJob(vault, "cf.audit.read", w as Record<string, string>), /bad_params/, JSON.stringify(w));
  }
  await assert.rejects(signedRun(vault, "cf.token.zone.read", { zone: ZONE, minutes: "5", ip: "203.0.113.7" }, prf(7)), /job_not_offered/);
  assert.equal(cf.calls.length, 0);
});

test("read jobs: a long DNS list is cut at 500 and says so", async () => {
  const { vault, cf } = await stored();
  const many = Array.from({ length: 600 }, (_, i) => ({ id: `r${i}`, type: "A", name: `h${i}.${ZONE}`, content: "192.0.2.1" }));
  const fetchFn = cf.fetchFn;
  const v = testVault((vault as any).store, async (input: string, init?: RequestInit) =>
    String(input).includes("/dns_records?") ? Response.json({ success: true, result: many }) : fetchFn(input, init), () => NOW);
  const r = await readJob(v, "cf.dns.list", { zone: ZONE });
  assert.equal(r.ok, true);
  assert.equal(r.truncated, true);
  assert.equal((r.data as unknown[]).length, 500);
});

// Card ae6147e4 R10: the vault's short keys are recorded before they exist and until a delete is confirmed.
test("short keys: the intent is stored before the mint (name, asked expiry), the id right after", async () => {
  const { store, vault, cf } = await stored();
  const seen: unknown[] = [];
  const v = testVault(store, async (input: string, init?: RequestInit) => {
    if (init?.method === "POST" && String(input).endsWith("/tokens")) seen.push({ name: JSON.parse(String(init.body)).name, stored: await store.get("helpers") });
    return cf.fetchFn(input, init);
  }, () => NOW);
  await readJob(v, "cf.zone.read", { zone: ZONE });
  assert.equal(seen.length, 2);
  for (const x of seen as { name: string; stored: { name: string; id?: string }[] }[]) {
    const mine = x.stored.find((h) => h.name === x.name);
    assert.ok(mine && mine.id === undefined, "recorded, without an id, before Cloudflare is asked");
    assert.match((mine as { purpose?: string }).purpose ?? "", /^(find zone benculbert\.com|cf\.zone\.read: read zone)$/, "with its purpose");
  }
});

test("short keys: a failed delete leaves them recorded; the nightly count lists them as cleanup (not acceptable), the next tap deletes them", async () => {
  const { store, vault, cf } = await stored();
  await hcSetup(vault);
  const broken = testVault(store, async (input: string, init?: RequestInit) =>
    init?.method === "DELETE" && String(input).includes("/tokens/minted") ? Response.json({ success: false, errors: [{ message: "delete broke" }] }, { status: 500 }) : cf.fetchFn(input, init), () => NOW);
  const r = await readJob(broken, "cf.dns.list", { zone: ZONE });
  assert.equal(r.ok, false);
  assert.equal(r.data, undefined, "no answer handed on when a key was left behind");
  const left = (await store.get<{ id?: string }[]>("helpers"))!;
  assert.equal(left.length, 2);
  const night = await vault.headcount();
  assert.equal(night.ok, false);
  assert.deepEqual(night.unexpected, [], "not 'unexpected', so cf.token.accept never offers them");
  assert.deepEqual(night.cleanup.map((k) => k.id).sort(), left.map((h) => h.id).sort());
  assert.ok(night.cleanup.every((k) => !k.expired && k.expires_on !== "never"), "expiry is Cloudflare's own");
  assert.ok(night.cleanup.every((k) => k.recorded), "the vault's own: it will delete them");
  assert.deepEqual(await vault.cfPreview(), []);
  // The next approved Cloudflare taps sweep them first, SWEEP_DELETES per tap (F9 cap, card 85818ab1).
  const next = await readJob(vault, "cf.zone.read", { zone: ZONE });
  assert.equal(next.ok, true, JSON.stringify(next));
  assert.equal((await store.get<unknown[]>("helpers"))!.length, 2 - SWEEP_DELETES, "the rest waits for the next tap");
  assert.equal((await readJob(vault, "cf.zone.read", { zone: ZONE })).ok, true);
  assert.deepEqual(await store.get("helpers"), []);
  const after = await vault.headcount();
  assert.ok(cfClean(after) && after.cleanup.length === 0, JSON.stringify(after));
});

test("short keys: a lost mint answer leaves a named intent; the next tap finds the key by its name and deletes it", async () => {
  const { store, vault, cf, clock } = await stored("lostMint");
  const r = await readJob(vault, "cf.zone.read", { zone: ZONE });
  assert.equal(r.ok, false);
  const [intent] = (await store.get<{ name: string; id?: string }[]>("helpers"))!;
  assert.equal(intent.id, undefined);
  assert.ok(cf.tokens.some((t) => t.name === intent.name), "Cloudflare made it anyway");
  clock.now += 60_000;
  assert.equal((await readJob(vault, "cf.zone.read", { zone: ZONE })).ok, true);
  assert.ok(!cf.tokens.some((t) => t.name === intent.name), "found by name and deleted");
  assert.deepEqual(await store.get("helpers"), []);
});

test("short keys: an intent never made is dropped only after its asked expiry; an outside key borrowing the name is never deleted, keeps alarming, is never accepted", async () => {
  const { store, vault, cf, clock } = await stored();
  await hcSetup(vault);
  await store.put("helpers", [{ name: `${HELPER_PREFIX}ghost`, until: new Date(NOW + 60_000).toISOString() }]);
  await readJob(vault, "cf.zone.read", { zone: ZONE });
  assert.equal((await store.get<unknown[]>("helpers"))!.length, 1, "kept: its mint could still be in flight");
  clock.now += 2 * 60_000;
  await readJob(vault, "cf.zone.read", { zone: ZONE });
  assert.deepEqual(await store.get("helpers"), []);
  cf.tokens.push({ id: "f".repeat(32), name: `${HELPER_PREFIX}not ours` });
  await readJob(vault, "cf.zone.read", { zone: ZONE });
  assert.ok(cf.tokens.some((t) => t.id === "f".repeat(32)), "a name the vault did not record is never deleted");
  const night = await vault.headcount();
  assert.equal(night.ok, false);
  assert.deepEqual(night.cleanup.map((k) => [k.id, k.recorded]), [["f".repeat(32), false]], "not recorded: the vault will not delete it");
  assert.match((await accept(vault, "f".repeat(32), 7, "x")).error ?? "", /helper_key_not_acceptable/);
});

test("short keys: cf.token.accept refuses a recorded short key by its id, even under another name", async () => {
  const { store, vault, cf } = await stored();
  await hcSetup(vault);
  const id = "e".repeat(32);
  cf.tokens.push({ id, name: "renamed" });
  await store.put("helpers", [{ name: `${HELPER_PREFIX}x`, until: new Date(NOW + 60_000).toISOString(), id }]);
  const stuck = testVault(store, async (input: string, init?: RequestInit) =>
    init?.method === "DELETE" ? Response.json({ success: false, errors: [{ message: "delete broke" }] }, { status: 500 }) : cf.fetchFn(input, init), () => NOW);
  const r = (await signedRun(stuck, "cf.token.accept", { ids: id, scopes: "x" }, prf(7))) as CfAcceptResult;
  assert.equal(r.ok, false);
  assert.match(r.error ?? "", /helper_key_not_acceptable/);
  assert.ok(!(await store.get<any>("master")).baseline.includes(id));
});

test("read jobs: a failed final audit is not a success, and no answer is handed on (Codex 4a-1 r1 #1)", async () => {
  const { vault } = await stored("list");
  const r = await readJob(vault, "cf.zone.read", { zone: ZONE });
  assert.equal(r.ok, false);
  assert.match(r.audit.error ?? "", /list broke/);
  assert.equal(r.data, undefined);
});

test("short keys: an earlier key the sweep cannot delete is reported on this tap's result, while the new read succeeds (Codex 4a-1 r1 #2)", async () => {
  const { store, vault, cf } = await stored();
  const id = "d".repeat(32);
  cf.tokens.push({ id, name: `${HELPER_PREFIX}old` });
  await store.put("helpers", [{ name: `${HELPER_PREFIX}old`, purpose: "cf.zone.read: read zone", until: new Date(NOW + 60_000).toISOString(), id }]);
  const v = testVault(store, async (input: string, init?: RequestInit) =>
    init?.method === "DELETE" && String(input).endsWith(`/tokens/${id}`) ? Response.json({ success: false, errors: [{ message: "delete broke" }] }, { status: 500 }) : cf.fetchFn(input, init), () => NOW);
  const r = await readJob(v, "cf.zone.read", { zone: ZONE });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual(r.leftover, [id]);
  const { JOBS } = await import("../src/jobs.ts");
  assert.match(JOBS["cf.zone.read"].done(r), /^Done\.[\s\S]*Also: 1 short vault key from an earlier tap could not be confirmed deleted/);
  assert.deepEqual((await readJob(vault, "cf.zone.read", { zone: ZONE })).leftover, [], "next tap with working deletes: cleared");
});

test("read jobs: an answer is cut to the storage bound in bytes, whole rows, and says so (Codex 4a-1 r1 #5)", async () => {
  const { store, cf } = await stored();
  const big = Array.from({ length: 500 }, (_, i) => ({ id: `r${i}`, type: "TXT", name: `h${i}.${ZONE}`, content: "x".repeat(2000) }));
  const fetchFn = cf.fetchFn;
  const v = testVault(store, async (input: string, init?: RequestInit) =>
    String(input).includes("/dns_records?") ? Response.json({ success: true, result: big }) : fetchFn(input, init), () => NOW);
  const r = await readJob(v, "cf.dns.list", { zone: ZONE });
  assert.equal(r.ok, true);
  assert.equal(r.truncated, true);
  const rows = r.data as { id: string }[];
  assert.ok(rows.length > 0 && rows.length < 500);
  assert.ok(new TextEncoder().encode(JSON.stringify(rows)).length <= RESULT_MAX_BYTES);
  assert.deepEqual(rows.map((x) => x.id), big.slice(0, rows.length).map((x) => x.id), "whole rows from the start");
});

test("handed-out keys from before 4a-1: once expired, the next job deletes them", async () => {
  const { store, vault, cf, clock } = await stored();
  await probe(vault);
  cf.tokens.push({ id: "old1", expires_on: new Date(NOW + 60_000).toISOString() });
  const m = await store.get<any>("master");
  await store.put("master", { ...m, issued: [{ id: "old1", expires_on: new Date(NOW + 60_000).toISOString() }] });
  clock.now += 2 * 60_000;
  assert.equal((await readJob(vault, "cf.zone.read", { zone: ZONE })).ok, true);
  assert.ok(!cf.tokens.some((t) => t.id === "old1"));
  assert.deepEqual((await store.get<any>("master")).issued, []);
});

test("setup page: Ben gets the form, saves the token, sees the paper key once; then every address is 404", async () => {
  const vault = testVault(new MemoryStore(), fakeCloudflare().fetchFn, () => NOW);
  const get = await handleSetup(new Request(`${VAULT}/setup`), vault, "ben@example.com");
  assert.equal(get.status, 200);
  assert.match(get.headers.get("content-security-policy")!, /form-action 'self'/);
  // With "no-referrer" the browser posts Origin: null and Ben's own Save is refused.
  assert.equal(get.headers.get("referrer-policy"), "same-origin");
  assert.ok(!(await get.text()).includes("<script"), "no script on the page");
  const saved = await handleSetup(form(PARENT), vault, "ben@example.com");
  const html = await saved.text();
  assert.equal(saved.status, 200);
  assert.match(html, /PASS: stored/);
  assert.match(html, /([0-9a-f]{4}-){15}[0-9a-f]{4}/);
  assert.ok(!html.includes(PARENT), "the token is not echoed back");
  for (const req of [new Request(`${VAULT}/setup`), form(PARENT), new Request(`${VAULT}/`)]) {
    assert.equal((await handleSetup(req, vault, "ben@example.com")).status, 404);
  }
});

test("setup page refuses: no email (the agent or no login), another site's form, other paths, a bad token", async () => {
  const vault = testVault(new MemoryStore(), fakeCloudflare().fetchFn, () => NOW);
  assert.equal((await handleSetup(new Request(`${VAULT}/setup`), vault, "")).status, 403);
  assert.equal((await handleSetup(form(PARENT), vault, "")).status, 403);
  assert.equal((await handleSetup(form(PARENT, "https://evil.example"), vault, "ben@example.com")).status, 403);
  assert.equal((await handleSetup(form(PARENT, "null"), vault, "ben@example.com")).status, 403);
  assert.equal((await handleSetup(new Request(`${VAULT}/`), vault, "ben@example.com")).status, 404);
  const bad = await handleSetup(form("short"), vault, "ben@example.com");
  assert.equal(bad.status, 400);
  assert.match(await bad.text(), /FAIL: not_a_token/);
  assert.deepEqual(await vault.status(), { stored: false, pending: false }, "nothing stored by any refused request");
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

test("deploy-vault.sh deploys the vault only in Workers Builds, on a real deploy of main", async () => {
  const { execFileSync } = await import("node:child_process");
  const { mkdtempSync, writeFileSync, chmodSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  // A stand-in npx that only reports what it was asked to run.
  const bin = mkdtempSync(`${tmpdir()}/fake-npx-`);
  writeFileSync(`${bin}/npx`, '#!/bin/sh\necho "npx $* name=${WRANGLER_CI_OVERRIDE_NAME:-unset} tag=${WRANGLER_CI_MATCH_TAG:-unset}"\n');
  chmodSync(`${bin}/npx`, 0o755);
  const run = (env: Record<string, string>) =>
    execFileSync("sh", ["scripts/deploy-vault.sh"], { env: { PATH: `${bin}:/usr/bin:/bin`, ...env }, encoding: "utf8" });
  const ci = { WORKERS_CI: "1", WRANGLER_COMMAND: "deploy", WORKERS_CI_BRANCH: "main" };
  assert.match(run(ci), /npx wrangler deploy -c vault\/wrangler\.jsonc/);
  // Workers Builds' name and tag for the front desk must not reach the vault deploy,
  // or wrangler uploads the vault code as the front desk.
  const builds = { ...ci, WRANGLER_CI_OVERRIDE_NAME: "front-desk", WRANGLER_CI_MATCH_TAG: "abc123" };
  assert.match(run(builds), /npx wrangler deploy -c vault\/wrangler\.jsonc name=unset tag=unset/);
  for (const env of [{}, { ...ci, WORKERS_CI: "" }, { ...ci, WRANGLER_COMMAND: "dev" }, { ...ci, WORKERS_CI_BRANCH: "probe" }]) {
    const out = run(env);
    assert.match(out, /skipping/);
    assert.doesNotMatch(out, /npx/);
  }
});

// Nightly headcount (C5c-2 3baea7cc): its own list-only key, then a count with no tap.
// The Cloudflare half of a night is clean (the GitHub half has its own tests: github.test.ts).
const cfClean = (r: Headcount) => !r.error && r.unexpected.length === 0 && r.stretched.length === 0 && r.missing.length === 0;
const hcSetup = (vault: VaultLogic) => signedRun(vault, "cf.token.headcount.setup", {}, prf(7)) as Promise<HeadcountSetupResult>;

test("headcount setup: keeps a key that lists and is refused a mint; account-wide read only, no expiry", async () => {
  const { store, vault, cf } = await stored();
  const r = await hcSetup(vault);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.lists, true);
  assert.equal(r.mint_refused, true);
  const kept = (await store.get<any>("headcount"))!;
  assert.equal(kept.token_id, r.key_id);
  assert.ok(cf.listOnly.has(kept.value), "the kept key is the list-only one");
  const made = cf.calls.find((c) => c.method === "POST" && c.path.endsWith("/tokens") && c.body?.name?.startsWith("front-desk headcount 2"))!;
  assert.deepEqual(made.body.policies, [{ effect: "allow", resources: { [`com.cloudflare.api.account.${ACCOUNT}`]: "*" }, permission_groups: [{ id: "tok-r" }] }]);
  assert.equal(made.body.expires_on, undefined);
  assert.ok(!JSON.stringify(r).includes(kept.value), "the key's secret is never in the result");
  const probeMint = cf.calls.find((c) => c.body?.name === "front-desk headcount must-fail")!;
  assert.equal(probeMint.body.policies[0].permission_groups[0].id, "tok-r", "the refused mint was a complete, valid request");
});

for (const fail of ["hcCanMint", "hcMint500", "hcNoGroup"] as const) {
  test(`headcount setup fails closed (${fail}): nothing kept, no key left in the account`, async () => {
    const { store, vault, cf } = await stored(fail);
    const r = await hcSetup(vault);
    assert.equal(r.ok, false);
    assert.equal(await store.get("headcount"), undefined);
    assert.deepEqual(cf.tokens.map((t) => t.id), ["t0", "t1", "t2"], "the new key (and any key it made) is deleted");
  });
}

test("headcount setup again: the new key replaces the old, which is deleted", async () => {
  const { store, vault, cf } = await stored();
  const first = await hcSetup(vault);
  const second = await hcSetup(vault);
  assert.equal(second.ok, true);
  assert.deepEqual(second.replaced, [first.key_id]);
  assert.equal((await store.get<any>("headcount")).token_id, second.key_id);
  assert.ok(!cf.tokens.some((t) => t.id === first.key_id));
});

test("headcount: a clean account counts ok, using only the list-only key", async () => {
  const { vault, cf } = await stored();
  await hcSetup(vault);
  cf.calls.length = 0;
  const r = await vault.headcount();
  // Cloudflare is clean; GitHub is not set up in these tests, so the night as a whole fails closed.
  assert.deepEqual(r, { ok: false, tokens: 4, unexpected: [], stretched: [], missing: [], cleanup: [], widened: [], github: { ok: false, changes: [], error: "github_not_set_up" } });
  assert.ok(cf.calls.every((c) => cf.listOnly.has(c.token) && c.method === "GET"), "reads only, never with the master");
});

test("headcount: a planted extra key is named", async () => {
  const { vault, cf } = await stored();
  await hcSetup(vault);
  cf.tokens.push({ id: "planted", name: "not from the front desk" });
  const r = await vault.headcount();
  assert.equal(r.ok, false);
  assert.deepEqual(r.unexpected, [{ id: "planted", name: "not from the front desk" }]);
});

test("headcount: a handed-out key is expected even after expiry, until its expiry is stretched", async () => {
  const { store, vault, cf, clock } = await stored();
  await hcSetup(vault);
  const exp = new Date(NOW + 5 * 60_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  cf.tokens.push({ id: "k-old", expires_on: exp });
  await store.put("master", { ...(await store.get<any>("master")), issued: [{ id: "k-old", expires_on: exp }] });
  clock.now += 60 * 60_000; // expired, still listed: Cloudflare keeps it until the next job sweeps it
  assert.ok(cfClean(await vault.headcount()));
  cf.tokens.find((t) => t.id === "k-old")!.expires_on = "2027-01-01T00:00:00Z";
  const r = await vault.headcount();
  assert.equal(r.ok, false);
  assert.deepEqual(r.stretched, [{ id: "k-old", expires_on: "2027-01-01T00:00:00Z" }]);
});

test("headcount: refuses to report ok without a headcount key or a locked master", async () => {
  const { vault } = await stored();
  assert.match((await vault.headcount()).error ?? "", /no_master_key/, "setup not yet confirmed by Ben's tap");
  await probe(vault);
  const r = await vault.headcount();
  assert.equal(r.ok, false);
  assert.match(r.error ?? "", /headcount_not_set_up/);
});

test("headcount: a list failure is not ok", async () => {
  const { vault, cf } = await stored();
  await hcSetup(vault);
  cf.tokens.length = 0;
  const r = await vault.headcount();
  assert.equal(r.ok, false, "an empty list is not a clean count: the master and headcount keys must appear");
  assert.equal(r.missing.length, 2);
});

test("after headcount setup, the jobs' own audit expects the headcount key (reads still pass)", async () => {
  const { vault } = await stored();
  await hcSetup(vault);
  const p = await probe(vault);
  assert.equal(p.ok, true, JSON.stringify(p.audit));
  const k = await readJob(vault, "cf.dns.list", { zone: ZONE });
  assert.equal(k.ok, true, JSON.stringify(k.audit));
});

test("headcount setup again: an old key that will not delete makes the result not ok, alarms nightly, and is retried", async () => {
  const { store, vault, cf } = await stored("hcOldStays");
  const first = await hcSetup(vault);
  cf.hcOld.stuck = first.key_id!;
  const second = await hcSetup(vault);
  assert.equal(second.ok, false);
  assert.match(second.error ?? "", /delete failed/);
  assert.deepEqual((await store.get<any>("headcount")).retired, [first.key_id]);
  const night = await vault.headcount();
  assert.equal(night.ok, false);
  assert.deepEqual(night.unexpected.map((t) => t.id), [first.key_id]);
  cf.hcOld.stuck = undefined;
  const third = await hcSetup(vault);
  assert.equal(third.ok, true);
  assert.ok(third.replaced.includes(first.key_id!));
  assert.deepEqual((await store.get<any>("headcount")).retired, []);
  assert.ok(cfClean(await vault.headcount()));
});

// Job cf.token.accept: Ben keeps a flagged key he made himself, as a standing exception.
const OURS = "0".repeat(31) + "1";
// A key as Cloudflare lists it: read-only on this account's zones unless told otherwise.
const policy = (group = "Zone Read", resources: Record<string, unknown> = { [`com.cloudflare.api.account.${ACCOUNT}`]: { "com.cloudflare.api.account.zone.*": "*" } }) => [
  { effect: "allow", resources, permission_groups: [{ id: "g", name: group }] },
];
// Ben's tap carries the scopes his screen showed (the desk copies them from cfPreview at /request).
const accept = async (vault: VaultLogic, ids: string, fill = 7, scopes?: string) =>
  signedRun(vault, "cf.token.accept", { ids, scopes: scopes ?? (await vault.cfPreview().catch(() => [])).map((k) => k.scope).join("\n") }, prf(fill)) as Promise<CfAcceptResult>;
const SCOPE = `allow Zone Read [g] on {"com.cloudflare.api.account.${ACCOUNT}":{"com.cloudflare.api.account.zone.*":"*"}}; no address limit; expires never`;

test("cf.token.accept: the preview names the flagged key and its real scope; after Ben's tap it is a standing exception the count and audit expect", async () => {
  const { vault, cf, store } = await stored();
  await hcSetup(vault);
  cf.tokens.push({ id: OURS, name: "observatory-backup-read", policies: policy() });
  assert.deepEqual(await vault.cfPreview(), [{ id: OURS, name: "observatory-backup-read", scope: SCOPE, over: null }]);
  assert.equal((await vault.headcount()).unexpected.length, 1);
  cf.calls.length = 0;
  const r = await accept(vault, OURS);
  assert.deepEqual(r, { ok: true, accepted: [OURS], leftover: [], master: r.master });
  assert.ok(cf.calls.every((c) => c.method === "GET"), "changes nothing in Cloudflare");
  const m = await store.get<any>("master");
  assert.deepEqual(m.exceptions.map((e: any) => [e.id, e.scope]), [[OURS, SCOPE]]);
  assert.ok(!m.baseline.includes(OURS), "an exception, not part of the setup baseline");
  assert.ok(cfClean(await vault.headcount()));
  assert.deepEqual(await vault.cfPreview(), []);
  const p = await probe(vault);
  assert.equal(p.ok, true, JSON.stringify(p.audit));
});

test("cf.token.accept: nothing is accepted for a key that is gone, already expected, or not on Ben's screen", async () => {
  const { vault, cf, store } = await stored();
  await hcSetup(vault);
  const gone = await accept(vault, OURS, 7, SCOPE);
  assert.equal(gone.ok, false);
  assert.match(gone.error ?? "", /keys_changed_since_request/);
  cf.tokens.push({ id: OURS, name: "x", policies: policy() });
  await assert.rejects(accept(vault, `${OURS},not-an-id`), /bad_params/);
  await assert.rejects(accept(vault, ""), /bad_params/);
  await assert.rejects(signedRun(vault, "cf.token.accept", { ids: OURS }, prf(7)), /bad_params/, "no scope from Ben's screen, no accept");
  assert.equal((await store.get<any>("master")).exceptions, undefined, "nothing added by a refused tap");
  assert.equal((await accept(vault, OURS)).ok, true);
  const again = await accept(vault, OURS, 7, SCOPE);
  assert.match(again.error ?? "", /keys_changed_since_request/, "an already expected key is not on any new screen");
  assert.equal((await store.get<any>("master")).exceptions.length, 1);
});

test("cf.token.accept: refused over the ceiling -- write, anything touching keys, another account, or a scope it cannot read", async () => {
  const cases: [string, any[] | undefined, RegExp][] = [
    ["write", policy("DNS Write"), /over_ceiling: .*not_read_only: DNS Write/],
    ["edit", policy("Access: Apps and Policies Edit"), /not_read_only/],
    ["keys", policy("Account API Tokens Read"), /touches_keys/],
    ["other account", policy("Zone Read", { [`com.cloudflare.api.account.${"c".repeat(32)}`]: "*" }), /outside_account/],
    ["user scope", policy("Zone Read", { "com.cloudflare.api.user.u1": "*" }), /outside_account/],
    ["unreadable", undefined, /scope_unreadable/],
  ];
  for (const [label, pol, why] of cases) {
    const { vault, cf, store } = await stored();
    await hcSetup(vault);
    cf.tokens.push({ id: OURS, name: label, policies: pol });
    const [seen] = await vault.cfPreview();
    assert.match(seen.over ?? "", new RegExp(why.source.replace("over_ceiling: .*", "")), `${label}: preview flags it`);
    const r = await accept(vault, OURS);
    assert.equal(r.ok, false, label);
    assert.match(r.error ?? "", why, label);
    assert.equal((await store.get<any>("master")).exceptions, undefined, `${label}: nothing kept`);
  }
});

test("cf.token.accept: refused when the key's scope changed after Ben's screen was made (wider than his approval)", async () => {
  const { vault, cf, store } = await stored();
  await hcSetup(vault);
  const key = { id: OURS, name: "x", policies: policy() };
  cf.tokens.push(key);
  const shown = (await vault.cfPreview())[0].scope;
  key.policies = [...policy(), ...policy("DNS Read")]; // still under the ceiling, but more than Ben saw
  const r = await accept(vault, OURS, 7, shown);
  assert.match(r.error ?? "", /scope_changed_since_request/);
  assert.equal((await store.get<any>("master")).exceptions, undefined);
});

test("cf.token.accept: needs Ben's passkey secret; a wrong one changes nothing", async () => {
  const { vault, cf, store } = await stored();
  await hcSetup(vault);
  cf.tokens.push({ id: OURS, name: "x", policies: policy() });
  await assert.rejects(accept(vault, OURS, 9));
  assert.equal((await store.get<any>("master")).exceptions, undefined);
});

test("headcount: a kept exception that later widens, or the headcount key gaining power, alarms", async () => {
  const { vault, cf, store } = await stored();
  await hcSetup(vault);
  const key = { id: OURS, name: "x", policies: policy() };
  cf.tokens.push(key);
  assert.equal((await accept(vault, OURS)).ok, true);
  // GitHub stands in as clean, so the night's verdict turns on Cloudflare alone.
  (vault as any).ghHeadcount = async () => ({ ok: true, changes: [] });
  assert.equal((await vault.headcount()).ok, true, "clean with the exception as approved");
  key.policies = [...policy(), ...policy("DNS Read")];
  let night = await vault.headcount();
  assert.equal(night.ok, false, "a widened key fails the night");
  assert.deepEqual(night.widened, [{ id: OURS, why: "scope_changed_since_approved" }]);
  // Exception record says it was approved wider than the ceiling (only reachable by a stored-state edit): still alarms.
  const m = await store.get<any>("master");
  m.exceptions[0].scope = `allow DNS Write [g] on {"com.cloudflare.api.account.${ACCOUNT}":"*"}; no address limit; expires never`;
  await store.put("master", m);
  key.policies = policy("DNS Write", { [`com.cloudflare.api.account.${ACCOUNT}`]: "*" });
  night = await vault.headcount();
  assert.deepEqual(night.widened, [{ id: OURS, why: "not_read_only: DNS Write" }]);
  // The headcount key itself.
  const hcId = (await store.get<any>("headcount")).token_id;
  key.policies = policy();
  m.exceptions[0].scope = SCOPE;
  await store.put("master", m);
  const hc = cf.tokens.find((t) => t.id === hcId)!;
  hc.policies = [...hc.policies!, ...policy("DNS Read")];
  night = await vault.headcount();
  assert.deepEqual(night.widened, [{ id: hcId, why: "headcount_key_not_list_only" }]);
  hc.policies = undefined;
  assert.deepEqual((await vault.headcount()).widened, [{ id: hcId, why: "headcount_key_not_list_only" }], "an unreadable scope never passes");
});

test("TOKENS_READ: only Cloudflare's exact account-level list-keys group passes (Codex Build R r1 #1)", () => {
  assert.ok(TOKENS_READ.test("Account API Tokens Read"));
  for (const other of ["API Tokens Read", "Account API Tokens Write", "Account API Tokens Read ", "x Account API Tokens Read"]) assert.ok(!TOKENS_READ.test(other), other);
});

test("scope identity (Codex Build R r1b #1-#3): a same-name group with another id, an unknown effect, or a lifted address or time limit counts as a change", async () => {
  // Before the tap: what Ben saw no longer matches.
  {
    const { vault, cf, store } = await stored();
    await hcSetup(vault);
    const key: any = { id: OURS, name: "x", policies: policy() };
    cf.tokens.push(key);
    const shown = (await vault.cfPreview())[0].scope;
    key.policies = [{ ...policy()[0], permission_groups: [{ id: "zone-level-logs", name: "Zone Read" }] }];
    assert.match((await accept(vault, OURS, 7, shown)).error ?? "", /scope_changed_since_request/, "same name, other id");
    assert.equal((await store.get<any>("master")).exceptions, undefined);
  }
  // After the tap: the nightly count alarms on each kind of change.
  const changes: [string, (k: any) => void][] = [
    ["same name, other id", (k) => (k.policies = [{ ...policy()[0], permission_groups: [{ id: "other", name: "Zone Read" }] }])],
    ["address limit lifted", (k) => delete k.condition],
    ["expiry pushed later", (k) => (k.expires_on = "2099-01-01T00:00:00Z")],
    ["not-before changed", (k) => (k.not_before = "2026-01-01T00:00:00Z")],
  ];
  for (const [label, change] of changes) {
    const { vault, cf } = await stored();
    await hcSetup(vault);
    const key: any = { id: OURS, name: "x", policies: policy(), condition: { request_ip: { in: ["198.51.100.7/32"] } }, expires_on: "2027-01-01T00:00:00Z" };
    cf.tokens.push(key);
    const [seen] = await vault.cfPreview();
    assert.match(seen.scope, /condition .*198\.51\.100\.7\/32.*expires 2027-01-01/, `${label}: the screen shows the key's limits`);
    assert.equal((await accept(vault, OURS)).ok, true, label);
    assert.deepEqual((await vault.headcount()).widened, [], `${label}: clean as approved`);
    change(key);
    assert.deepEqual((await vault.headcount()).widened, [{ id: OURS, why: "scope_changed_since_approved" }], label);
  }
});

test("scope readability (Codex Build R r1b #2): a missing or unknown effect is unreadable -- refused at the tap and alarmed at night", async () => {
  for (const effect of [undefined, "", "permit"]) {
    const { vault, cf, store } = await stored();
    await hcSetup(vault);
    cf.tokens.push({ id: OURS, name: "x", policies: [{ ...policy()[0], effect }] });
    assert.match((await accept(vault, OURS, 7, "x")).error ?? "", /over_ceiling: .*scope_unreadable/, String(effect));
    assert.equal((await store.get<any>("master")).exceptions, undefined);
    const hcId = (await store.get<any>("headcount")).token_id;
    const hc = cf.tokens.find((t) => t.id === hcId)!;
    hc.policies = [{ ...hc.policies![0], effect }];
    assert.deepEqual((await vault.headcount()).widened, [{ id: hcId, why: "headcount_key_not_list_only" }], `headcount key, effect ${String(effect)}`);
  }
});

test("headcount key identity (Codex Build R r2 #1): setup records its group id; a same-name group with another id alarms; a key made before Build R asks for the setup tap", async () => {
  const { vault, cf, store } = await stored();
  await hcSetup(vault);
  const kept = await store.get<any>("headcount");
  assert.equal(kept.group_id, "tok-r", "the id from Cloudflare's own group list");
  assert.deepEqual((await vault.headcount()).widened, []);
  const hc = cf.tokens.find((t) => t.id === kept.token_id)!;
  hc.policies = [{ ...hc.policies![0], permission_groups: [{ id: "look-alike", name: "Account API Tokens Read" }] }];
  assert.deepEqual((await vault.headcount()).widened, [{ id: kept.token_id, why: "headcount_key_not_list_only" }], "same name, other id");
  hc.policies = [{ ...hc.policies![0], permission_groups: [{ id: "tok-r", name: "Account API Tokens Read" }] }];
  await store.put("headcount", { ...kept, group_id: undefined });
  assert.deepEqual((await vault.headcount()).widened, [{ id: kept.token_id, why: "headcount_key_needs_setup" }], "made before Build R");
  assert.equal((await hcSetup(vault)).ok, true);
  assert.deepEqual((await vault.headcount()).widened, [], "the setup tap records the id and the night is clean again");
});

// Card build 3 (85818ab1) F9 (V5/W2): the heaviest card entry's subrequests in one vault invocation -- cf.dns.list
// with more than DNS_MAX records, paged 100 at a time -- through runCardEntry, today's tap path. Asserted so a change
// that adds calls is seen. Each short vault key left over from an earlier tap adds one DELETE (sweepHelpers).
test("F9: one cf.dns.list card entry at DNS_MAX makes a fixed, counted number of Cloudflare calls", async () => {
  const { store, cf } = await stored();
  const rows = Array.from({ length: 1000 }, (_, i) => ({ id: `r${i}`, type: "A", name: `h${i}.${ZONE}`, content: "192.0.2.1" }));
  let fetches = 0;
  const v = testVault(store, async (input: string, init?: RequestInit) => {
    fetches++;
    const u = new URL(String(input));
    if (u.pathname.includes("/dns_records")) {
      const page = Number(u.searchParams.get("page")), per = Number(u.searchParams.get("per_page"));
      return Response.json({ success: true, result: rows.slice((page - 1) * per, page * per) });
    }
    return cf.fetchFn(input as string, init);
  }, () => NOW);
  await readJob(v, "cf.zone.read", { zone: ZONE }); // the first tap locks the master key to the passkey
  fetches = 0;
  cf.calls.length = 0;
  const r = (await v.runCardEntry("cf.dns.list", { zone: ZONE }, prf(7))) as ReadResult;
  assert.equal(r.ok, true);
  assert.equal(r.truncated, true);
  const byKind = cf.calls.map((c) => `${c.method} ${c.path.split("?")[0].replace(/[0-9a-f]{32}|minted\d+/g, "<id>")}`);
  // Measured 2026-11-08: permission groups, mint + delete for the zone lookup key, zone lookup, mint + delete for the DNS
  // key, the leftover-key list, and 6 DNS pages (1000 rows: pages 1-6 until more than 500 are held).
  assert.equal(fetches, 13, `measured: ${JSON.stringify(byKind)} + 6 DNS pages`);
});

// F9 with a planted cleanup backlog (Codex build r1 R7): five expired handed-out keys and five leftover short keys.
// Each sweep sends at most SWEEP_DELETES deletes per tap; the rest stay recorded and go at later taps.
test("F9: a cleanup backlog adds a fixed number of calls per tap (SWEEP_DELETES per sweep); the rest waits for later taps", async () => {
  const { store, cf, clock } = await stored();
  let fetches = 0;
  const rows = Array.from({ length: 1000 }, (_, i) => ({ id: `r${i}`, type: "A", name: `h${i}.${ZONE}`, content: "192.0.2.1" }));
  const v = testVault(store, async (input: string, init?: RequestInit) => {
    fetches++;
    const u = new URL(String(input));
    if (u.pathname.includes("/dns_records")) {
      const page = Number(u.searchParams.get("page")), per = Number(u.searchParams.get("per_page"));
      return Response.json({ success: true, result: rows.slice((page - 1) * per, page * per) });
    }
    return cf.fetchFn(input as string, init);
  }, () => clock.now);
  await readJob(v, "cf.zone.read", { zone: ZONE });
  const exp = new Date(clock.now + 60_000).toISOString();
  const issued = Array.from({ length: 5 }, (_, i) => ({ id: `${"a".repeat(31)}${i}`, expires_on: exp }));
  const helpers = Array.from({ length: 5 }, (_, i) => ({ name: `${HELPER_PREFIX}old${i}`, until: exp, id: `${"b".repeat(31)}${i}` }));
  for (const k of issued) cf.tokens.push({ id: k.id, expires_on: exp });
  for (const h of helpers) cf.tokens.push({ id: h.id, name: h.name });
  await store.put("master", { ...(await store.get<any>("master")), issued });
  await store.put("helpers", helpers);
  clock.now += 2 * 60_000;
  fetches = 0;
  const r = (await v.runCardEntry("cf.dns.list", { zone: ZONE }, prf(7))) as ReadResult;
  assert.equal(r.ok, true);
  // 13 as measured above + SWEEP_DELETES handed-out deletes + 1 token-list page for the short-key sweep + SWEEP_DELETES
  // short-key deletes = 16 at SWEEP_DELETES 1. Two cf.dns.list entries on one card: 15 desk + 2 x 16 = 47 < 50.
  assert.equal(SWEEP_DELETES, 1, "F9-MAP-85818ab1.md's 47-call total for two DNS entries assumes 1");
  assert.equal(fetches, 13 + SWEEP_DELETES + 1 + SWEEP_DELETES);
  assert.equal((await store.get<any>("master")).issued.length, 5 - SWEEP_DELETES, "the rest stays recorded");
  assert.equal((await store.get<any[]>("helpers"))!.length, 5 - SWEEP_DELETES);
  assert.equal(r.leftover?.length, 5 - SWEEP_DELETES, "and is shown on this tap's result");
  // Safeguard working: later taps keep clearing it.
  for (let i = 0; i < Math.ceil(5 / SWEEP_DELETES); i++) await v.runCardEntry("cf.dns.list", { zone: ZONE }, prf(7));
  assert.equal((await store.get<any>("master")).issued.length, 0);
  assert.deepEqual(await store.get<any[]>("helpers"), []);
});
