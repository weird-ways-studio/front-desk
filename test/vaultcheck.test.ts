// The vault checks Ben's passkey itself on every tap (card bb86abf0; studio-os REFINE-bb86abf0.md v2.1).
// Each safeguard is shown working, then refusing its unsafe case (instruction.control-must-refuse-unsafe-case).
// "Got past admission" shows as no_master_key: the test vault holds no key, so the job stops right after the
// admission step, before anything is unlocked. A refusal shows as its own code, and no Cloudflare call is made.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Desk, MemoryStore, grantHash, vaultStage, type Grant } from "../src/desk.ts";
import { JOBS } from "../src/jobs.ts";
import { ALREADY_USED, REFUSED_BEFORE_RUN, USED_GRACE_MS, checkSigned, type SignedRun } from "../vault/src/approval.ts";
import { approvalCheck, grantHashOf, PASSKEY_PIN, type PasskeyPin } from "../vault/src/passkey.ts";
import { VaultLogic } from "../vault/src/vault.ts";
import { FakeRecorder } from "./fakerecorder.ts";
import { SoftKey } from "./softkey.ts";
import { TEST_PIN, pinOf, signed } from "./vaultsign.ts";

const T = 1_800_000_000_000;
const PRF = Buffer.from(new Uint8Array(32).fill(7)).toString("base64url");
const ZONE = { zone: "benculbert.com" };
const PASSED = /no_master_key/; // reached the job: the admission step let it through

function vaultAt(clock = { now: T }, pin: PasskeyPin | undefined = TEST_PIN) {
  const store = new MemoryStore();
  let calls = 0;
  const vault = new VaultLogic(store, async () => (calls++, Response.json({ success: false })), () => clock.now, pin);
  return { vault, store, clock, calls: () => calls };
}
const until = (ms: number) => ({ expires_at: T + ms });

// ---- R4: the vault's copy gives the recorder's own verdict on every fixed answer ----
const vectors = JSON.parse(readFileSync("test/fixtures/passkey-vectors.json", "utf8"));

test("shared vectors: the vault's copy of the recorder's check gives the recorder's verdict on every case", async () => {
  const check = approvalCheck(vectors.pin);
  const g = vectors.grant;
  assert.ok(vectors.cases.length >= 15);
  assert.equal(vectors.cases.filter((c: { verdict: string | null }) => c.verdict === null).length, 1, "exactly one valid answer");
  for (const c of vectors.cases) {
    const verdict = await check({ v: 1, grant: g.id, stage: "approval", job: g.job, assertion: c.assertion }, vectors.grant_hash);
    assert.equal(verdict ?? null, c.verdict, c.name);
  }
});

test("shared vectors: desk, vault and recorder hash the same grant to the same value", async () => {
  const g = vectors.grant;
  assert.equal(await grantHash(g), vectors.grant_hash);
  assert.equal(await grantHashOf({ v: 1, grant: g.id, stage: "request", job: g.job, params: g.params, requester: g.requester, expires_at: g.expires_at }), vectors.grant_hash);
});

test("shared vectors through vault.run: only the valid answer gets past the check", async () => {
  for (const c of vectors.cases) {
    const { vault } = vaultAt({ now: vectors.grant.expires_at }, vectors.pin);
    const run = vault.run({ grant: vectors.grant, assertion: c.assertion, prf: PRF });
    await assert.rejects(run, c.verdict === null ? PASSED : /^Error: bad_assertion$/, c.name);
  }
});

test("the vault pins the same passkey as the recorder (values copied in passkey.ts)", () => {
  assert.ok(PASSKEY_PIN, "a pin is set");
  assert.equal(PASSKEY_PIN!.id.length > 20, true);
  assert.match(PASSKEY_PIN!.rp_hash, /^[0-9a-f]{64}$/);
  assert.match(PASSKEY_PIN!.origin_hash, /^[0-9a-f]{64}$/);
});

// ---- Outcome 1: the vault runs only what Ben's passkey signed ----
test("a correctly signed grant gets past the check; nothing is called before the job", async () => {
  const { vault, calls } = vaultAt();
  await assert.rejects(vault.run(await signed("cf.zone.read", ZONE, PRF, until(60_000))), PASSED);
  assert.equal(calls(), 0);
});

test("refused: the desk changes any signed field after Ben's tap (params, job, id, requester, expiry)", async () => {
  const changes: [string, (g: SignedRun["grant"]) => SignedRun["grant"]][] = [
    ["params", (g) => ({ ...g, params: { zone: "weirdways.studio" } })],
    ["job", (g) => ({ ...g, job: "cf.dns.list" })],
    ["id", (g) => ({ ...g, id: "g-other" })],
    ["requester", (g) => ({ ...g, requester: "someone else" })],
    ["expires_at", (g) => ({ ...g, expires_at: g.expires_at + 60_000 })],
  ];
  for (const [field, change] of changes) {
    const { vault, calls } = vaultAt();
    const s = await signed("cf.zone.read", ZONE, PRF, until(60_000));
    await assert.rejects(vault.run({ ...s, grant: change(s.grant) }), /^Error: bad_assertion$/, field);
    // Safeguard working: the unchanged call passes.
    await assert.rejects(vault.run(s), PASSED, field);
    assert.equal(calls(), 0);
  }
});

test("refused: one grant's answer used for another grant (an excluded job)", async () => {
  const { vault } = vaultAt();
  const approved = (await signed("cf.zone.read", ZONE, PRF, until(60_000))).grant;
  const other = await signed("cf.token.accept", { ids: "x", scopes: "y" }, PRF, { ...until(60_000), signedFor: approved });
  await assert.rejects(vault.run(other), /^Error: bad_assertion$/);
});

test("refused: no answer, another passkey, no Face ID, another site", async () => {
  const other = await SoftKey.create();
  const cases: [string, () => Promise<SignedRun>][] = [
    ["empty answer", async () => ({ ...(await signed("cf.zone.read", ZONE, PRF, until(60_000))), assertion: {} as SignedRun["assertion"] })],
    ["another passkey", () => signed("cf.zone.read", ZONE, PRF, { ...until(60_000), key: other })],
    ["no user verification", () => signed("cf.zone.read", ZONE, PRF, { ...until(60_000), userVerified: false })],
    ["wrong origin", () => signed("cf.zone.read", ZONE, PRF, { ...until(60_000), origin: "https://evil.example" })],
    ["wrong rp", () => signed("cf.zone.read", ZONE, PRF, { ...until(60_000), rp: "evil.example" })],
  ];
  for (const [name, make] of cases) {
    const { vault } = vaultAt();
    await assert.rejects(vault.run(await make()), /^Error: bad_assertion$/, name);
  }
  // Safeguard working: the other passkey passes once it is the pinned one.
  const { vault } = vaultAt({ now: T }, await pinOf(other));
  await assert.rejects(vault.run(await signed("cf.zone.read", ZONE, PRF, { ...until(60_000), key: other })), PASSED);
});

test("refused: no pin, or an unreadable pin, refuses every vault job (fail closed)", async () => {
  const s = await signed("cf.zone.read", ZONE, PRF, until(60_000));
  await assert.rejects(checkSigned(s, 0, undefined), /^Error: no_pin$/);
  const broken = { ...TEST_PIN, key: "not-a-cose-key" };
  await assert.rejects(vaultAt({ now: T }, broken).vault.run(s), /^Error: bad_assertion$/);
  assert.equal((await checkSigned(s, 0, TEST_PIN)).grant.id, s.grant.id); // safeguard working
});

// ---- R2: the recorder's input checks ----
test("refused as bad_grant: params not all text, missing requester, unsafe or -0 expiry, extra or missing fields", async () => {
  const s = await signed("cf.zone.read", ZONE, PRF, until(60_000));
  const bad: [string, unknown][] = [
    ["number param", { ...s.grant, params: { zone: 5 } }],
    ["nested param", { ...s.grant, params: { zone: { a: "b" } } }],
    ["array params", { ...s.grant, params: ["benculbert.com"] }],
    ["no requester", { ...s.grant, requester: undefined }],
    ["unsafe expiry", { ...s.grant, expires_at: 2 ** 53 }],
    ["fractional expiry", { ...s.grant, expires_at: T + 0.5 }],
    ["-0 expiry", { ...s.grant, expires_at: -0 }],
    ["number id", { ...s.grant, id: 7 }],
    ["empty id", { ...s.grant, id: "" }],
    ["extra field", { ...s.grant, reason: "x" }],
  ];
  for (const [name, grant] of bad) {
    const { vault } = vaultAt();
    await assert.rejects(vault.run({ ...s, grant } as SignedRun), /^Error: bad_grant$/, name);
  }
});

test("refused as wrong_shape: the old call (job, params, prf), extra or missing parts, a bad passkey secret", async () => {
  const s = await signed("cf.zone.read", ZONE, PRF, until(60_000));
  const { vault } = vaultAt();
  const old = vault.run as unknown as (...a: unknown[]) => Promise<unknown>;
  await assert.rejects(old.call(vault, "cf.zone.read", ZONE, PRF), /^Error: wrong_shape$/);
  await assert.rejects(old.call(vault, s, "extra"), /^Error: wrong_shape$/);
  for (const req of [null, "x", [s], { grant: s.grant, assertion: s.assertion }, { ...s, more: 1 }, { ...s, prf: "short" }, { ...s, prf: 7 }]) {
    await assert.rejects(vault.run(req as SignedRun), /^Error: wrong_shape$/, JSON.stringify(req)?.slice(0, 40));
  }
});

// ---- Outcome 2 and R1: once only, one admission step ----
test("a grant runs once: a replay after it ran is refused already_used", async () => {
  const { vault } = vaultAt();
  const s = await signed("cf.zone.read", ZONE, PRF, until(60_000));
  await assert.rejects(vault.run(s), PASSED);
  await assert.rejects(vault.run(s), /^Error: already_used$/);
  // Even with a fresh answer for the same grant (the id is what counts, and the signed hash covers it).
  await assert.rejects(vault.run(await signed("cf.zone.read", ZONE, PRF, { ...until(60_000), id: s.grant.id })), /^Error: already_used$/);
});

test("two calls at once for one grant: exactly one gets past admission", async () => {
  const { vault } = vaultAt();
  const s = await signed("cf.zone.read", ZONE, PRF, until(60_000));
  const out = await Promise.allSettled([vault.run(s), vault.run(s)]);
  const why = out.map((o) => (o.status === "rejected" ? String((o.reason as Error).message) : "ran")).sort();
  assert.deepEqual(why, ["already_used", "no_master_key"]);
});

test("a refusal before admission does not use up the grant", async () => {
  const { vault } = vaultAt();
  const s = await signed("cf.zone.read", ZONE, PRF, until(60_000));
  await assert.rejects(vault.run({ ...s, grant: { ...s.grant, params: { zone: "weirdways.studio" } } }), /bad_assertion/);
  await assert.rejects(vault.run(s), PASSED);
});

test("expiry: allowed up to expires_at + 5 minutes, refused after", async () => {
  const s = await signed("cf.zone.read", ZONE, PRF, until(0));
  await assert.rejects(vaultAt({ now: T + USED_GRACE_MS }).vault.run(s), PASSED);
  await assert.rejects(vaultAt({ now: T + USED_GRACE_MS + 1 }).vault.run(s), /^Error: expired$/);
});

test("the clock is read again after the crypto: an answer checked in time but admitted late is refused", async () => {
  const { vault, clock } = vaultAt();
  const s = await signed("cf.zone.read", ZONE, PRF, until(0));
  const pending = vault.run(s); // its signature check is in flight
  clock.now = T + USED_GRACE_MS + 1;
  await assert.rejects(pending, /^Error: expired$/);
});

test("pruning: an id is forgotten only once its grant is past expiry, so a paused replay of it is refused", async () => {
  const { vault, store, clock } = vaultAt();
  const a = await signed("cf.zone.read", ZONE, PRF, until(0));
  await assert.rejects(vault.run(a), PASSED);
  // A replay of A starts (its crypto in flight) while A is still within its time...
  const replay = assert.rejects(vault.run(a), /^Error: expired$/, "the replay resumes after the prune and is refused");
  // ...meanwhile time passes and another grant's admission prunes A's id.
  clock.now = T + USED_GRACE_MS + 1;
  await assert.rejects(vault.run(await signed("cf.zone.read", ZONE, PRF, until(USED_GRACE_MS * 2))), PASSED);
  assert.equal((await store.get<Map<string, number>>("used"))!.has(a.grant.id), false, "A was pruned");
  await replay;
  assert.equal((await store.get<Map<string, number>>("used"))!.size, 1, "the list stays small");
});

test("pruning and expiry share one boundary: at the last allowed moment the id is still kept, so a replay is already_used", async () => {
  const { vault, store, clock } = vaultAt();
  const a = await signed("cf.zone.read", ZONE, PRF, until(0));
  await assert.rejects(vault.run(a), PASSED);
  clock.now = T + USED_GRACE_MS; // A is still within its time
  await assert.rejects(vault.run(await signed("cf.zone.read", ZONE, PRF, until(USED_GRACE_MS))), PASSED);
  assert.equal((await store.get<Map<string, number>>("used"))!.has(a.grant.id), true, "not pruned while A could still be admitted");
  await assert.rejects(vault.run(a), /^Error: already_used$/);
});

// ---- R6: the three result messages, chosen by the exact code ----
test("result words: each before-admission code says nothing ran; already_used says it may have run; anything else is unknown", () => {
  const words = (error: string) => JOBS["cf.zone.read"].done({ error, vault_stage: vaultStage(error) });
  for (const code of REFUSED_BEFORE_RUN) assert.match(words(code), /^Nothing ran\. The vault refused this approval: .+\. Ask for it again\. \[/, code);
  assert.match(words(ALREADY_USED), /^This approval was already used once, so it may have run\. Check its result before asking again\./);
  for (const other of ["no_master_key", "cf_500: boom", "Error: bad_assertion", "bad_assertion ", "expired: late", "", "job_not_offered"]) {
    assert.match(words(other), /^It is not known whether this ran\. Check its result before asking again\./, JSON.stringify(other));
  }
  // Every vault job's words follow the same three messages.
  for (const job of Object.keys(JOBS) as (keyof typeof JOBS)[]) {
    if (!(JOBS[job] as { vault?: true }).vault) continue;
    assert.match(JOBS[job].done({ error: "expired", vault_stage: "before" }), /^Nothing ran\./, job);
    assert.match(JOBS[job].done({ error: "x", vault_stage: "unknown" }), /^It is not known whether this ran\./, job);
  }
});

test("vaultStage matches the exact message only, never a part of it", () => {
  for (const code of REFUSED_BEFORE_RUN) assert.equal(vaultStage(code), "before", code);
  assert.equal(vaultStage(ALREADY_USED), "used");
  for (const m of ["Error: bad_assertion", "bad_assertion ", "expired: late", "wrong_shape\n", "not already_used", "", "no_master_key"]) assert.equal(vaultStage(m), "unknown", JSON.stringify(m));
});

test("the before-admission codes are thrown only by the vault's check, never later in a job", () => {
  for (const f of ["vault.ts", "runs.ts", "github.ts", "cloudflare.ts", "seal.ts", "setup.ts", "ghsetup.ts", "index.ts"]) {
    const src = readFileSync(`vault/src/${f}`, "utf8");
    for (const code of [...REFUSED_BEFORE_RUN, ALREADY_USED]) assert.ok(!src.includes(`VaultError("${code}")`), `${f} throws ${code}`);
  }
});

// ---- The desk sends what the vault checks, and maps what comes back ----
const site = { origin: "https://desk.example", rpID: "desk.example" };
async function deskWith(vaultFor: (key: SoftKey) => Promise<unknown>) {
  const rec = new FakeRecorder();
  const store = new MemoryStore();
  const key = await SoftKey.create();
  const vault = (await vaultFor(key)) as never;
  const desk = new Desk(store, site, { recorder: rec.send, vault });
  await desk.enroll(await key.register(await desk.enrollOptions(T), site.origin), T);
  const g = await desk.request({ job: "cf.token.headcount.setup", params: {}, reason: "prove the vault check" }, "agent", T);
  const options = await desk.approvalOptions(g.id, T);
  const answer = { ...(await key.assert(options.challenge, site.rpID, site.origin)), prf: PRF };
  return { desk, g, answer };
}
const summary = (g: Grant) => JOBS[g.job].done(g.result);

test("desk -> real vault: the desk's call passes the vault's own check (gets to the job)", async () => {
  let seen: SignedRun | undefined;
  const { desk, g, answer } = await deskWith(async (key) => {
    const real = new VaultLogic(new MemoryStore(), async () => Response.json({}), () => T, await pinOf(key));
    return { approvalApi: async () => ({ version: 1 }), run: (req: SignedRun) => ((seen = req), real.run(req)) };
  });
  const done = await desk.approve(g.id, answer as never, T);
  assert.deepEqual(done.result, { error: "no_master_key", vault_stage: "unknown" });
  assert.deepEqual(seen!.grant, { id: g.id, job: g.job, params: g.params, requester: g.requester, expires_at: g.expires_at });
  assert.equal(await grantHash(seen!.grant as Grant), g.hash);
});

test("desk -> vault refusing before admission: Ben reads 'Nothing ran ... Ask for it again'", async () => {
  const { desk, g, answer } = await deskWith(async () => ({ approvalApi: async () => ({ version: 1 }), run: async () => { throw new Error("bad_assertion"); } }));
  assert.match(summary(await desk.approve(g.id, answer as never, T)), /^Nothing ran\./);
});

test("desk -> old vault (no approvalApi): run is never called, and it reads as wrong_shape", async () => {
  let ran = 0;
  const { desk, g, answer } = await deskWith(async () => ({ run: async () => { ran++; return { ok: true }; }, approvalApi: async () => { throw new Error("The RPC receiver does not implement the method \"approvalApi\"."); } }));
  const done = await desk.approve(g.id, answer as never, T);
  assert.equal(ran, 0);
  assert.deepEqual(done.result, { error: "wrong_shape", vault_stage: "before" });
  assert.match(summary(done), /^Nothing ran\. The vault refused this approval: the front desk and the vault were on different versions/);
});

test("desk -> vault failures that are not a known before-admission code read as unknown, never 'Nothing ran'", async () => {
  const throws: unknown[] = [new Error("cf_500: provider down"), new Error("Error: bad_assertion"), "bad_assertion", { message: "bad_assertion" }, new Error("already_used ")];
  for (const t of throws) {
    const { desk, g, answer } = await deskWith(async () => ({ approvalApi: async () => ({ version: 1 }), run: async () => { throw t; } }));
    const s = summary(await desk.approve(g.id, answer as never, T));
    assert.match(s, /^It is not known whether this ran\./, String(t));
  }
  const { desk, g, answer } = await deskWith(async () => ({ approvalApi: async () => ({ version: 1 }), run: async () => { throw new Error(ALREADY_USED); } }));
  assert.match(summary(await desk.approve(g.id, answer as never, T)), /^This approval was already used once/);
});
