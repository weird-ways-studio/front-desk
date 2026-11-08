// The vault's rules: it holds the master key (a Cloudflare token that can make other
// tokens) only in sealed form, opens it only with the secret Ben's passkey releases at
// his tap, uses it for one job from a fixed list, and never returns it.
// Design: studio-os docs/specifications/face-id-access/C4-SPIKE.md sections 3.4-3.7.

import { Cloudflare, type Fetch } from "./cloudflare.ts";
import { STUDIO_ZONES } from "./zones.ts";
import { GitHub, appJwt, canonical, checkApp, checkInstallation, convert, diff, installationKey, pkcs8FromPem, sha256Hex, snapshot, type AppKind, type GhSnapshot } from "./github.ts";
import { admit, checkSigned } from "./approval.ts";
import { PASSKEY_PIN, type PasskeyPin } from "./passkey.ts";
import { MASTER_LABEL, RECOVERY_LABEL, VaultError, b64url, fromB64url, open, seal, secretBytes, type Sealed } from "./seal.ts";

export const PROBE_TOKEN_MS = 5 * 60_000;
// Every short key the vault makes for itself (withKey) is named with this prefix, so the nightly count
// can tell a leftover helper from anything else, and cf.token.accept never adopts one (card ae6147e4 R10).
export const HELPER_PREFIX = "front-desk probe ";
// The read jobs (card ae6147e4 4a-1): what an agent may read, and how much comes back. The caps keep a
// result inside one storage value; a cut list says so (`truncated`).
export const READ_JOBS = ["cf.zone.read", "cf.dns.list", "cf.audit.read"] as const;
export const DNS_MAX = 500;
export const AUDIT_MAX = 300;
export const AUDIT_MAX_DAYS = 7;
// A read's answer is stored in the grant until the agent collects it. Durable Object storage holds at most
// 128 KiB per value (FROM MEMORY; the grant also carries other fields), so the answer is cut to this many
// bytes of JSON, whole rows at a time, and marked `truncated` (Codex 4a-1 r1 #5).
export const RESULT_MAX_BYTES = 64_000;
// Setup waits this long for Ben's first Face ID tap to lock the key to his passkey.
export const PENDING_MS = 30 * 60_000;
const PENDING_LABEL = "front-desk pending-key v1";
// GitHub (card C6a-1): the main App's key is locked to Ben's passkey under its own label, so a
// box sealed for the Cloudflare master never opens as the GitHub key, or the reverse.
export const GH_LABEL = "github-app-key v1";
// Creating and installing two Apps, then the agent's request and Ben's tap, take longer than the
// Cloudflare paste; the main key waits sealed under a one-time key for at most this long.
export const GH_PENDING_MS = 60 * 60_000;
// GitHub's manifest code is good for one hour; the vault's matching `state` lasts as long.
export const GH_STATE_MS = 60 * 60_000;
// How GitHub refuses an installation key with permissions the App was not given: VERIFIED live
// 2026-10-28 (grant 8db03e71), exactly this. Anything else -- an outage, another 422 -- proves nothing.
export const GH_ESCALATION_REFUSAL = /^gh_422: The level of access for permissions requested are not granted to this installation\.$/;

export interface VaultStore {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
}

interface Master {
  account_id: string;
  token_id: string;
  // Locked to Ben's passkey secret. Absent until his first tap after setup.
  by_passkey?: Sealed;
  // Between setup and that tap: the token sealed under a one-time key the vault holds.
  pending?: { key: string; box: Sealed; until: number };
  by_recovery: Sealed;
  stored_at: number;
  // Token ids the audit expects (ids are not secrets): those in the account at setup, plus keys Ben
  // accepted since with job cf.token.accept.
  baseline: string[];
  // Keys handed to the agent and not yet deleted. Cloudflare keeps expired keys listed, so the
  // vault deletes these once expired, at its next job, and the audit expects them (Codex minted r1 #6).
  issued?: { id: string; expires_on: string }[];
  // Keys the front desk did not make that Ben keeps, each added only by his tap on cf.token.accept,
  // with the scope his screen showed (cutover Build R 2c19a923 step 3). The agent cannot write this.
  exceptions?: Exception[];
}

interface Exception {
  id: string;
  name: string;
  scope: string; // scopeWords() as Ben's screen showed it
  at: number;
}

// The nightly headcount's own key: it can list the account's keys and nothing else. Minted once by
// the Ben-approved job cf.token.headcount.setup, then kept in vault storage UNSEALED, because the
// nightly run has no Ben tap to open anything with (C5c-2 3baea7cc; C5c-1 retro learning 4).
// A standing credential by Ben's choice on that job's screen; it holds no power to mint or change.
interface HeadcountKey {
  token_id: string;
  value: string;
  made_at: number;
  // The id of the one permission group it was made with (Account API Tokens Read), read from Cloudflare's own
  // group list at setup. The nightly check compares the live key's group to this id, not to a name (Codex
  // Build R r2 #1). Missing on keys made before Build R: the night alarms until Ben re-runs the setup.
  group_id?: string;
  // Old headcount keys a replacement could not delete. Not expected by the count, so they alarm
  // nightly until the next setup deletes them.
  retired?: string[];
}

export interface HeadcountSetupResult {
  leftover?: string[]; // earlier short keys this tap's sweep could not confirm deleted (R10)
  ok: boolean; // true only when the new key could list and was refused a mint
  master: { token_id: string; locked_to_passkey_now: boolean };
  key_id: string | null;
  lists: boolean;
  mint_refused: boolean;
  mint_error?: string;
  replaced: string[]; // previous headcount keys, deleted
  error?: string;
}

// The GitHub Apps. Ids and names are not secrets. The headcount App's key is kept unsealed for the
// nightly run (no Ben tap), and it only reads; the main App's key is sealed like the master.
interface GhApp {
  id: number;
  slug: string;
  installation?: number;
}
interface GhHeadcountApp extends GhApp {
  key: string; // PKCS#8, base64url
}
interface GhMainApp extends GhApp {
  by_passkey?: Sealed;
  pending?: { key: string; box: Sealed; until: number };
}

// Job cf.token.accept: which unexpected keys Ben's tap added to what the audit expects.
export interface CfAcceptResult {
  leftover?: string[]; // earlier short keys this tap's sweep could not confirm deleted (R10)
  ok: boolean;
  accepted: string[];
  master: { token_id: string; locked_to_passkey_now: boolean };
  error?: string;
}

export interface GhBaselineResult {
  ok: boolean; // true only when both Apps work, the read-only App was refused write, and the list was taken
  main: { app_id: number; locked_to_passkey_now: boolean; key_works: boolean };
  headcount: { app_id: number; write_refused: boolean; write_error?: string };
  counts: Record<string, number>;
  changes: string[]; // against the previous expected list ("first list" the first time)
  error?: string;
}

export interface Headcount {
  ok: boolean; // true only when every listed key is expected, none outlives its recorded expiry, none is missing, and GitHub matches
  tokens: number;
  unexpected: { id: string; name: string }[];
  // Handed-out keys whose listed expiry is later than the one the vault recorded when it made them.
  stretched: { id: string; expires_on: string }[];
  // The master and the headcount key must be on the list; a list without them is not the account's.
  missing: string[];
  // The vault's own short keys still listed (a failed or lost delete). Expiry is Cloudflare's, never assumed.
  // `recorded`: the vault made it and deletes it at the next Cloudflare tap. Not recorded: a key from
  // outside borrowing the helper name, which the vault never deletes (Codex 4a-1 r1 #3).
  cleanup: { id: string; expires_on: string; expired: boolean; recorded: boolean }[];
  // GitHub against the list Ben accepted with job gh.app.baseline: every addition or removal.
  github: { ok: boolean; changes: string[]; error?: string };
  // Kept keys now wider than Ben approved or than the ceiling, and a headcount key no longer list-only.
  widened?: { id: string; why: string }[];
  error?: string;
}

// A read job's answer. Only `data` is the reading; the rest is what the vault did to get it.
export interface ReadResult {
  leftover?: string[]; // earlier short keys this tap's sweep could not confirm deleted (R10)
  ok: boolean; // true only when the read came back and every short key was deleted
  master: { token_id: string; locked_to_passkey_now: boolean };
  job: string;
  data?: unknown;
  truncated?: boolean;
  minted: { id: string; deleted: boolean }[];
  audit: { tokens: number; minted_still_listed: string[]; new_since_setup: string[]; error?: string };
  error?: string;
}

// A short key's intent, stored before it is made and kept until its delete is confirmed (R10).
interface Helper {
  name: string;
  purpose: string; // why the vault made it, e.g. "cf.dns.list: read DNS" (R10)
  until: string; // the expiry the vault asked for
  id?: string; // set once Cloudflare answered
}

type Evidence = { minted: { id: string; deleted: boolean }[]; error?: string; audit: ReadResult["audit"] };

const hex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const isoSeconds = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

export class VaultLogic {
  private store: VaultStore;
  private fetch: Fetch;
  private now: () => number;
  private pin: PasskeyPin | undefined;
  // `pin`: Ben's passkey as pinned in passkey.ts; tests pass their own.
  constructor(store: VaultStore, fetchFn: Fetch, now: () => number = Date.now, pin: PasskeyPin | undefined = PASSKEY_PIN) {
    this.store = store;
    this.fetch = fetchFn;
    this.now = now;
    this.pin = pin;
  }

  private async master(): Promise<Master | undefined> {
    const m = await this.store.get<Master | null>("master");
    if (!m) return undefined;
    if (!m.by_passkey && (!m.pending || this.now() > m.pending.until)) {
      // A setup nobody confirmed with Face ID in time is erased, one-time key and all (Codex r3 #1).
      await this.store.put("master", null);
      return undefined;
    }
    return m;
  }

  /** Whether a key is locked to Ben's passkey, or waiting for his first tap (ids are not secret). */
  async status(): Promise<{ stored: boolean; pending: boolean; token_id?: string }> {
    const m = await this.master();
    return m ? { stored: !!m.by_passkey, pending: !m.by_passkey, token_id: m.token_id } : { stored: false, pending: false };
  }

  /**
   * One time, on the vault's own page (setup.ts): checks the pasted token with Cloudflare, seals it
   * under a one-time key the vault keeps until Ben's next Face ID tap, and under a new paper
   * recovery key, which it returns once. The token never passes through the front desk.
   */
  async setup(parent: string): Promise<{ token_id: string; recovery_key: string }> {
    if (await this.master()) throw new VaultError("already_stored");
    if (typeof parent !== "string" || !/^[A-Za-z0-9_-]{40,80}$/.test(parent.trim())) throw new VaultError("not_a_token");
    const token = parent.trim();
    const cf = new Cloudflare(token, this.fetch);
    const accounts = await cf.call<{ id: string }[]>("GET", "/accounts");
    if (accounts.length !== 1) throw new VaultError("account_unclear");
    const account_id = accounts[0].id;
    const check = await cf.call<{ id: string; status: string }>("GET", `/accounts/${account_id}/tokens/verify`);
    if (check.status !== "active") throw new VaultError("token_not_active");
    const baseline = (await listTokens(cf, account_id)).map((t) => t.id);
    const recovery = crypto.getRandomValues(new Uint8Array(32));
    const once = crypto.getRandomValues(new Uint8Array(32));
    const master: Master = {
      account_id,
      token_id: check.id,
      pending: { key: b64url(once), box: await seal(once, PENDING_LABEL, token), until: this.now() + PENDING_MS },
      by_recovery: await seal(recovery, RECOVERY_LABEL, token),
      stored_at: this.now(),
      baseline,
    };
    // Re-checked after the awaited calls, so two setups cannot both store.
    if (await this.master()) throw new VaultError("already_stored");
    await this.store.put("master", master);
    return { token_id: check.id, recovery_key: hex(recovery).replace(/(.{4})(?!$)/g, "$1-") };
  }

  // Opens the key with Ben's passkey secret. On the first tap after setup, locks it to that
  // secret instead and forgets the one-time key.
  private async unlock(m: Master, prf: string): Promise<{ token: string; lockedNow: boolean }> {
    const secret = secretBytes(prf);
    if (m.by_passkey) return { token: await open(secret, MASTER_LABEL, m.by_passkey), lockedNow: false };
    const token = await open(fromB64url(m.pending!.key), PENDING_LABEL, m.pending!.box);
    const locked: Master = { ...m, by_passkey: await seal(secret, MASTER_LABEL, token) };
    delete locked.pending;
    // Re-read after the awaited crypto: only the first tap may lock it (Codex r3 #2). Storage
    // calls only from here on, which the Durable Object does not interleave.
    const now = await this.store.get<Master | null>("master");
    if (!now?.pending || now.pending.key !== m.pending!.key) throw new VaultError("already_locked");
    await this.store.put("master", locked);
    return { token, lockedNow: true };
  }

  /**
   * Runs one job from the fixed list with the master key opened by Ben's passkey secret -- only when the
   * caller hands over Ben's passkey answer for this exact grant, and only once per grant (card bb86abf0;
   * rules in approval.ts). `rest` catches an old-shape call (job, params, prf): refused as wrong_shape.
   */
  async run(req: unknown, ...rest: unknown[]): Promise<ReadResult | HeadcountSetupResult | GhBaselineResult | CfAcceptResult> {
    const signed = await checkSigned(req, rest.length, this.pin);
    // After the crypto: one storage-only step, with the clock read again (approval.ts admit).
    await admit(this.store, signed.grant.id, signed.grant.expires_at, this.now());
    return this.runJob(signed.grant.job, signed.grant.params, signed.prf);
  }

  private async runJob(job: string, params: Record<string, string>, prf: string): Promise<ReadResult | HeadcountSetupResult | GhBaselineResult | CfAcceptResult> {
    const read = (READ_JOBS as readonly string[]).includes(job);
    if (!read && job !== "cf.token.headcount.setup" && job !== "gh.app.baseline" && job !== "cf.token.accept") throw new VaultError("job_not_offered");
    if (job === "cf.token.headcount.setup") return this.runHeadcountSetup(prf);
    if (job === "cf.token.accept") return this.acceptKeys(prf, params?.ids ?? "", params?.scopes ?? "");
    if (job === "gh.app.baseline") return this.ghBaseline(prf, params?.snapshot ?? "", params?.base ?? "");
    // Checked here too, not only at the front desk: the vault is the last word on what it does.
    if (job === "cf.audit.read") {
      if (!auditWindow(params?.since, params?.until, this.now())) throw new VaultError("bad_params");
    } else if (!STUDIO_ZONES.includes(params?.zone ?? "")) throw new VaultError("zone_not_offered");
    const m = await this.master();
    if (!m) throw new VaultError("no_master_key");
    const { token, lockedNow } = await this.unlock(m, prf);
    const master = new Cloudflare(token, this.fetch);
    const facts = { token_id: m.token_id, locked_to_passkey_now: lockedNow };
    m.issued = await this.sweepIssued(master, m);
    const leftover = await this.sweepHelpers(master, m);
    return { ...(await this.read(master, m, job, params)), master: facts, leftover };
  }

  // Job cf.token.headcount.setup: opens the master with Ben's tap and makes the headcount key.
  private async runHeadcountSetup(prf: string): Promise<HeadcountSetupResult> {
    const m = await this.master();
    if (!m) throw new VaultError("no_master_key");
    const { token, lockedNow } = await this.unlock(m, prf);
    const master = new Cloudflare(token, this.fetch);
    m.issued = await this.sweepIssued(master, m);
    const leftover = await this.sweepHelpers(master, m);
    return { ...(await this.setupHeadcount(master, m)), master: { token_id: m.token_id, locked_to_passkey_now: lockedNow }, leftover };
  }

  // Makes the headcount key: account-wide "API Tokens Read", no expiry, no address pin (the nightly
  // run leaves from Cloudflare's network, whose address varies). Before keeping it, the vault needs
  // it to list keys and to be refused a mint; otherwise it is deleted and the old one kept.
  private async setupHeadcount(master: Cloudflare, m: Master): Promise<Omit<HeadcountSetupResult, "master">> {
    const account = m.account_id;
    const r: Omit<HeadcountSetupResult, "master"> = { ok: false, key_id: null, lists: false, mint_refused: false, replaced: [] };
    let value: string | undefined;
    let groupId = "";
    try {
      const groups = await master.call<{ id: string; name: string; scopes: string[] }[]>("GET", `/accounts/${account}/tokens/permission_groups`);
      const read = groups.filter((g) => TOKENS_READ.test(g.name) && g.scopes.includes("com.cloudflare.api.account"));
      if (read.length !== 1) throw new VaultError("permission_group_unclear: API Tokens Read");
      groupId = read[0].id;
      const made = await master.call<{ id: string; value: string }>("POST", `/accounts/${account}/tokens`, {
        name: `front-desk headcount ${isoSeconds(this.now())}`,
        policies: [{ effect: "allow", resources: { [`com.cloudflare.api.account.${account}`]: "*" }, permission_groups: [{ id: read[0].id }] }],
      });
      r.key_id = made.id;
      value = made.value;
      const cf = new Cloudflare(made.value, this.fetch);
      r.lists = (await listTokens(cf, account)).some((t) => t.id === made.id);
      try {
        // A complete, valid request (the same narrow policy, 5 minutes), so only a lack of
        // permission can refuse it -- not a malformed body (Codex C5c-2 r1 #1).
        const leaked = await cf.call<{ id: string }>("POST", `/accounts/${account}/tokens`, {
          name: "front-desk headcount must-fail",
          policies: [{ effect: "allow", resources: { [`com.cloudflare.api.account.${account}`]: "*" }, permission_groups: [{ id: read[0].id }] }],
          expires_on: isoSeconds(this.now() + PROBE_TOKEN_MS),
        });
        r.mint_error = "headcount key could mint";
        await master.call("DELETE", `/accounts/${account}/tokens/${leaked.id}`).catch((e: Error) => note(r, `leaked key delete failed: ${e.message}`));
      } catch (e) {
        // Only Cloudflare's permission refusal counts; an outage proves nothing about the key.
        r.mint_error = (e as Error).message.slice(0, 120);
        r.mint_refused = /^cf_403\b/.test(r.mint_error);
      }
    } catch (e) {
      note(r, (e as Error).message);
    }
    r.ok = !r.error && !!r.key_id && r.lists && r.mint_refused;
    if (!r.ok) {
      if (r.key_id) await master.call("DELETE", `/accounts/${account}/tokens/${r.key_id}`).catch((e: Error) => note(r, `key delete failed: ${e.message}`));
      return r;
    }
    // The new key is stored first, then every older one is deleted. One that will not delete stays
    // on `retired`: the result is not ok, the nightly count names it, and the next setup retries
    // (Codex C5c-2 r1 #2).
    const old = await this.store.get<HeadcountKey | null>("headcount");
    const olds = old ? [old.token_id, ...(old.retired ?? [])] : [];
    await this.store.put<HeadcountKey>("headcount", { token_id: r.key_id!, value: value!, made_at: this.now(), group_id: groupId, retired: olds });
    for (const id of olds) {
      const gone = await master.call("DELETE", `/accounts/${account}/tokens/${id}`).then(
        () => true,
        (e: Error) => /^cf_404/.test(e.message) || (note(r, `old headcount key ${id} delete failed: ${e.message}`), false),
      );
      if (gone) r.replaced.push(id);
    }
    const now = (await this.store.get<HeadcountKey>("headcount"))!;
    await this.store.put<HeadcountKey>("headcount", { ...now, retired: (now.retired ?? []).filter((id) => !r.replaced.includes(id)) });
    r.ok = !r.error;
    return r;
  }

  /**
   * What job cf.token.accept would accept, read at request time with the list-only key (no tap), so
   * Ben's approval screen names every key his tap adds.
   */
  async cfPreview(): Promise<CfPreviewKey[]> {
    const m = await this.master();
    const hc = await this.store.get<HeadcountKey | null>("headcount");
    if (!m || !hc) throw new VaultError("headcount_not_set_up");
    const listed = await listTokens(new Cloudflare(hc.value, this.fetch), m.account_id);
    return this.unexpectedKeys(m, listed, hc.token_id, await this.helpers()).map((k) => {
      const t = listed.find((x) => x.id === k.id)!;
      return { ...k, scope: scopeWords(t) ?? "unreadable", over: overCeiling(t, m.account_id) };
    });
  }

  // Keys in the account the vault does not expect: not in the baseline, not the master or headcount
  // key, not handed out. The nightly count and job cf.token.accept use this same rule.
  // The vault's own short keys are never "unexpected": the nightly count lists them as cleanup instead,
  // so cf.token.accept can never adopt one (R10). A key from outside that borrows the helper name is
  // still reported every night, as cleanup, and the vault never deletes a name it did not record.
  private unexpectedKeys(m: Master, listed: Listed[], hcId: string, helpers: Helper[]): { id: string; name: string }[] {
    const known = new Set([...m.baseline, m.token_id, hcId, ...(m.issued ?? []).map((k) => k.id), ...(m.exceptions ?? []).map((k) => k.id)]);
    return listed.filter((t) => !known.has(t.id) && !isHelper(t, helpers)).map((t) => ({ id: t.id, name: String(t.name ?? "").slice(0, 60) }));
  }

  /**
   * Job cf.token.accept, at Ben's tap: keeps exactly the keys his screen listed as standing exceptions.
   * Each must still be in the account, still unexpected, still exactly the scope his screen showed, and
   * within the ceiling (read-only, this account, nothing that touches keys); otherwise nothing is added.
   * Keys the vault issued are already expected, so only keys it did not make ever reach here.
   */
  private async acceptKeys(prf: string, approved: string, approvedScopes: string): Promise<CfAcceptResult> {
    const ids = approved.split(",");
    const scopes = approvedScopes.split("\n");
    if (!ids.length || ids.some((id) => !/^[0-9a-f]{32}$/.test(id)) || scopes.length !== ids.length || scopes.some((x) => !x)) throw new VaultError("bad_params");
    const m = await this.master();
    if (!m) throw new VaultError("no_master_key");
    const { token, lockedNow } = await this.unlock(m, prf);
    const r: CfAcceptResult = { ok: false, accepted: [], master: { token_id: m.token_id, locked_to_passkey_now: lockedNow } };
    try {
      r.leftover = await this.sweepHelpers(new Cloudflare(token, this.fetch), m);
      const hcIds = await this.headcountId();
      const helpers = await this.helpers();
      const listed = await listTokens(new Cloudflare(token, this.fetch), m.account_id);
      if (listed.some((t) => ids.includes(t.id) && isHelper(t, helpers)) || helpers.some((h) => h.id && ids.includes(h.id))) {
        throw new VaultError("helper_key_not_acceptable: nothing accepted");
      }
      const unexpected = this.unexpectedKeys(m, listed, hcIds[0] ?? "", helpers).map((k) => k.id);
      if (ids.some((id) => !unexpected.includes(id))) throw new VaultError("keys_changed_since_request: nothing accepted, ask again");
      const keys = ids.map((id) => listed.find((t) => t.id === id)!);
      keys.forEach((t, i) => {
        const over = overCeiling(t, m.account_id);
        if (over) throw new VaultError(`over_ceiling: ${t.id}: ${over}: nothing accepted`);
        if (scopeWords(t) !== scopes[i]) throw new VaultError(`scope_changed_since_request: ${t.id}: nothing accepted, ask again`);
      });
      // Re-read after the awaited calls: unlock may have just locked the master to the passkey.
      const now = (await this.master())!;
      const at = this.now();
      const added = keys.map((t, i) => ({ id: t.id, name: String(t.name ?? "").slice(0, 60), scope: scopes[i], at }));
      await this.store.put<Master>("master", { ...now, exceptions: [...(now.exceptions ?? []), ...added] });
      r.accepted = ids;
      r.ok = true;
    } catch (e) {
      note(r, (e as Error).message);
    }
    return r;
  }

  // The headcount key is known to every job's audit, so making it does not stop later jobs.
  private async headcountId(): Promise<string[]> {
    const hc = await this.store.get<HeadcountKey | null>("headcount");
    return hc ? [hc.token_id] : [];
  }

  /**
   * The nightly count (no Ben tap): lists every key with the headcount key and compares with what
   * the vault expects -- the setup baseline, the master, the headcount key itself, and keys handed
   * out and not yet deleted (Cloudflare keeps expired keys listed). Reads only; changes nothing.
   */
  async headcount(): Promise<Headcount> {
    const r: Headcount = { ok: false, tokens: -1, unexpected: [], stretched: [], missing: [], cleanup: [], github: await this.ghHeadcount() };
    try {
      const m = await this.master();
      if (!m?.by_passkey) throw new VaultError("no_master_key");
      const hc = await this.store.get<HeadcountKey | null>("headcount");
      if (!hc) throw new VaultError("headcount_not_set_up");
      const listed = await listTokens(new Cloudflare(hc.value, this.fetch), m.account_id);
      r.tokens = listed.length;
      const issued = new Map((m.issued ?? []).map((k) => [k.id, k.expires_on]));
      const helpers = await this.helpers();
      r.unexpected = this.unexpectedKeys(m, listed, hc.token_id, helpers);
      r.cleanup = listed
        .filter((t) => isHelper(t, helpers))
        .map((t) => ({
          id: t.id, expires_on: t.expires_on ?? "never", expired: !!t.expires_on && Date.parse(t.expires_on) <= this.now(),
          recorded: helpers.some((h) => h.id === t.id || (!h.id && h.name === t.name)),
        }));
      r.stretched = listed
        .filter((t) => issued.has(t.id) && (!t.expires_on || Date.parse(t.expires_on) > Date.parse(issued.get(t.id)!)))
        .map((t) => ({ id: t.id, expires_on: t.expires_on ?? "never" }));
      r.missing = [m.token_id, hc.token_id].filter((id) => !listed.some((t) => t.id === id));
      r.widened = widened(m, listed, hc);
      r.ok = r.unexpected.length === 0 && r.stretched.length === 0 && r.missing.length === 0 && r.cleanup.length === 0 && r.widened.length === 0 && r.github.ok;
    } catch (e) {
      note(r, (e as Error).message);
    }
    return r;
  }

  // ---- GitHub (card C6a-1). Setup runs on the vault's own page (ghsetup.ts); the rest at Ben's tap or nightly. ----

  /** Which Apps exist, are installed, and whether the main key is locked to Ben's passkey (for the setup page). */
  async ghStatus(): Promise<{ headcount: { created: boolean; installed: boolean }; main: { created: boolean; installed: boolean; locked: boolean } }> {
    const hc = await this.store.get<GhHeadcountApp | null>("gh.app.headcount");
    const main = await this.ghMain();
    return {
      headcount: { created: !!hc, installed: !!hc?.installation },
      main: { created: !!main, installed: !!main?.installation, locked: !!main?.by_passkey },
    };
  }

  // The main App, or nothing if its one-time hold lapsed before Ben's tap (then erased, as for the master).
  private async ghMain(): Promise<GhMainApp | undefined> {
    const m = await this.store.get<GhMainApp | null>("gh.app.main");
    if (!m) return undefined;
    if (!m.by_passkey && (!m.pending || this.now() > m.pending.until)) {
      await this.store.put("gh.app.main", null);
      return undefined;
    }
    return m;
  }

  /** Starts making one App: a one-hour `state` the redirect must bring back. Refused once that App exists. */
  async ghStart(kind: AppKind): Promise<string> {
    if ((await this.ghStatus())[kind].created) throw new VaultError("app_exists");
    const state = b64url(crypto.getRandomValues(new Uint8Array(24)));
    await this.store.put(`gh.state.${kind}`, { state, until: this.now() + GH_STATE_MS });
    return state;
  }

  /**
   * GitHub's redirect after Ben tapped Create: the vault trades the code for the App and its key at once,
   * so the key goes GitHub -> vault and nowhere else. Only the `state` this vault issued is accepted.
   */
  async ghCreated(kind: AppKind, code: string, state: string): Promise<{ slug: string }> {
    const issued = await this.store.get<{ state: string; until: number } | null>(`gh.state.${kind}`);
    if (!issued || issued.state !== state || this.now() > issued.until) throw new VaultError("bad_state");
    await this.store.put(`gh.state.${kind}`, null);
    if ((await this.ghStatus())[kind].created) throw new VaultError("app_exists");
    const app = await convert(code, this.fetch);
    const key = pkcs8FromPem(app.pem);
    // Refuses a key WebCrypto cannot use, or an App GitHub registered with wider permissions than
    // this kind allows, before anything is stored.
    await checkApp(new GitHub(await appJwt(app.id, key, this.now()), this.fetch), kind);
    if (kind === "headcount") {
      await this.store.put<GhHeadcountApp>("gh.app.headcount", { id: app.id, slug: app.slug, key });
    } else {
      const once = crypto.getRandomValues(new Uint8Array(32));
      const pending = { key: b64url(once), box: await seal(once, GH_LABEL, key), until: this.now() + GH_PENDING_MS };
      await this.store.put<GhMainApp>("gh.app.main", { id: app.id, slug: app.slug, pending });
    }
    return { slug: app.slug };
  }

  /** GitHub's redirect after Ben tapped Install: checked with the App's own sign-in, never taken on trust. */
  async ghInstalled(kind: AppKind, installationId: string): Promise<void> {
    if (!/^\d{1,12}$/.test(installationId)) throw new VaultError("bad_installation");
    const app = kind === "headcount" ? await this.store.get<GhHeadcountApp | null>("gh.app.headcount") : await this.ghMain();
    if (!app) throw new VaultError("no_app");
    if (app.installation) throw new VaultError("already_installed");
    let key: string;
    if (kind === "headcount") key = (app as GhHeadcountApp).key;
    else {
      const p = (app as GhMainApp).pending;
      if (!p) throw new VaultError("already_locked");
      key = await open(fromB64url(p.key), GH_LABEL, p.box);
    }
    await checkInstallation(new GitHub(await appJwt(app.id, key, this.now()), this.fetch), Number(installationId), kind);
    const now = await this.store.get<GhApp | null>(`gh.app.${kind}`);
    if (!now || now.id !== app.id) throw new VaultError("no_app");
    await this.store.put(`gh.app.${kind}`, { ...now, installation: Number(installationId) });
  }

  // A one-hour read key from the headcount App, used, then revoked (expiry is the backstop). First the
  // watcher checks itself: still read-only, still on all repositories (Codex C6a-1 r1 #1, #3).
  private async ghRead<T>(hc: GhHeadcountApp, use: (gh: GitHub) => Promise<T>): Promise<T> {
    const app = new GitHub(await appJwt(hc.id, hc.key, this.now()), this.fetch);
    await checkApp(app, "headcount");
    await checkInstallation(app, hc.installation!, "headcount");
    const k = await installationKey(app, hc.installation!);
    const gh = new GitHub(k.token, this.fetch);
    try {
      return await use(gh);
    } finally {
      await gh.call("DELETE", "/installation/token").catch(() => undefined);
    }
  }

  /**
   * What job gh.app.baseline would accept, read at request time (no tap; the read-only App only), so
   * Ben's approval screen shows every change and his tap is bound to exactly that state (Codex C6a-1 r1 #4).
   */
  async ghPreview(): Promise<{ changes: string[]; snapshot: string; base: string }> {
    const hc = await this.store.get<GhHeadcountApp | null>("gh.app.headcount");
    if (!hc?.installation) throw new VaultError("github_not_set_up");
    const snap = await this.ghRead(hc, snapshot);
    const old = await this.store.get<GhSnapshot | null>("gh.baseline");
    // `base` names the accepted list the changes were counted from, so an older screen cannot undo a newer approval (Codex C6a-1 r2 #10).
    return { changes: diff(old ?? ({} as GhSnapshot), snap), snapshot: await sha256Hex(canonical(snap)), base: await sha256Hex(canonical(old ?? null)) };
  }

  /**
   * Job gh.app.baseline, at Ben's tap. First time: locks the main App's key to his passkey and forgets
   * the one-time key. Every time: proves the main key works (a one-hour key, revoked at once), proves the
   * headcount App is refused write, and records what can reach the org as the list the nightly count expects.
   */
  private async ghBaseline(prf: string, approved: string, approvedBase: string): Promise<GhBaselineResult> {
    const secret = secretBytes(prf);
    const hc = await this.store.get<GhHeadcountApp | null>("gh.app.headcount");
    const main = await this.ghMain();
    if (!hc?.installation || !main?.installation) throw new VaultError("github_not_set_up");
    const r: GhBaselineResult = {
      ok: false, main: { app_id: main.id, locked_to_passkey_now: false, key_works: false },
      headcount: { app_id: hc.id, write_refused: false }, counts: {}, changes: [],
    };
    let key: string;
    if (main.by_passkey) key = await open(secret, GH_LABEL, main.by_passkey);
    else {
      key = await open(fromB64url(main.pending!.key), GH_LABEL, main.pending!.box);
      const locked: GhMainApp = { ...main, by_passkey: await seal(secret, GH_LABEL, key) };
      delete locked.pending;
      const now = await this.store.get<GhMainApp | null>("gh.app.main");
      if (!now?.pending || now.pending.key !== main.pending!.key) throw new VaultError("already_locked");
      await this.store.put("gh.app.main", locked);
      r.main.locked_to_passkey_now = true;
    }
    try {
      const app = new GitHub(await appJwt(main.id, key, this.now()), this.fetch);
      const k = await installationKey(app, main.installation, { permissions: { metadata: "read" } });
      await new GitHub(k.token, this.fetch).call("DELETE", "/installation/token");
      r.main.key_works = true;
      const hcApp = new GitHub(await appJwt(hc.id, hc.key, this.now()), this.fetch);
      try {
        const leaked = await installationKey(hcApp, hc.installation, { permissions: { administration: "write" } });
        r.headcount.write_error = "headcount App was given write";
        await new GitHub(leaked.token, this.fetch).call("DELETE", "/installation/token").catch(() => undefined);
      } catch (e) {
        r.headcount.write_error = (e as Error).message.slice(0, 120);
        r.headcount.write_refused = GH_ESCALATION_REFUSAL.test(r.headcount.write_error);
      }
      if (!r.headcount.write_refused) throw new VaultError("headcount App not refused write: list not recorded");
      const snap = await this.ghRead(hc, snapshot);
      const old = await this.store.get<GhSnapshot | null>("gh.baseline");
      r.changes = diff(old ?? ({} as GhSnapshot), snap);
      // Only the state Ben saw on his screen is accepted; anything added since stays an alarm.
      if ((await sha256Hex(canonical(old ?? null))) !== approvedBase) throw new VaultError("baseline_changed_since_request: nothing recorded, ask again");
      if ((await sha256Hex(canonical(snap))) !== approved) throw new VaultError("github_changed_since_request: nothing recorded, ask again");
      r.counts = Object.fromEntries(Object.entries(snap).map(([k, v]) => [k, v.length]));
      await this.store.put("gh.baseline", snap);
      r.ok = true;
    } catch (e) {
      note(r, (e as Error).message);
    }
    return r;
  }

  // The nightly GitHub count: what can reach the org now, against the list Ben accepted. Reads only.
  private async ghHeadcount(): Promise<Headcount["github"]> {
    const r: Headcount["github"] = { ok: false, changes: [] };
    try {
      const base = await this.store.get<GhSnapshot | null>("gh.baseline");
      const hc = await this.store.get<GhHeadcountApp | null>("gh.app.headcount");
      if (!base || !hc?.installation) throw new VaultError("github_not_set_up");
      r.changes = diff(base, await this.ghRead(hc, snapshot));
      r.ok = r.changes.length === 0;
    } catch (e) {
      note(r, (e as Error).message);
    }
    return r;
  }

  // Mints a short key, uses it, and always deletes it (its expiry is the backstop).
  // The intent (unique name, asked expiry) is stored BEFORE the mint and the id right after, and the
  // entry is dropped only once the delete is confirmed, so a lost answer or a failed delete leaves a
  // record the next tap's sweep acts on (card ae6147e4 R10). The secret is never stored or returned.
  private async withKey<T>(master: Cloudflare, account: string, r: Evidence, purpose: string, policy: unknown, use: (cf: Cloudflare) => Promise<T>): Promise<T> {
    const name = `${HELPER_PREFIX}${isoSeconds(this.now())} ${hex(crypto.getRandomValues(new Uint8Array(4)))}`;
    const until = isoSeconds(this.now() + PROBE_TOKEN_MS);
    await this.updateHelpers((list) => [...list, { name, purpose, until }]);
    const minted = await master.call<{ id: string; value: string }>("POST", `/accounts/${account}/tokens`, { name, policies: [policy], expires_on: until });
    await this.updateHelpers((list) => list.map((h) => (h.name === name ? { ...h, id: minted.id } : h)));
    const entry = { id: minted.id, deleted: false };
    r.minted.push(entry);
    try {
      return await use(new Cloudflare(minted.value, this.fetch));
    } finally {
      try {
        await master.call("DELETE", `/accounts/${account}/tokens/${minted.id}`);
        entry.deleted = true;
        await this.updateHelpers((list) => list.filter((h) => h.name !== name));
      } catch (e) {
        note(r, `token delete failed: ${(e as Error).message}`);
      }
    }
  }

  /** The recorded short keys (vault storage `helpers`): intents and ids not yet confirmed deleted. */
  private async helpers(): Promise<Helper[]> {
    return (await this.store.get<Helper[] | null>("helpers")) ?? [];
  }

  // Storage calls only between get and put, which the Durable Object does not interleave (as updateIssued).
  private async updateHelpers(change: (list: Helper[]) => Helper[]): Promise<void> {
    await this.store.put("helpers", change(await this.helpers()));
  }

  // At every approved Cloudflare tap, before its job: deletes each recorded short key still at
  // Cloudflare, found by id, or by its unique name when the mint's answer was lost. An entry is dropped
  // only when the delete is confirmed, or when Cloudflare does not list it (it lists expired keys too,
  // so unlisted means gone or never made -- the latter only once its asked expiry has passed).
  // Returns what is still recorded afterwards (id, or name while the id is unknown), so the tap's result
  // tells Ben about earlier leftovers (Codex 4a-1 r1 #2).
  private async sweepHelpers(master: Cloudflare, m: Master): Promise<string[]> {
    const list = await this.helpers();
    if (!list.length) return [];
    let listed: Listed[];
    try {
      listed = await listTokens(master, m.account_id);
    } catch {
      return list.map((h) => h.id ?? h.name); // unknown: everything stays recorded, the nightly count still shows it
    }
    const done: string[] = [];
    for (const h of list) {
      const found = listed.find((t) => (h.id ? t.id === h.id : t.name === h.name));
      if (!found) {
        if (h.id || Date.parse(h.until) <= this.now()) done.push(h.name);
        continue;
      }
      const gone = await master.call("DELETE", `/accounts/${m.account_id}/tokens/${found.id}`).then(() => true, (e: Error) => /^cf_404/.test(e.message));
      if (gone) done.push(h.name);
    }
    await this.updateHelpers((now) => now.filter((h) => !done.includes(h.name)));
    return list.filter((h) => !done.includes(h.name)).map((h) => h.id ?? h.name);
  }

  // Deletes handed-out keys past their expiry and returns the ones still live. A failed delete
  // keeps the key on the list, so the audit still expects it and the next job tries again.
  private async sweepIssued(master: Cloudflare, m: Master): Promise<{ id: string; expires_on: string }[]> {
    const gone: string[] = [];
    for (const k of m.issued ?? []) {
      if (Date.parse(k.expires_on) > this.now()) continue;
      const deleted = await master.call("DELETE", `/accounts/${m.account_id}/tokens/${k.id}`).then(() => true, (e: Error) => /^cf_404/.test(e.message));
      if (deleted) gone.push(k.id);
    }
    // Removes only what this sweep deleted: a key another job recorded meanwhile is kept (Codex minted r2).
    return this.updateIssued((list) => list.filter((k) => !gone.includes(k.id)));
  }

  // Changes the handed-out list from its CURRENT stored value, with storage calls only (get then
  // put, no await between them on anything else), which the Durable Object does not interleave.
  private async updateIssued(change: (list: { id: string; expires_on: string }[]) => { id: string; expires_on: string }[]) {
    const now = await this.store.get<Master | null>("master");
    if (!now) return [];
    const issued = change(now.issued ?? []);
    await this.store.put("master", { ...now, issued });
    return issued;
  }

  // Looks up a zone's id by name with a read-only key for all zones, deleted straight after.
  private findZone(master: Cloudflare, account: string, r: Evidence, group: (name: string) => { id: string }, zoneName: string): Promise<string> {
    const allZones = { [`com.cloudflare.api.account.${account}`]: { "com.cloudflare.api.account.zone.*": "*" } };
    return this.withKey(master, account, r, `find zone ${zoneName}`, { effect: "allow", resources: allZones, permission_groups: [group("Zone Read")] }, async (cf) => {
      const zones = await cf.call<{ id: string; name: string }[]>("GET", `/zones?name=${encodeURIComponent(zoneName)}`);
      if (zones.length !== 1 || zones[0].name !== zoneName) throw new VaultError("zone_not_found");
      return zones[0].id;
    });
  }

  // The read jobs (card ae6147e4 4a-1). Each reads with a short key whose policy is fixed here per job,
  // on the one zone (or the account, for its change log), made and deleted inside Ben's tap (R9). The
  // agent gets only the answer, never a key.
  private async read(master: Cloudflare, m: Master, job: string, params: Record<string, string>): Promise<Omit<ReadResult, "master">> {
    const account = m.account_id;
    const r: Omit<ReadResult, "master"> = { ok: false, job, minted: [], audit: { tokens: -1, minted_still_listed: [], new_since_setup: [] } };
    try {
      if (job === "cf.audit.read") {
        const group = await accountGroup(master, account, ACCOUNT_SETTINGS_READ, "Account Settings Read");
        const policy = { effect: "allow", resources: { [`com.cloudflare.api.account.${account}`]: "*" }, permission_groups: [group] };
        Object.assign(r, await this.withKey(master, account, r, "cf.audit.read: read change log", policy, readWith(job, account, "", params)));
      } else {
        const group = await zoneGroups(master, account);
        const zoneId = await this.findZone(master, account, r, group, params.zone);
        const oneZone = { [`com.cloudflare.api.account.zone.${zoneId}`]: "*" };
        const [purpose, perm] = job === "cf.zone.read" ? ["cf.zone.read: read zone", "Zone Read"] : ["cf.dns.list: read DNS", "DNS Read"];
        Object.assign(r, await this.withKey(master, account, r, purpose, { effect: "allow", resources: oneZone, permission_groups: [group(perm)] }, readWith(job, account, zoneId, params)));
      }
    } catch (e) {
      note(r, (e as Error).message);
    }
    await audit(master, m, r, [], await this.headcountId());
    r.ok = !r.error && !r.audit.error && r.data !== undefined && r.minted.length > 0 && r.minted.every((t) => t.deleted) && r.audit.minted_still_listed.length === 0;
    if (!r.ok) delete r.data; // an answer is handed on only when the whole job checked out
    return r;
  }
}

/** One read job's call and shaping, given a key that may read it: used by Ben's tap jobs (a short helper key)
 * and by runs (the run's key, on the run's frozen account and zone -- runs.ts). Returns only the answer. */
export function readWith(job: string, account: string, zoneId: string, params: Record<string, string>): (cf: Cloudflare) => Promise<{ data: unknown; truncated?: boolean }> {
  return async (cf) => {
    const r: { data?: unknown; truncated?: boolean } = {};
    if (job === "cf.audit.read") {
      const q = `since=${encodeURIComponent(params.since)}&before=${encodeURIComponent(params.until)}`;
      const rows = await pages<AuditRow>(cf, `/accounts/${account}/audit_logs?${q}`, AUDIT_MAX);
      r.truncated = rows.length > AUDIT_MAX;
      r.data = fit(r, rows.slice(0, AUDIT_MAX).map((x) => ({
        when: x.when, action: x.action?.type, result: x.action?.result, actor: x.actor?.email ?? x.actor?.type, ip: x.actor?.ip,
        resource: [x.resource?.type, x.resource?.id].filter(Boolean).join(" "),
      })));
    } else if (job === "cf.zone.read") {
      const z = await cf.call<ZoneRow>("GET", `/zones/${zoneId}`);
      r.data = { id: z.id, name: z.name, status: z.status, paused: z.paused, type: z.type, plan: z.plan?.name, name_servers: z.name_servers };
    } else if (job === "cf.dns.list") {
      const rows = await pages<DnsRow>(cf, `/zones/${zoneId}/dns_records?`, DNS_MAX);
      r.truncated = rows.length > DNS_MAX;
      r.data = fit(r, rows.slice(0, DNS_MAX).map((x) => ({ id: x.id, type: x.type, name: x.name, content: x.content, proxied: x.proxied, ttl: x.ttl })));
    } else throw new VaultError("job_not_offered");
    return r as { data: unknown; truncated?: boolean };
  };
}

// Drops whole rows from the end until the JSON fits RESULT_MAX_BYTES; says so with `truncated`.
function fit<T>(r: { truncated?: boolean }, rows: T[]): T[] {
  const size = (x: unknown) => new TextEncoder().encode(JSON.stringify(x)).length;
  let n = rows.length;
  while (n > 0 && size(rows.slice(0, n)) > RESULT_MAX_BYTES) n = Math.floor(n * 0.9);
  if (n < rows.length) r.truncated = true;
  return rows.slice(0, n);
}

type ZoneRow = { id: string; name: string; status?: string; paused?: boolean; type?: string; plan?: { name?: string }; name_servers?: string[] };
type DnsRow = { id: string; type: string; name: string; content: string; proxied?: boolean; ttl?: number };
type AuditRow = { when?: string; action?: { type?: string; result?: boolean }; actor?: { email?: string; type?: string; ip?: string }; resource?: { type?: string; id?: string } };

// Pages of 100 until a short page, stopping one row past `max` so the caller can say the list was cut.
async function pages<T>(cf: Cloudflare, path: string, max: number): Promise<T[]> {
  const all: T[] = [];
  const sep = path.endsWith("?") ? "" : "&";
  for (let page = 1; all.length <= max; page++) {
    const batch = await cf.call<T[]>("GET", `${path}${sep}per_page=100&page=${page}`);
    all.push(...batch);
    if (batch.length < 100) break;
  }
  return all;
}

/** cf.audit.read's window: two whole-second UTC times, since before until, at most 7 days apart, not in the future. */
export function auditWindow(since: unknown, until: unknown, now: number): boolean {
  const iso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
  if (typeof since !== "string" || typeof until !== "string" || !iso.test(since) || !iso.test(until)) return false;
  const [a, b] = [Date.parse(since), Date.parse(until)];
  return Number.isFinite(a) && Number.isFinite(b) && a < b && b - a <= AUDIT_MAX_DAYS * 86_400_000 && b <= now + 5 * 60_000;
}

const isHelper = (t: { id: string; name?: string }, helpers: Helper[]) =>
  String(t.name ?? "").startsWith(HELPER_PREFIX) || helpers.some((h) => h.id === t.id);

// The account-level group the change-log reader gets (FROM MEMORY: "Account Settings Read"; Cloudflare's
// docs name no narrower account audit-log group -- checked 2026-11-03. The first live cf.audit.read
// records the exact name, and this is narrowed to it). Exactly one match, or the job stops.
export const ACCOUNT_SETTINGS_READ = /^Account Settings Read$/;
/** An account-level permission group by name: exactly one match, or the job stops. */
async function accountGroup(master: Cloudflare, account: string, name: RegExp, label: string): Promise<{ id: string }> {
  const groups = await master.call<{ id: string; name: string; scopes: string[] }[]>("GET", `/accounts/${account}/tokens/permission_groups`);
  const found = groups.filter((g) => name.test(g.name) && g.scopes.includes("com.cloudflare.api.account"));
  if (found.length !== 1) throw new VaultError(`permission_group_unclear: ${label}`);
  return { id: found[0].id };
}

// Zone-level permission groups by name; exactly one match each, or the job stops.
async function zoneGroups(master: Cloudflare, account: string): Promise<(name: string) => { id: string }> {
  const groups = await master.call<{ id: string; name: string; scopes: string[] }[]>("GET", `/accounts/${account}/tokens/permission_groups`);
  return (name: string) => {
    const found = groups.filter((g) => g.name === name && g.scopes.includes("com.cloudflare.api.account.zone"));
    if (found.length !== 1) throw new VaultError(`permission_group_unclear: ${name}`);
    return { id: found[0].id };
  };
}

// Lists every token in the account and compares with the setup baseline (Ben's QB check).
// `expected` are ids that should be new: the key just handed over, if any. `standing` are other keys
// the vault made on purpose (the headcount key).
async function audit(master: Cloudflare, m: Master, r: Evidence, expected: string[] = [], standing: string[] = []): Promise<void> {
  try {
    const ids = (await listTokens(master, m.account_id)).map((t) => t.id);
    r.audit.tokens = ids.length;
    r.audit.minted_still_listed = r.minted.map((t) => t.id).filter((id) => ids.includes(id));
    const known = [...expected, ...standing, ...(m.issued ?? []).map((k) => k.id), ...(m.exceptions ?? []).map((k) => k.id)];
    r.audit.new_since_setup = ids.filter((id) => !m.baseline.includes(id) && !known.includes(id));
    if (expected.some((id) => !ids.includes(id))) note(r, "minted key not listed");
  } catch (e) {
    r.audit.error = (e as Error).message.slice(0, 120);
  }
}

function note(r: { error?: string }, message: string): void {
  r.error = `${r.error ? `${r.error}; ` : ""}${message.slice(0, 120)}`;
}

// The account-level permission group the headcount key gets (FROM MEMORY: "Account API Tokens Read";
// the first live setup records the exact name, and this is narrowed to it).
// The exact account-level group, as Cloudflare names it (VERIFIED 2026-11-06, API reference "List Token Permission
// Groups", Accepted Permissions: "Account API Tokens Read"; Codex Build R r1 #1). No other name passes.
export const TOKENS_READ = /^Account API Tokens Read$/;

type Policy = { effect?: string; resources?: Record<string, unknown>; permission_groups?: { id?: string; name?: string }[] };
type Listed = { id: string; name?: string; expires_on?: string; not_before?: string; condition?: unknown; policies?: Policy[] };

export interface CfPreviewKey {
  id: string;
  name: string;
  scope: string; // scopeWords(), or "unreadable"
  over: string | null; // why it is over the ceiling, or null
}

// Sorted keys at every level, so one scope always reads the same.
function stable(v: unknown): string {
  if (!v || typeof v !== "object") return JSON.stringify(v);
  return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${stable((v as Record<string, unknown>)[k])}`).join(",")}}`;
}

/**
 * A key's real scope as Cloudflare lists it, in one fixed form: each policy's effect, its groups by name AND id
 * (names are cosmetic and repeat across levels; Codex Build R r1b #1), its resources, and the key's own limits
 * (address condition, not-before, expiry; r1b #3), so any change to what the key can do, from where or until when,
 * changes the string. Null when anything cannot be read, including an effect other than allow/deny (r1b #2):
 * unreadable never passes.
 */
export function scopeWords(t: Listed): string | null {
  if (!Array.isArray(t.policies) || !t.policies.length) return null;
  const lines: string[] = [];
  for (const p of t.policies) {
    const groups = p.permission_groups ?? [];
    if (p.effect !== "allow" && p.effect !== "deny") return null;
    if (!groups.length || groups.some((g) => typeof g.name !== "string" || !g.name || typeof g.id !== "string" || !g.id)) return null;
    if (!p.resources || typeof p.resources !== "object") return null;
    lines.push(`${p.effect} ${groups.map((g) => `${g.name} [${g.id}]`).sort().join(" + ")} on ${stable(p.resources)}`);
  }
  const limits = [
    t.condition !== undefined && t.condition !== null ? `condition ${stable(t.condition)}` : "no address limit",
    t.not_before ? `not before ${t.not_before}` : "",
    `expires ${t.expires_on || "never"}`,
  ].filter(Boolean);
  return [...lines.sort(), ...limits].join("; ");
}

/**
 * The ceiling for a key Ben keeps that the front desk did not make (cutover outcome 2, Codex r3 F5):
 * read-only permission groups, on the main account and its zones only, and nothing that touches keys.
 * Returns why a key is over it, or null. A deny only narrows, so it is not checked.
 */
export function overCeiling(t: Listed, account: string): string | null {
  if (scopeWords(t) === null) return "scope_unreadable";
  const zone = (k: string) => k.startsWith("com.cloudflare.api.account.zone.");
  for (const p of t.policies!) {
    if (p.effect === "deny") continue;
    for (const g of p.permission_groups!) {
      if (/token/i.test(g.name!)) return `touches_keys: ${g.name}`;
      if (!/ Read$/.test(g.name!)) return `not_read_only: ${g.name}`;
    }
    for (const [k, v] of Object.entries(p.resources!)) {
      const inAccount = k === `com.cloudflare.api.account.${account}` &&
        (v === "*" || (!!v && typeof v === "object" && Object.entries(v).every(([z, s]) => zone(z) && s === "*")));
      if (!(zone(k) && v === "*") && !inAccount) return `outside_account: ${k.slice(0, 60)}`;
    }
  }
  return null;
}

// The nightly check on scopes: each kept exception must still read exactly as Ben approved it and stay
// under the ceiling; the headcount key must still hold only the one list-keys group on this account.
function widened(m: Master, listed: Listed[], hcKey: HeadcountKey): { id: string; why: string }[] {
  const out: { id: string; why: string }[] = [];
  for (const e of m.exceptions ?? []) {
    const t = listed.find((x) => x.id === e.id);
    if (!t) continue; // deleted: nothing left to watch
    if (scopeWords(t) !== e.scope) out.push({ id: e.id, why: "scope_changed_since_approved" });
    else {
      const over = overCeiling(t, m.account_id);
      if (over) out.push({ id: e.id, why: over });
    }
  }
  const hc = listed.find((x) => x.id === hcKey.token_id);
  if (hc && !hcKey.group_id) out.push({ id: hcKey.token_id, why: "headcount_key_needs_setup" });
  else if (hc && !listOnly(hc, m.account_id, hcKey.group_id!)) out.push({ id: hcKey.token_id, why: "headcount_key_not_list_only" });
  return out;
}

// The headcount key as it was made: readable, one allow policy, one group -- the exact id recorded at setup and
// named TOKENS_READ -- the whole account and nothing else. Any other shape, or one that cannot be read, fails.
function listOnly(t: Listed, account: string, groupId: string): boolean {
  if (scopeWords(t) === null || t.policies!.length !== 1) return false;
  const [p] = t.policies!;
  return p.effect === "allow" && p.permission_groups!.length === 1 && p.permission_groups![0].id === groupId && TOKENS_READ.test(p.permission_groups![0].name!) &&
    stable(p.resources) === stable({ [`com.cloudflare.api.account.${account}`]: "*" });
}

// Every token in the account, all pages.
async function listTokens(cf: Cloudflare, account: string): Promise<Listed[]> {
  const all: Listed[] = [];
  for (let page = 1; page <= 20; page++) {
    const batch = await cf.call<Listed[]>("GET", `/accounts/${account}/tokens?per_page=50&page=${page}`);
    all.push(...batch);
    if (batch.length < 50) return all;
  }
  throw new VaultError("too_many_tokens");
}
