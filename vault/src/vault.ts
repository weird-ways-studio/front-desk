// The vault's rules: it holds the master key (a Cloudflare token that can make other
// tokens) only in sealed form, opens it only with the secret Ben's passkey releases at
// his tap, uses it for one job from a fixed list, and never returns it.
// Design: studio-os docs/specifications/face-id-access/C4-SPIKE.md sections 3.4-3.7.

import { Cloudflare, type Fetch } from "./cloudflare.ts";
import { STUDIO_ZONES } from "./zones.ts";
import { MASTER_LABEL, RECOVERY_LABEL, VaultError, b64url, fromB64url, open, seal, secretBytes, type Sealed } from "./seal.ts";

export const PROBE_TOKEN_MS = 5 * 60_000;
// A key handed to the agent lasts at most this long (C4 design 3.7: <=15 minutes).
export const MAX_KEY_MINUTES = 15;
// How Cloudflare refuses a key used outside its request_ip condition (FROM MEMORY: HTTP 403,
// "Cannot use the access token from location: <ip>"; the first live run records the exact text and
// code, and this is narrowed to them). Anything else -- another 403, an outage -- fails closed.
export const OFFBOX_REFUSAL = /^cf_403(\[\d+\])?: Cannot use the access token from location\b/;
export const PROBE_RECORD = "_front-desk-probe";
// Setup waits this long for Ben's first Face ID tap to lock the key to his passkey.
export const PENDING_MS = 30 * 60_000;
const PENDING_LABEL = "front-desk pending-key v1";

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
  // Token ids in the account at setup: the audit's baseline (ids are not secrets).
  baseline: string[];
  // Keys handed to the agent and not yet deleted. Cloudflare keeps expired keys listed, so the
  // vault deletes these once expired, at its next job, and the audit expects them (Codex minted r1 #6).
  issued?: { id: string; expires_on: string }[];
}

export interface ProbeResult {
  ok: boolean; // true only when every step below checked out
  master: { token_id: string; locked_to_passkey_now: boolean };
  zone: string;
  record: string;
  before: number;
  added: boolean;
  seen_after_add: boolean;
  removed: boolean;
  after: number;
  minted: { id: string; deleted: boolean }[];
  audit: { tokens: number; minted_still_listed: string[]; new_since_setup: string[]; error?: string };
  error?: string;
}

export interface MintResult {
  ok: boolean; // true only when every check below held; otherwise no key is handed over
  master: { token_id: string; locked_to_passkey_now: boolean };
  zone: string;
  // The key for the agent. `value` is the secret: the front desk passes it on once and never logs it.
  key: { id: string; expires_on: string; ip: string; value?: string } | null;
  // The vault tried the key from Cloudflare's own network (not the pinned address): it must be refused.
  offbox_refused: boolean;
  offbox_error?: string;
  minted: { id: string; deleted: boolean }[]; // short helper keys, all deleted
  audit: { tokens: number; minted_still_listed: string[]; new_since_setup: string[]; error?: string };
  error?: string;
}

type Evidence = { minted: { id: string; deleted: boolean }[]; error?: string; audit: ProbeResult["audit"] };

const hex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const isoSeconds = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

export class VaultLogic {
  private store: VaultStore;
  private fetch: Fetch;
  private now: () => number;
  constructor(store: VaultStore, fetchFn: Fetch, now: () => number = Date.now) {
    this.store = store;
    this.fetch = fetchFn;
    this.now = now;
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

  /** Runs one job from the fixed list with the master key opened by Ben's passkey secret. */
  async run(job: string, params: Record<string, string>, prf: string): Promise<ProbeResult | MintResult> {
    if (job !== "cf.dns.txt.probe" && job !== "cf.token.zone.read") throw new VaultError("job_not_offered");
    if (!STUDIO_ZONES.includes(params?.zone ?? "")) throw new VaultError("zone_not_offered");
    // Checked here too, not only at the front desk: the vault is the last word on what it mints.
    if (job === "cf.token.zone.read" && (!isMinutes(params.minutes) || !isIPv4(params.ip))) throw new VaultError("bad_params");
    const m = await this.master();
    if (!m) throw new VaultError("no_master_key");
    const { token, lockedNow } = await this.unlock(m, prf);
    const master = new Cloudflare(token, this.fetch);
    const facts = { token_id: m.token_id, locked_to_passkey_now: lockedNow };
    m.issued = await this.sweepIssued(master, m);
    if (job === "cf.dns.txt.probe") return { ...(await this.probe(master, m, params.zone)), master: facts };
    return { ...(await this.mintReadKey(master, m, params.zone, Number(params.minutes), params.ip)), master: facts };
  }

  // Mints a short key, uses it, and always deletes it (its expiry is the backstop).
  private async withKey<T>(master: Cloudflare, account: string, r: Evidence, policy: unknown, use: (cf: Cloudflare) => Promise<T>): Promise<T> {
    const minted = await master.call<{ id: string; value: string }>("POST", `/accounts/${account}/tokens`, {
      name: `front-desk probe ${isoSeconds(this.now())}`,
      policies: [policy],
      expires_on: isoSeconds(this.now() + PROBE_TOKEN_MS),
    });
    const entry = { id: minted.id, deleted: false };
    r.minted.push(entry);
    try {
      return await use(new Cloudflare(minted.value, this.fetch));
    } finally {
      try {
        await master.call("DELETE", `/accounts/${account}/tokens/${minted.id}`);
        entry.deleted = true;
      } catch (e) {
        note(r, `token delete failed: ${(e as Error).message}`);
      }
    }
  }

  // Finds the zone with a read-only key, then adds one TXT record with a key for that zone
  // only, checks it, and removes it -- removal is tried even if a check failed. Then lists
  // every token in the account and compares with the setup baseline (Ben's QB check).
  private async probe(master: Cloudflare, m: Master, zoneName: string): Promise<Omit<ProbeResult, "master">> {
    const account = m.account_id;
    const r: Omit<ProbeResult, "master"> = {
      ok: false, zone: zoneName, record: `${PROBE_RECORD}.${zoneName}`, before: -1, added: false, seen_after_add: false,
      removed: false, after: -1, minted: [], audit: { tokens: -1, minted_still_listed: [], new_since_setup: [] },
    };
    try {
      const group = await zoneGroups(master, account);
      const zoneId = await this.findZone(master, account, r, group, zoneName);
      const oneZone = { [`com.cloudflare.api.account.zone.${zoneId}`]: "*" };
      await this.withKey(master, account, r, { effect: "allow", resources: oneZone, permission_groups: [group("DNS Write"), group("Zone Read")] }, async (dns) => {
        const find = () => dns.call<{ id: string }[]>("GET", `/zones/${zoneId}/dns_records?type=TXT&name=${encodeURIComponent(r.record)}`);
        r.before = (await find()).length;
        if (r.before !== 0) throw new VaultError("probe_record_exists");
        const content = `"front desk probe ${hex(crypto.getRandomValues(new Uint8Array(8)))}"`;
        const rec = await dns.call<{ id: string }>("POST", `/zones/${zoneId}/dns_records`, { type: "TXT", name: r.record, content, ttl: 60 });
        r.added = true;
        try {
          r.seen_after_add = (await find()).some((x) => x.id === rec.id);
        } finally {
          await dns.call("DELETE", `/zones/${zoneId}/dns_records/${rec.id}`);
          r.removed = true;
          r.after = (await find()).length;
        }
      });
    } catch (e) {
      note(r, (e as Error).message);
    }
    await audit(master, m, r);
    r.ok =
      !r.error && !r.audit.error && r.before === 0 && r.added && r.seen_after_add && r.removed && r.after === 0 &&
      r.minted.length === 2 && r.minted.every((t) => t.deleted) && r.audit.minted_still_listed.length === 0 && r.audit.new_since_setup.length === 0;
    return r;
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
    return this.withKey(master, account, r, { effect: "allow", resources: allZones, permission_groups: [group("Zone Read")] }, async (cf) => {
      const zones = await cf.call<{ id: string; name: string }[]>("GET", `/zones?name=${encodeURIComponent(zoneName)}`);
      if (zones.length !== 1 || zones[0].name !== zoneName) throw new VaultError("zone_not_found");
      return zones[0].id;
    });
  }

  // Makes the one key the agent gets: read-only on one zone, expiring after `minutes`, usable
  // only from `ip` (the address the agent's request came from). Before handing it over, the vault
  // tries it from Cloudflare's own network and needs that refused, and audits the account. If any
  // check fails, the key is deleted and nothing is handed over.
  private async mintReadKey(master: Cloudflare, m: Master, zoneName: string, minutes: number, ip: string): Promise<Omit<MintResult, "master">> {
    const account = m.account_id;
    const r: Omit<MintResult, "master"> = {
      ok: false, zone: zoneName, key: null, offbox_refused: false, minted: [],
      audit: { tokens: -1, minted_still_listed: [], new_since_setup: [] },
    };
    let value: string | undefined;
    try {
      const group = await zoneGroups(master, account);
      const zoneId = await this.findZone(master, account, r, group, zoneName);
      const expires_on = isoSeconds(this.now() + minutes * 60_000);
      const made = await master.call<{ id: string; value: string }>("POST", `/accounts/${account}/tokens`, {
        name: `front-desk zone-read ${isoSeconds(this.now())}`,
        policies: [{ effect: "allow", resources: { [`com.cloudflare.api.account.zone.${zoneId}`]: "*" }, permission_groups: [group("Zone Read")] }],
        expires_on,
        condition: { request_ip: { in: [`${ip}/32`] } },
      });
      r.key = { id: made.id, expires_on, ip };
      value = made.value;
      try {
        await new Cloudflare(made.value, this.fetch).call("GET", `/zones/${zoneId}`);
        r.offbox_error = "key worked off the pinned address";
      } catch (e) {
        // Only Cloudflare's own address refusal counts. Any other failure (an outage, a key not
        // yet live) proves nothing about the pin, so the key is not handed over.
        r.offbox_error = (e as Error).message.slice(0, 120);
        r.offbox_refused = OFFBOX_REFUSAL.test(r.offbox_error);
      }
    } catch (e) {
      note(r, (e as Error).message);
    }
    await audit(master, m, r, r.key ? [r.key.id] : []);
    r.ok =
      !r.error && !r.audit.error && !!r.key && r.offbox_refused && r.minted.length === 1 && r.minted.every((t) => t.deleted) &&
      r.audit.minted_still_listed.length === 0 && r.audit.new_since_setup.length === 0;
    if (r.ok) {
      const k = { id: r.key!.id, expires_on: r.key!.expires_on };
      await this.updateIssued((list) => [...list, k]);
      return { ...r, key: { ...r.key!, value } };
    }
    if (r.key) {
      // Fail closed: a key that did not pass every check is deleted, never handed over.
      await master.call("DELETE", `/accounts/${account}/tokens/${r.key.id}`).catch((e: Error) => note(r, `key delete failed: ${e.message}`));
    }
    return r;
  }
}

const isMinutes = (v: unknown) => typeof v === "string" && /^([1-9]|1[0-5])$/.test(v) && Number(v) <= MAX_KEY_MINUTES;
export const isIPv4 = (v: unknown) => typeof v === "string" && /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(v);

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
// `expected` are ids that should be new: the key just handed over, if any.
async function audit(master: Cloudflare, m: Master, r: Evidence, expected: string[] = []): Promise<void> {
  try {
    const ids = (await listTokens(master, m.account_id)).map((t) => t.id);
    r.audit.tokens = ids.length;
    r.audit.minted_still_listed = r.minted.map((t) => t.id).filter((id) => ids.includes(id));
    const known = [...expected, ...(m.issued ?? []).map((k) => k.id)];
    r.audit.new_since_setup = ids.filter((id) => !m.baseline.includes(id) && !known.includes(id));
    if (expected.some((id) => !ids.includes(id))) note(r, "minted key not listed");
  } catch (e) {
    r.audit.error = (e as Error).message.slice(0, 120);
  }
}

function note(r: { error?: string }, message: string): void {
  r.error = `${r.error ? `${r.error}; ` : ""}${message.slice(0, 120)}`;
}

// Every token in the account, all pages.
async function listTokens(cf: Cloudflare, account: string): Promise<{ id: string }[]> {
  const all: { id: string }[] = [];
  for (let page = 1; page <= 20; page++) {
    const batch = await cf.call<{ id: string }[]>("GET", `/accounts/${account}/tokens?per_page=50&page=${page}`);
    all.push(...batch);
    if (batch.length < 50) return all;
  }
  throw new VaultError("too_many_tokens");
}
