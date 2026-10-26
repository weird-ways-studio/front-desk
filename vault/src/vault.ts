// The vault's rules: it holds the master key (a Cloudflare token that can make other
// tokens) only in sealed form, opens it only with the secret Ben's passkey releases at
// his tap, uses it for one job from a fixed list, and never returns it.
// Design: studio-os docs/specifications/face-id-access/C4-SPIKE.md sections 3.4-3.7.

import { Cloudflare, type Fetch } from "./cloudflare.ts";
import { STUDIO_ZONES } from "./zones.ts";
import { MASTER_LABEL, RECOVERY_LABEL, VaultError, open, seal, secretBytes, type Sealed } from "./seal.ts";

export const PROBE_TOKEN_MS = 5 * 60_000;
export const PROBE_RECORD = "_front-desk-probe";

export interface VaultStore {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
}

interface Master {
  account_id: string;
  token_id: string;
  by_passkey: Sealed;
  by_recovery: Sealed;
  stored_at: number;
  // Token ids in the account at setup: the audit's baseline (ids are not secrets).
  baseline: string[];
}

export interface ProbeResult {
  ok: boolean; // true only when every step below checked out
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

  /** Whether a master key is stored, and which provider token it is (not secret). */
  async status(): Promise<{ stored: boolean; token_id?: string }> {
    const m = await this.store.get<Master>("master");
    return m ? { stored: true, token_id: m.token_id } : { stored: false };
  }

  /**
   * One time only: checks the pasted token with Cloudflare, seals it under the passkey's
   * secret and under a new random recovery key, and returns the recovery key once (for paper).
   */
  async setup(prf: string, parent: string): Promise<{ token_id: string; recovery_key: string }> {
    if (await this.store.get<Master>("master")) throw new VaultError("already_stored");
    const secret = secretBytes(prf);
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
    const master: Master = {
      account_id,
      token_id: check.id,
      by_passkey: await seal(secret, MASTER_LABEL, token),
      by_recovery: await seal(recovery, RECOVERY_LABEL, token),
      stored_at: this.now(),
      baseline,
    };
    // Re-checked after the awaited calls, so two setups cannot both store.
    if (await this.store.get<Master>("master")) throw new VaultError("already_stored");
    await this.store.put("master", master);
    return { token_id: check.id, recovery_key: hex(recovery).replace(/(.{4})(?!$)/g, "$1-") };
  }

  /** Runs one job from the fixed list with the master key opened by Ben's passkey secret. */
  async run(job: string, params: Record<string, string>, prf: string): Promise<ProbeResult> {
    if (job !== "cf.dns.txt.probe") throw new VaultError("job_not_offered");
    if (!STUDIO_ZONES.includes(params?.zone ?? "")) throw new VaultError("zone_not_offered");
    const m = await this.store.get<Master>("master");
    if (!m) throw new VaultError("no_master_key");
    const parent = await open(secretBytes(prf), MASTER_LABEL, m.by_passkey);
    return this.probe(new Cloudflare(parent, this.fetch), m, params.zone);
  }

  // Mints a short key, uses it, and always deletes it (its expiry is the backstop).
  private async withKey<T>(master: Cloudflare, account: string, r: ProbeResult, policy: unknown, use: (cf: Cloudflare) => Promise<T>): Promise<T> {
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
  private async probe(master: Cloudflare, m: Master, zoneName: string): Promise<ProbeResult> {
    const account = m.account_id;
    const r: ProbeResult = {
      ok: false, zone: zoneName, record: `${PROBE_RECORD}.${zoneName}`, before: -1, added: false, seen_after_add: false,
      removed: false, after: -1, minted: [], audit: { tokens: -1, minted_still_listed: [], new_since_setup: [] },
    };
    try {
      const groups = await master.call<{ id: string; name: string; scopes: string[] }[]>("GET", `/accounts/${account}/tokens/permission_groups`);
      const group = (name: string) => {
        const found = groups.filter((g) => g.name === name && g.scopes.includes("com.cloudflare.api.account.zone"));
        if (found.length !== 1) throw new VaultError(`permission_group_unclear: ${name}`);
        return { id: found[0].id };
      };
      const allZones = { [`com.cloudflare.api.account.${account}`]: { "com.cloudflare.api.account.zone.*": "*" } };
      const zoneId = await this.withKey(master, account, r, { effect: "allow", resources: allZones, permission_groups: [group("Zone Read")] }, async (cf) => {
        const zones = await cf.call<{ id: string; name: string }[]>("GET", `/zones?name=${encodeURIComponent(zoneName)}`);
        if (zones.length !== 1 || zones[0].name !== zoneName) throw new VaultError("zone_not_found");
        return zones[0].id;
      });
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
    try {
      const ids = (await listTokens(master, account)).map((t) => t.id);
      r.audit.tokens = ids.length;
      r.audit.minted_still_listed = r.minted.map((t) => t.id).filter((id) => ids.includes(id));
      r.audit.new_since_setup = ids.filter((id) => !m.baseline.includes(id));
    } catch (e) {
      r.audit.error = (e as Error).message.slice(0, 120);
    }
    r.ok =
      !r.error && !r.audit.error && r.before === 0 && r.added && r.seen_after_add && r.removed && r.after === 0 &&
      r.minted.length === 2 && r.minted.every((t) => t.deleted) && r.audit.minted_still_listed.length === 0 && r.audit.new_since_setup.length === 0;
    return r;
  }
}

function note(r: ProbeResult, message: string): void {
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
