// The vault's rules: it holds the master key (a Cloudflare token that can make other
// tokens) only in sealed form, opens it only with the secret Ben's passkey releases at
// his tap, uses it for one job from a fixed list, and never returns it.
// Design: studio-os docs/specifications/face-id-access/C4-SPIKE.md sections 3.4-3.7.

import { Cloudflare, type Fetch } from "./cloudflare.ts";
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
}

export interface ProbeResult {
  zone: string;
  record: string;
  before: number;
  seen_after_add: boolean;
  after: number;
  minted_token_id: string;
  minted_token_deleted: boolean;
  minted_token_in_list: boolean;
  tokens_in_account: number;
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
    const recovery = crypto.getRandomValues(new Uint8Array(32));
    const master: Master = {
      account_id,
      token_id: check.id,
      by_passkey: await seal(secret, MASTER_LABEL, token),
      by_recovery: await seal(recovery, RECOVERY_LABEL, token),
      stored_at: this.now(),
    };
    // Re-checked after the awaited calls, so two setups cannot both store.
    if (await this.store.get<Master>("master")) throw new VaultError("already_stored");
    await this.store.put("master", master);
    return { token_id: check.id, recovery_key: hex(recovery).replace(/(.{4})(?!$)/g, "$1-") };
  }

  /** Runs one job from the fixed list with the master key opened by Ben's passkey secret. */
  async run(job: string, params: Record<string, string>, prf: string): Promise<ProbeResult> {
    if (job !== "cf.dns.txt.probe") throw new VaultError("job_not_offered");
    if (!/^[0-9a-f]{32}$/.test(params?.zone_id ?? "")) throw new VaultError("bad_params");
    const m = await this.store.get<Master>("master");
    if (!m) throw new VaultError("no_master_key");
    const parent = await open(secretBytes(prf), MASTER_LABEL, m.by_passkey);
    return this.probe(new Cloudflare(parent, this.fetch), m.account_id, params.zone_id);
  }

  // Makes a 5-minute DNS key for one zone, adds one TXT record, checks it, removes it,
  // deletes the key, then lists the account's tokens to show the key is gone.
  private async probe(master: Cloudflare, account: string, zoneId: string): Promise<ProbeResult> {
    const groups = await master.call<{ id: string; name: string; scopes: string[] }[]>("GET", `/accounts/${account}/tokens/permission_groups`);
    const group = (name: string) => {
      const found = groups.filter((g) => g.name === name && g.scopes.includes("com.cloudflare.api.account.zone"));
      if (found.length !== 1) throw new VaultError(`permission_group_unclear: ${name}`);
      return { id: found[0].id };
    };
    const minted = await master.call<{ id: string; value: string }>("POST", `/accounts/${account}/tokens`, {
      name: `front-desk dns probe ${isoSeconds(this.now())}`,
      policies: [{ effect: "allow", resources: { [`com.cloudflare.api.account.zone.${zoneId}`]: "*" }, permission_groups: [group("DNS Write"), group("Zone Read")] }],
      expires_on: isoSeconds(this.now() + PROBE_TOKEN_MS),
    });
    const r: ProbeResult = {
      zone: "",
      record: "",
      before: -1,
      seen_after_add: false,
      after: -1,
      minted_token_id: minted.id,
      minted_token_deleted: false,
      minted_token_in_list: true,
      tokens_in_account: -1,
    };
    try {
      const dns = new Cloudflare(minted.value, this.fetch);
      const zone = await dns.call<{ name: string }>("GET", `/zones/${zoneId}`);
      r.zone = zone.name;
      r.record = `${PROBE_RECORD}.${zone.name}`;
      const find = () => dns.call<{ id: string; content: string }[]>("GET", `/zones/${zoneId}/dns_records?type=TXT&name=${encodeURIComponent(r.record)}`);
      r.before = (await find()).length;
      if (r.before !== 0) throw new VaultError("probe_record_exists");
      const content = `"front desk probe ${hex(crypto.getRandomValues(new Uint8Array(8)))}"`;
      const rec = await dns.call<{ id: string }>("POST", `/zones/${zoneId}/dns_records`, { type: "TXT", name: r.record, content, ttl: 60 });
      r.seen_after_add = (await find()).some((x) => x.id === rec.id);
      await dns.call("DELETE", `/zones/${zoneId}/dns_records/${rec.id}`);
      r.after = (await find()).length;
    } catch (e) {
      r.error = (e as Error).message.slice(0, 120);
    } finally {
      // The key is deleted whatever happened above; its 5-minute expiry is the backstop.
      try {
        await master.call("DELETE", `/accounts/${account}/tokens/${minted.id}`);
        r.minted_token_deleted = true;
      } catch (e) {
        r.error = `${r.error ? `${r.error}; ` : ""}token delete failed: ${(e as Error).message.slice(0, 80)}`;
      }
    }
    const tokens = await master.call<{ id: string }[]>("GET", `/accounts/${account}/tokens?per_page=100`);
    r.tokens_in_account = tokens.length;
    r.minted_token_in_list = tokens.some((t) => t.id === minted.id);
    return r;
  }
}
