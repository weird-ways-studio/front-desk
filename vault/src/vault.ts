// The vault's rules: it holds the master key (a Cloudflare token that can make other
// tokens) only in sealed form, opens it only with the secret Ben's passkey releases at
// his tap, uses it for one job from a fixed list, and never returns it.
// Design: studio-os docs/specifications/face-id-access/C4-SPIKE.md sections 3.4-3.7.

import { Cloudflare, type Fetch } from "./cloudflare.ts";
import { STUDIO_ZONES } from "./zones.ts";
import { GitHub, appJwt, canonical, checkApp, checkInstallation, convert, diff, installationKey, pkcs8FromPem, sha256Hex, snapshot, type AppKind, type GhSnapshot } from "./github.ts";
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
  // Token ids in the account at setup: the audit's baseline (ids are not secrets).
  baseline: string[];
  // Keys handed to the agent and not yet deleted. Cloudflare keeps expired keys listed, so the
  // vault deletes these once expired, at its next job, and the audit expects them (Codex minted r1 #6).
  issued?: { id: string; expires_on: string }[];
}

// The nightly headcount's own key: it can list the account's keys and nothing else. Minted once by
// the Ben-approved job cf.token.headcount.setup, then kept in vault storage UNSEALED, because the
// nightly run has no Ben tap to open anything with (C5c-2 3baea7cc; C5c-1 retro learning 4).
// A standing credential by Ben's choice on that job's screen; it holds no power to mint or change.
interface HeadcountKey {
  token_id: string;
  value: string;
  made_at: number;
  // Old headcount keys a replacement could not delete. Not expected by the count, so they alarm
  // nightly until the next setup deletes them.
  retired?: string[];
}

export interface HeadcountSetupResult {
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
  // GitHub against the list Ben accepted with job gh.app.baseline: every addition or removal.
  github: { ok: boolean; changes: string[]; error?: string };
  error?: string;
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
  async run(job: string, params: Record<string, string>, prf: string): Promise<ProbeResult | MintResult | HeadcountSetupResult | GhBaselineResult> {
    if (job !== "cf.dns.txt.probe" && job !== "cf.token.zone.read" && job !== "cf.token.headcount.setup" && job !== "gh.app.baseline") throw new VaultError("job_not_offered");
    if (job === "cf.token.headcount.setup") return this.runHeadcountSetup(prf);
    if (job === "gh.app.baseline") return this.ghBaseline(prf, params?.snapshot ?? "", params?.base ?? "");
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

  // Job cf.token.headcount.setup: opens the master with Ben's tap and makes the headcount key.
  private async runHeadcountSetup(prf: string): Promise<HeadcountSetupResult> {
    const m = await this.master();
    if (!m) throw new VaultError("no_master_key");
    const { token, lockedNow } = await this.unlock(m, prf);
    const master = new Cloudflare(token, this.fetch);
    m.issued = await this.sweepIssued(master, m);
    return { ...(await this.setupHeadcount(master, m)), master: { token_id: m.token_id, locked_to_passkey_now: lockedNow } };
  }

  // Makes the headcount key: account-wide "API Tokens Read", no expiry, no address pin (the nightly
  // run leaves from Cloudflare's network, whose address varies). Before keeping it, the vault needs
  // it to list keys and to be refused a mint; otherwise it is deleted and the old one kept.
  private async setupHeadcount(master: Cloudflare, m: Master): Promise<Omit<HeadcountSetupResult, "master">> {
    const account = m.account_id;
    const r: Omit<HeadcountSetupResult, "master"> = { ok: false, key_id: null, lists: false, mint_refused: false, replaced: [] };
    let value: string | undefined;
    try {
      const groups = await master.call<{ id: string; name: string; scopes: string[] }[]>("GET", `/accounts/${account}/tokens/permission_groups`);
      const read = groups.filter((g) => TOKENS_READ.test(g.name) && g.scopes.includes("com.cloudflare.api.account"));
      if (read.length !== 1) throw new VaultError("permission_group_unclear: API Tokens Read");
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
    await this.store.put<HeadcountKey>("headcount", { token_id: r.key_id!, value: value!, made_at: this.now(), retired: olds });
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
    const r: Headcount = { ok: false, tokens: -1, unexpected: [], stretched: [], missing: [], github: await this.ghHeadcount() };
    try {
      const m = await this.master();
      if (!m?.by_passkey) throw new VaultError("no_master_key");
      const hc = await this.store.get<HeadcountKey | null>("headcount");
      if (!hc) throw new VaultError("headcount_not_set_up");
      const listed = await listTokens(new Cloudflare(hc.value, this.fetch), m.account_id);
      r.tokens = listed.length;
      const issued = new Map((m.issued ?? []).map((k) => [k.id, k.expires_on]));
      const known = new Set([...m.baseline, m.token_id, hc.token_id, ...issued.keys()]);
      r.unexpected = listed.filter((t) => !known.has(t.id)).map((t) => ({ id: t.id, name: String(t.name ?? "").slice(0, 60) }));
      r.stretched = listed
        .filter((t) => issued.has(t.id) && (!t.expires_on || Date.parse(t.expires_on) > Date.parse(issued.get(t.id)!)))
        .map((t) => ({ id: t.id, expires_on: t.expires_on ?? "never" }));
      r.missing = [m.token_id, hc.token_id].filter((id) => !listed.some((t) => t.id === id));
      r.ok = r.unexpected.length === 0 && r.stretched.length === 0 && r.missing.length === 0 && r.github.ok;
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
    await audit(master, m, r, [], await this.headcountId());
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
    await audit(master, m, r, r.key ? [r.key.id] : [], await this.headcountId());
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
// `expected` are ids that should be new: the key just handed over, if any. `standing` are other keys
// the vault made on purpose (the headcount key).
async function audit(master: Cloudflare, m: Master, r: Evidence, expected: string[] = [], standing: string[] = []): Promise<void> {
  try {
    const ids = (await listTokens(master, m.account_id)).map((t) => t.id);
    r.audit.tokens = ids.length;
    r.audit.minted_still_listed = r.minted.map((t) => t.id).filter((id) => ids.includes(id));
    const known = [...expected, ...standing, ...(m.issued ?? []).map((k) => k.id)];
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
export const TOKENS_READ = /^(Account )?API Tokens Read$/;

type Listed = { id: string; name?: string; expires_on?: string };

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
