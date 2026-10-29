// The front desk's rules, free of Cloudflare specifics so they run in tests.
// A grant is fixed when the agent asks; Ben's passkey approves that exact grant
// (its hash is inside the challenge); a grant is collected at most once.

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { name, plainChanges } from "./ghplain.ts";
import { JOBS, type Job, type JobName } from "./jobs.ts";
import { currentKey, fingerprint, keyRev, type CboxKey } from "./cboxkey.ts";
import type { Headcount, VaultApi } from "../vault/src/api.ts";

export const APPROVE_WINDOW_MS = 10 * 60_000; // ask -> approve
export const COLLECT_WINDOW_MS = 5 * 60_000; // approve -> collect
export const MAX_PENDING = 3; // grants one requester may have waiting for Ben at once
export const CHALLENGE_TTL_MS = 5 * 60_000;
export const ROUTE_REFUSALS_PER_DAY = 20;
// PRF check only. The master key will use a different label, so a check never reveals key material.
export const PRF_CHECK_LABEL = "front-desk prf-check v1";
// Salt for the secret that unlocks the master key (setup and vault jobs).
export const PRF_MASTER_LABEL = "front-desk master-key v1";

// The subset of Durable Object storage the desk uses; MemoryStore implements it for tests.
export interface Store {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  list<T>(options: { prefix: string }): Promise<Map<string, T>>;
  delete(key: string): Promise<boolean>;
}

export type GrantStatus = "pending" | "approved" | "collected";

// Where an agent request came from: the address Cloudflare saw, and the route's check of the c-box
// signature (cboxkey.ts), run only for jobs that hand out keys.
export interface Source {
  ip?: string;
  checkSignature?: () => Promise<void>;
}

export interface Grant {
  id: string;
  job: JobName;
  params: Record<string, string>;
  reason: string;
  requester: string;
  created_at: number;
  expires_at: number;
  hash: string;
  status: GrantStatus;
  approved_at?: number;
  collected_at?: number;
  // For key jobs: the c-box key generation (cboxkey.ts keyRev) the request was signed under. Approval
  // and collect are refused if Ben has removed or replaced the key since (Codex architecture r2).
  cbox_rev?: number;
  // What a vault job reported when it ran at approval. A minted key's secret (result.key.value)
  // is kept only until the agent collects it, then erased; it is never logged or shown to Ben.
  result?: unknown;
}

export interface Passkey {
  id: string;
  publicKey: number[];
  counter: number;
  enrolled_at: number;
}

interface Challenge {
  purpose: "approve" | "enroll" | "check" | "setup";
  grant_id?: string;
  expires_at: number;
  used: boolean;
}

export interface LogEntry {
  at: number;
  event: string;
  grant_id?: string;
  job?: string;
  reason?: string;
  requester?: string;
  params?: Record<string, string>;
  expires_at?: number;
  detail?: string;
}

export class DeskError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, status: number) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

export interface Site {
  origin: string;
  rpID: string;
}

const enc = new TextEncoder();

export function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(text: string): Uint8Array {
  const s = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Sorted keys so the same grant always hashes the same.
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value as object).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export async function grantHash(g: Pick<Grant, "id" | "job" | "params" | "requester" | "expires_at">): Promise<string> {
  const fixed = { id: g.id, job: g.job, params: g.params, requester: g.requester, expires_at: g.expires_at };
  return hex(await sha256(enc.encode(canonical(fixed))));
}

// Tells the off-box alarm the night's result (headcountAlarm below: healthchecks.io).
// Throws when the alarm did not take it.
/**
 * The nightly count in words, for Ben's phone and the log (instruction.orient-the-person): what to do
 * first, one line per kind of trouble with its own next step, then the changes, cut to fit `max`
 * with a count of what was left out. The vault's exact reasons stay in brackets for the agent.
 */
export function headcountWords(r: Headcount, max = LOG_DETAIL_MAX): string {
  if (r.ok) return `All clear: ${r.tokens} Cloudflare keys, all expected; GitHub matches the list you accepted.`;
  if (r.error) return `The nightly check could not finish, so tonight is unconfirmed. Tell the agent to fix it; there is nothing to accept. [${name(r.error)}]`;
  const cf: string[] = [
    ...r.unexpected.map((k) => `Cloudflare: a key nobody asked you for, named ${name(k.name)} [${name(k.id)}]`),
    ...r.stretched.map((k) => `Cloudflare: a key whose expiry was pushed later, now ${name(k.expires_on)} [${name(k.id)}]`),
    ...r.missing.map((k) => `Cloudflare: one of the front desk's own keys is missing [${name(k)}]`),
  ];
  const gh = plainChanges(r.github.changes).flatMap((g) => g.items.map((i) => `GitHub, ${g.heading.split(":")[0]}: ${i}`));
  const todo = ["Front desk nightly check: needs you."];
  if (cf.length) todo.push(`Cloudflare: ${cf.length} key change${cf.length === 1 ? "" : "s"} you did not approve. If one is not yours, tell the agent now: it may be someone else's access. If you made it, tell the agent so it can check it.`);
  if (gh.length) todo.push(`GitHub: ${gh.length} change${gh.length === 1 ? "" : "s"} since the list you accepted. If you made them, ask the agent to accept them (one Face ID tap). If not, tell the agent now.`);
  if (r.github.error) todo.push(r.github.error === "github_not_set_up" ? "GitHub: not checked, because the GitHub setup is not finished. Tell the agent to finish it; there is nothing to accept." : `GitHub: could not be checked tonight, so it is unconfirmed. Tell the agent to fix it; there is nothing to accept. [${name(r.github.error)}]`);
  const lines = [...todo];
  const changes = [...cf, ...gh];
  if (changes.length) lines.push("The changes:");
  let shown = 0;
  for (const c of changes) {
    const rest = changes.length - shown - 1;
    const tail = rest ? `\n...and ${rest} more not shown here: ask the agent for the full list.` : "";
    if ([...lines, `- ${c}`].join("\n").length + tail.length > max) break;
    lines.push(`- ${c}`);
    shown++;
  }
  if (shown < changes.length) lines.push(`...and ${changes.length - shown} more not shown here: ask the agent for the full list.`);
  return lines.join("\n");
}

export type Alarm = (ok: boolean, detail: string) => Promise<void>;

/**
 * Pings healthchecks.io: the check URL for all-clear, its /fail with the detail otherwise. Its phone
 * alert does not carry that detail (VERIFIED: healthchecks ntfy_message.html has no ping body), so a
 * failed count is ALSO pushed straight to ntfy with the detail when `ntfyUrl` is set.
 */
export function headcountAlarm(url: string | undefined, ntfyUrl?: string, fetchFn: typeof fetch = fetch): Alarm | undefined {
  if (!url || !/^https:\/\/hc-ping\.com\/[0-9a-f-]{36}$/.test(url.trim())) return undefined;
  const ntfy = ntfyTopic(ntfyUrl);
  return async (ok, detail) => {
    const res = await fetchFn(ok ? url.trim() : `${url.trim()}/fail`, { method: "POST", body: detail });
    if (!res.ok) throw new Error(`healthchecks answered ${res.status}`);
    if (ok) return;
    if (!ntfy) throw new Error("no ntfy topic set: the phone alert will not name the keys");
    const push = await fetchFn(ntfy, { method: "POST", body: detail.slice(0, 3000), headers: { Title: "Front desk nightly check: needs you", Priority: "high" } });
    if (!push.ok) throw new Error(`ntfy answered ${push.status}`);
  };
}

/** The ntfy topic URL if it is a well-formed ntfy.sh topic, else undefined. */
function ntfyTopic(ntfyUrl: string | undefined): string | undefined {
  return ntfyUrl && /^https:\/\/ntfy\.sh\/[A-Za-z0-9_-]{16,64}$/.test(ntfyUrl.trim()) ? ntfyUrl.trim() : undefined;
}

// Tells Ben's phone a request is waiting; a tap opens its approve page. Throws when ntfy did not take it.
export type Push = (what: string, approveUrl: string) => Promise<void>;

/** Pushover's user key and app token (dashboard secrets), each 30 letters and digits. */
export interface PushoverKeys {
  user?: string;
  token?: string;
}

/**
 * One push per request (card a830d543): Pushover first, then ntfy. It carries what is asked and the
 * approve link, never a secret: the link still needs Ben's Access login and his passkey. MAX_PENDING
 * bounds how many can arrive. ntfy.sh refuses Cloudflare Workers' shared addresses (429, ntfy issues
 * #1963/#1726), hence Pushover, which counts per account. Throws "<service> answered NNN; ..." when none took it.
 */
export function approvalPush(ntfyUrl: string | undefined, pushover: PushoverKeys = {}, fetchFn: typeof fetch = fetch): Push | undefined {
  const ntfy = ntfyTopic(ntfyUrl);
  const key = /^[A-Za-z0-9]{30}$/;
  const po = pushover.user && pushover.token && key.test(pushover.user.trim()) && key.test(pushover.token.trim())
    ? { user: pushover.user.trim(), token: pushover.token.trim() } : undefined;
  const senders: [string, (what: string, url: string) => Promise<Response>][] = [];
  if (po) senders.push(["pushover", (what, url) => fetchFn("https://api.pushover.net/1/messages.json", { method: "POST",
    body: new URLSearchParams({ token: po.token, user: po.user, title: "Front desk: approve?", message: what.slice(0, 300), url, url_title: "Open to approve" }) })]);
  if (ntfy) senders.push(["ntfy", (what, url) => fetchFn(ntfy, { method: "POST", body: what.slice(0, 300), headers: { Title: "Front desk: approve?", Click: url, Priority: "high" } })]);
  if (!senders.length) return undefined;
  return async (what, approveUrl) => {
    const failed: string[] = [];
    for (const [name, send] of senders) {
      // A thrown fetch error is reduced to fixed words: its message could carry the topic or a key.
      const status = await send(what, approveUrl).then((r) => r.status, () => 0);
      if (status >= 200 && status < 300) return;
      failed.push(status ? `${name} answered ${status}` : `${name} unreachable`);
    }
    throw new Error(failed.join("; "));
  };
}

// Test seam: lets a test pause an approval between verification and commit.
export interface DeskHooks {
  afterVerify?: (grantId: string) => Promise<void>;
  // The vault Worker (service binding VAULT); absent in tests that do not need it.
  vault?: VaultApi;
}

// The passkey secret a browser sent with its answer, if it is 32 bytes.
function prfOf(input: unknown): string | null {
  const prf = (input as { prf?: unknown } | null)?.prf;
  try {
    return typeof prf === "string" && fromB64url(prf).length === 32 ? prf : null;
  } catch {
    return null;
  }
}

const isVault = (job: JobName) => (JOBS[job] as Job).vault === true;

export class Desk {
  private store: Store;
  private site: Site;
  private hooks: DeskHooks;
  constructor(store: Store, site: Site, hooks: DeskHooks = {}) {
    this.store = store;
    this.site = site;
    this.hooks = hooks;
  }

  private grantFacts(g: Grant) {
    return { grant_id: g.id, job: g.job, params: g.params, reason: g.reason, requester: g.requester, expires_at: g.expires_at };
  }

  private async log(entry: Omit<LogEntry, "at">, now: number): Promise<void> {
    // Keys sort by a running number; there is no delete or update path for log entries.
    const seq = ((await this.store.get<number>("meta:logseq")) ?? 0) + 1;
    await this.store.put("meta:logseq", seq);
    const key = `log:${String(seq).padStart(12, "0")}`;
    await this.store.put<LogEntry>(key, { at: now, ...entry });
  }

  async readLog(): Promise<LogEntry[]> {
    return [...(await this.store.list<LogEntry>({ prefix: "log:" })).values()];
  }

  async passkeys(): Promise<Passkey[]> {
    return [...(await this.store.list<Passkey>({ prefix: "passkey:" })).values()];
  }

  async grant(id: string): Promise<Grant> {
    const g = await this.store.get<Grant>(`grant:${id}`);
    if (!g) throw new DeskError("no_such_grant", 404);
    return g;
  }

  async request(input: unknown, requester: string, now: number, source: Source = {}): Promise<Grant> {
    await this.eraseStaleSecrets(now);
    const body = (input ?? {}) as { job?: unknown; params?: unknown; reason?: unknown };
    if (typeof body.job !== "string" || !Object.hasOwn(JOBS, body.job)) {
      await this.log({ event: "refused", requester, detail: `job not offered: ${String(body.job).slice(0, 60)}` }, now);
      throw new DeskError("job_not_offered", 400);
    }
    const job = body.job as JobName;
    // A key for the agent is made only for a request signed with the enrolled c-box key, so a
    // stolen agent login used elsewhere gets nothing (Codex minted r1 #2, architecture review r1).
    if ((JOBS[job] as Job).pinIp) await this.requireSigned(source, requester, job, now);
    // Bounds on what can wait for Ben, so a stolen login cannot flood his phone (Codex architecture r1 #4).
    const waiting = [...(await this.store.list<Grant>({ prefix: "grant:" })).values()].filter((x) => x.status === "pending" && x.expires_at > now);
    const refuseBusy = async (code: string) => {
      await this.log({ event: "refused", requester, job, detail: `${job}: ${code}` }, now);
      throw new DeskError(code, 429);
    };
    if (waiting.filter((x) => x.requester === requester).length >= MAX_PENDING) await refuseBusy("too_many_pending");
    if (job === "cbox.key.enroll" && waiting.some((x) => x.job === "cbox.key.enroll")) await refuseBusy("enroll_pending");
    // Whatever ip the agent sent is replaced with the address Cloudflare saw.
    const asked = (JOBS[job] as Job).pinIp ? { ...((body.params ?? {}) as object), ip: source.ip } : body.params;
    const params: Record<string, string> | null = JOBS[job].validate(asked);
    if (!params) throw new DeskError("bad_params", 400);
    if (job === "cbox.key.enroll") {
      // Shown to Ben with what it replaces; approval is refused if that has changed since (stale request).
      params.fingerprint = await fingerprint(params.key);
      params.replaces = (await currentKey(this.store))?.fingerprint ?? "none";
      params.rev = String(await keyRev(this.store));
    }
    if (job === "gh.app.baseline") {
      // Ben's screen lists exactly what his tap accepts; the vault refuses if GitHub changed since (Codex C6a-1 r1 #4).
      const seen = await Promise.resolve()
        .then(() => {
          if (!this.hooks.vault) throw new Error("vault not connected");
          return this.hooks.vault.ghPreview();
        })
        .catch((e: Error) => {
          throw new DeskError(`github_preview_failed: ${e.message.slice(0, 100)}`, 502);
        });
      params.changes = seen.changes.length ? seen.changes.join("\n") : "none";
      if (params.changes.length > 4000) throw new DeskError("too_many_changes", 400);
      params.snapshot = seen.snapshot;
      params.base = seen.base;
    }
    if (typeof body.reason !== "string" || !body.reason.trim() || body.reason.length > 200) {
      throw new DeskError("bad_reason", 400);
    }
    const base = { id: crypto.randomUUID(), job, params, requester, expires_at: now + APPROVE_WINDOW_MS };
    const g: Grant = { ...base, reason: body.reason.trim(), created_at: now, hash: await grantHash(base), status: "pending" };
    if ((JOBS[job] as Job).pinIp) g.cbox_rev = await keyRev(this.store);
    await this.store.put(`grant:${g.id}`, g);
    await this.log({ event: "requested", ...this.grantFacts(g) }, now);
    return g;
  }

  private async pending(id: string, now: number): Promise<Grant> {
    const g = await this.grant(id);
    if (g.status !== "pending") throw new DeskError("not_pending", 409);
    if (now > g.expires_at) throw new DeskError("grant_expired", 410);
    return g;
  }

  // The challenge is 16 random bytes followed by the grant's hash, so an
  // approval can only ever be for this grant.
  async approvalOptions(id: string, now: number) {
    const g = await this.pending(id, now);
    const keys = await this.passkeys();
    if (!keys.length) throw new DeskError("no_passkey_enrolled", 409);
    const challenge = new Uint8Array([...crypto.getRandomValues(new Uint8Array(16)), ...hexToBytes(g.hash)]);
    const options = await generateAuthenticationOptions({
      rpID: this.site.rpID,
      challenge,
      userVerification: "required",
      allowCredentials: keys.map((k) => ({ id: k.id })),
    });
    await this.store.put<Challenge>(`challenge:${options.challenge}`, {
      purpose: "approve",
      grant_id: g.id,
      expires_at: now + CHALLENGE_TTL_MS,
      used: false,
    });
    return isVault(g.job) ? { ...options, prfSalt: await saltFor(PRF_MASTER_LABEL) } : options;
  }

  // A refusal Ben should be able to see, for something not tied to one grant.
  async refuse(detail: string, now: number): Promise<void> {
    await this.log({ event: "refused", detail: detail.slice(0, 160) }, now);
  }

  // Refusals of callers who are not Ben or the agent. Anyone past the edge login could
  // repeat these, so at most ROUTE_REFUSALS_PER_DAY get their own log row each UTC day;
  // the rest only raise that day's count, one stored number per day.
  async refuseCaller(detail: string, now: number): Promise<void> {
    const key = `refusals:${new Date(now).toISOString().slice(0, 10)}`;
    const count = ((await this.store.get<number>(key)) ?? 0) + 1;
    await this.store.put(key, count);
    if (count <= ROUTE_REFUSALS_PER_DAY) await this.refuse(detail, now);
    else if (count === ROUTE_REFUSALS_PER_DAY + 1) await this.refuse(`more caller refusals today; counted under ${key}`, now);
  }

  async refusalCounts(): Promise<Map<string, number>> {
    return this.store.list<number>({ prefix: "refusals:" });
  }

  private async takeChallenge(response: { response: { clientDataJSON: string } }, purpose: Challenge["purpose"], now: number) {
    // Every refusal here is logged: these fail before the passkey is checked, and used to leave no trace.
    const refuse = async (code: string, status: number) => {
      await this.refuse(`${purpose}: ${code}`, now);
      return new DeskError(code, status);
    };
    let challenge: string;
    try {
      challenge = JSON.parse(new TextDecoder().decode(fromB64url(response.response.clientDataJSON))).challenge;
    } catch {
      throw await refuse("bad_response", 400);
    }
    const c = await this.store.get<Challenge>(`challenge:${challenge}`);
    if (!c || c.purpose !== purpose) throw await refuse("unknown_challenge", 403);
    if (c.used) throw await refuse("challenge_used", 403);
    if (now > c.expires_at) throw await refuse("challenge_expired", 403);
    // Burned before verification, so a failed or replayed attempt never gets a second try.
    await this.store.put<Challenge>(`challenge:${challenge}`, { ...c, used: true });
    return { challenge, record: c };
  }

  async approve(id: string, response: AuthenticationResponseJSON, now: number): Promise<Grant> {
    let g: Grant;
    try {
      g = await this.pending(id, now);
    } catch (e) {
      if (e instanceof DeskError) await this.refuse(`approve: ${e.code}`, now);
      throw e;
    }
    const { challenge, record } = await this.takeChallenge(response, "approve", now);
    if (record.grant_id !== g.id || !challengeCarries(challenge, g.hash)) {
      await this.log({ event: "refused", ...this.grantFacts(g), detail: "approval was for a different grant" }, now);
      throw new DeskError("wrong_grant", 403);
    }
    const fail = (detail: string) => this.log({ event: "refused", ...this.grantFacts(g), detail }, now);
    const { key, newCounter } = await this.verifyPasskey(response, challenge, fail);
    // A vault job needs the passkey's secret; without it nothing is approved.
    const prf = isVault(g.job) ? prfOf(response) : null;
    if (isVault(g.job) && !prf) {
      await fail("no passkey secret sent");
      throw new DeskError("prf_missing", 422);
    }
    await this.hooks.afterVerify?.(g.id);
    // Verification awaited crypto, so another request may have run meanwhile.
    // Re-read and commit with storage calls only, which the Durable Object does not interleave.
    const current = await this.pending(id, now);
    if (current.cbox_rev !== undefined && current.cbox_rev !== (await keyRev(this.store))) {
      await fail("the c-box key was removed or replaced since this request");
      throw new DeskError("cbox_key_changed", 409);
    }
    await this.commitCounter(key.id, newCounter);
    const approved: Grant = { ...current, status: "approved", approved_at: now };
    await this.store.put(`grant:${g.id}`, approved);
    await this.log({ event: "approved", ...this.grantFacts(g) }, now);
    if (g.job === "cbox.key.enroll") await this.enrollCboxKey(approved, now);
    if (!prf) return approved;
    // Committed as approved first, so a replay finds it not pending while the vault works.
    let result: unknown;
    try {
      if (!this.hooks.vault) throw new Error("vault not connected");
      result = await this.hooks.vault.run(g.job, g.params, prf);
      const ok = (result as { ok?: unknown } | null)?.ok === true;
      await this.log({ event: ok ? "job_done" : "job_failed", ...this.grantFacts(g), detail: logDetail(withoutSecret(result)) }, now);
    } catch (e) {
      result = { error: (e as Error).message.slice(0, 120) };
      await this.log({ event: "job_failed", ...this.grantFacts(g), detail: (e as Error).message.slice(0, 120) }, now);
    }
    // Re-read: other requests ran while the vault worked; only the result is added. If Ben removed or
    // replaced the c-box key meanwhile, a minted key's secret is dropped, never released.
    const latest = await this.grant(id);
    if (latest.cbox_rev !== undefined && latest.cbox_rev !== (await keyRev(this.store)) && withoutSecret(result) !== result) {
      result = withoutSecret(result);
      await this.log({ event: "refused", ...this.grantFacts(g), detail: "c-box key changed during the job; the key's secret was dropped" }, now);
    }
    const done: Grant = { ...latest, result };
    await this.store.put(`grant:${g.id}`, done);
    return done;
  }

  /**
   * The nightly key count (cron, src/index.ts scheduled; card C5c-2 3baea7cc). Asks the vault to
   * count, logs the answer for Ben's /log, then tells the alarm: all-clear only when the count is
   * clean, a fail with the detail otherwise. A night with no all-clear -- a mismatch, an error, or
   * no run at all -- is what alerts Ben's phone, from healthchecks.io, off the c-box.
   */
  async headcount(alarm: Alarm | undefined, now: number): Promise<Headcount> {
    let r: Headcount;
    try {
      if (!this.hooks.vault) throw new Error("vault not connected");
      r = await this.hooks.vault.headcount();
    } catch (e) {
      r = { ok: false, tokens: -1, unexpected: [], stretched: [], missing: [], github: { ok: false, changes: [] }, error: (e as Error).message.slice(0, 120) };
    }
    const detail = headcountWords(r);
    await this.log({ event: r.ok ? "headcount_ok" : "headcount_mismatch", detail }, now);
    try {
      if (!alarm) throw new Error("no alarm configured");
      await alarm(r.ok, detail);
    } catch (e) {
      await this.log({ event: "headcount_alarm_failed", detail: (e as Error).message.slice(0, 120) }, now);
    }
    return r;
  }

  // Checks Ben's passkey answer against a challenge already taken. Every failure is logged through `fail`.
  private async verifyPasskey(response: AuthenticationResponseJSON, challenge: string, fail: (detail: string) => Promise<void>) {
    const key = await this.store.get<Passkey>(`passkey:${response.id}`);
    if (!key) {
      await fail("unknown passkey");
      throw new DeskError("unknown_passkey", 403);
    }
    try {
      const result = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: this.site.origin,
        expectedRPID: this.site.rpID,
        credential: { id: key.id, publicKey: new Uint8Array(key.publicKey), counter: key.counter },
        requireUserVerification: true,
      });
      if (!result.verified) throw new Error("not verified");
      return { key, newCounter: result.authenticationInfo.newCounter };
    } catch (e) {
      await fail(`passkey check failed: ${(e as Error).message.slice(0, 120)}`);
      throw new DeskError("passkey_check_failed", 403);
    }
  }

  // Storage calls only, after verification. A counter that does not move forward means a replayed
  // or cloned passkey (unless both stay 0, which synced passkeys such as 1Password's report).
  private async commitCounter(id: string, newCounter: number): Promise<void> {
    const currentKey = await this.store.get<Passkey>(`passkey:${id}`);
    if (!currentKey) throw new DeskError("unknown_passkey", 403);
    const inUse = newCounter > 0 || currentKey.counter > 0;
    if (inUse && newCounter <= currentKey.counter) throw new DeskError("stale_counter", 409);
    await this.store.put<Passkey>(`passkey:${id}`, { ...currentKey, counter: newCounter });
  }

  // PRF check: does Ben's passkey give the same secret on every tap? Nothing secret is stored;
  // only a short fingerprint of the output is logged. The output comes from Ben's browser and is
  // not signed by the passkey -- fine for a check; the master key's decryption is its own proof.
  async prfCheckOptions(now: number) {
    const keys = await this.passkeys();
    if (!keys.length) throw new DeskError("no_passkey_enrolled", 409);
    const options = await generateAuthenticationOptions({
      rpID: this.site.rpID,
      userVerification: "required",
      allowCredentials: keys.map((k) => ({ id: k.id })),
    });
    await this.store.put<Challenge>(`challenge:${options.challenge}`, { purpose: "check", expires_at: now + CHALLENGE_TTL_MS, used: false });
    return { ...options, prfSalt: await saltFor(PRF_CHECK_LABEL) };
  }

  async prfCheck(input: unknown, now: number): Promise<{ fingerprint: string }> {
    const body = (input ?? {}) as { credential?: AuthenticationResponseJSON; prf?: unknown; prf_info?: unknown };
    const { challenge } = await this.takeChallenge(body.credential as AuthenticationResponseJSON, "check", now);
    const fail = (detail: string) => this.log({ event: "refused", detail: `prf check: ${detail}` }, now);
    const { key, newCounter } = await this.verifyPasskey(body.credential!, challenge, fail);
    await this.commitCounter(key.id, newCounter);
    let bytes: Uint8Array | null = null;
    try {
      if (typeof body.prf === "string" && body.prf) bytes = fromB64url(body.prf);
    } catch {
      bytes = null;
    }
    if (!bytes || bytes.length !== 32) {
      const info = typeof body.prf_info === "string" ? body.prf_info.slice(0, 60) : "";
      await this.log({ event: "prf_check", detail: `FAIL: no usable PRF output (${info || "none"}), passkey ${key.id.slice(0, 8)}…` }, now);
      throw new DeskError("prf_missing", 422);
    }
    const fingerprint = hex(await sha256(bytes)).slice(0, 16);
    await this.log({ event: "prf_check", detail: `PASS: fingerprint ${fingerprint}, passkey ${key.id.slice(0, 8)}…` }, now);
    return { fingerprint };
  }

  // Marked collected before the job runs: two collects, or a crash mid-job, never run it twice.
  async collect(id: string, requester: string, now: number, source: Source = {}): Promise<{ grant: Grant; result: unknown }> {
    const first = await this.grant(id);
    if (first.requester !== requester) throw new DeskError("not_your_grant", 403);
    // A key is handed only to a signed collect from the address it is pinned to (Codex architecture r1 #2).
    if ((JOBS[first.job] as Job).pinIp) await this.requireSigned(source, requester, first.job, now);
    // Re-read after the signature's crypto: everything from here to the write is storage calls only,
    // so two collects cannot both see "approved" (Codex architecture r2).
    const g = await this.grant(id);
    if (g.status === "pending") throw new DeskError("not_approved", 403);
    if (g.status === "collected") throw new DeskError("already_collected", 409);
    if (now > (g.approved_at ?? 0) + COLLECT_WINDOW_MS) {
      await this.eraseStaleSecrets(now);
      throw new DeskError("collect_window_closed", 410);
    }
    // A vault job is approved before the vault finishes; until its result is in, there is nothing to collect.
    if ((JOBS[g.job] as Job).vault && g.result === undefined) throw new DeskError("not_ready", 409);
    if ((JOBS[g.job] as Job).pinIp) {
      if (g.cbox_rev !== (await keyRev(this.store))) throw new DeskError("cbox_key_changed", 409);
      if (source.ip !== g.params.ip) {
        await this.log({ event: "refused", ...this.grantFacts(g), detail: `collect from ${String(source.ip).slice(0, 45)}, key is pinned to ${g.params.ip}` }, now);
        throw new DeskError("address_changed", 409);
      }
    }
    // The stored copy loses the key's secret: it is handed over this once.
    const collected: Grant = { ...g, status: "collected", collected_at: now, result: withoutSecret(g.result) };
    await this.store.put(`grant:${g.id}`, collected);
    const job = JOBS[g.job] as Job;
    const result = job.vault ? g.result : await job.run!(g.params);
    await this.log({ event: "collected", ...this.grantFacts(g) }, now);
    return { grant: collected, result };
  }

  // Runs the route's signature check; a failure is logged and refused.
  private async requireSigned(source: Source, requester: string, job: string, now: number): Promise<void> {
    try {
      if (!source.checkSignature) throw new DeskError("not_signed", 401);
      await source.checkSignature();
    } catch (e) {
      const code = e instanceof DeskError ? e.code : "bad_signature";
      await this.log({ event: "refused", requester, job: job as JobName, detail: `${job}: ${code}` }, now);
      throw e instanceof DeskError ? e : new DeskError(code, 401);
    }
  }

  // At Ben's approval of cbox.key.enroll: stores the key, unless the key it was to replace has
  // changed since the request (two enrollments approved out of order).
  private async enrollCboxKey(g: Grant, now: number): Promise<void> {
    const current = (await currentKey(this.store))?.fingerprint ?? "none";
    // A generation number, not the fingerprint: after enroll-then-remove, "none" again must not
    // revive an old enrollment (Codex architecture r2).
    if (String(await keyRev(this.store)) !== g.params.rev) {
      await this.log({ event: "refused", ...this.grantFacts(g), detail: `enroll: key changed since the request (now ${current})` }, now);
      throw new DeskError("stale_enroll", 409);
    }
    await this.store.put<CboxKey>("cbox:key", { spki: g.params.key, fingerprint: g.params.fingerprint, enrolled_at: now, grant_id: g.id });
    await this.store.put("cbox:rev", (await keyRev(this.store)) + 1);
    await this.log({ event: "cbox_key_enrolled", ...this.grantFacts(g), detail: `c-box key ${g.params.fingerprint}, replaces ${current}` }, now);
  }

  /** Ben removes the c-box key (lost or stolen box): every signed request is refused until a new one is enrolled. */
  async removeCboxKey(now: number): Promise<string> {
    const k = await currentKey(this.store);
    if (!k) throw new DeskError("no_cbox_key", 404);
    await this.store.put("cbox:key", null);
    await this.store.put("cbox:rev", (await keyRev(this.store)) + 1);
    await this.log({ event: "cbox_key_removed", detail: `c-box key ${k.fingerprint} removed by Ben` }, now);
    return k.fingerprint;
  }

  async cboxKey(): Promise<CboxKey | undefined> {
    return currentKey(this.store);
  }

  // A minted key's secret not collected within the collect window is erased (Codex minted r1 #5).
  // Runs at each new /request and at a late collect -- not on page views -- so with no further
  // requests it stays stored (the key itself still expires within 15 minutes).
  private async eraseStaleSecrets(now: number): Promise<void> {
    // Remembered signed messages are dropped once their window is over (they can no longer pass anyway).
    for (const [k, until] of await this.store.list<number>({ prefix: "sig:" })) if (until < now) await this.store.delete(k);
    for (const [k, g] of await this.store.list<Grant>({ prefix: "grant:" })) {
      if (g.status === "approved" && now > (g.approved_at ?? 0) + COLLECT_WINDOW_MS && withoutSecret(g.result) !== g.result) {
        await this.store.put(k, { ...g, result: withoutSecret(g.result) });
      }
    }
  }

  // First passkey only. Adding or replacing passkeys comes with the recovery key (PR3b).
  async enrollOptions(now: number) {
    if ((await this.passkeys()).length) throw new DeskError("already_enrolled", 409);
    const options = await generateRegistrationOptions({
      rpName: "Front desk",
      rpID: this.site.rpID,
      userName: "ben",
      attestationType: "none",
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { prf: {} } as Record<string, unknown>,
    });
    await this.store.put<Challenge>(`challenge:${options.challenge}`, {
      purpose: "enroll",
      expires_at: now + CHALLENGE_TTL_MS,
      used: false,
    });
    return options;
  }

  async enroll(response: RegistrationResponseJSON, now: number): Promise<Passkey> {
    if ((await this.passkeys()).length) {
      await this.refuse("enroll: already_enrolled", now);
      throw new DeskError("already_enrolled", 409);
    }
    const { challenge } = await this.takeChallenge(response, "enroll", now);
    let info;
    try {
      const result = await verifyRegistrationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: this.site.origin,
        expectedRPID: this.site.rpID,
        requireUserVerification: true,
      });
      if (!result.verified || !result.registrationInfo) throw new Error("not verified");
      info = result.registrationInfo;
    } catch (e) {
      await this.log({ event: "refused", detail: `enrollment failed: ${(e as Error).message.slice(0, 120)}` }, now);
      throw new DeskError("enroll_failed", 403);
    }
    // Re-checked after the awaited verification, for the same reason as approve().
    if ((await this.passkeys()).length) throw new DeskError("already_enrolled", 409);
    const key: Passkey = {
      id: info.credential.id,
      publicKey: [...info.credential.publicKey],
      counter: info.credential.counter,
      enrolled_at: now,
    };
    await this.store.put(`passkey:${key.id}`, key);
    await this.log({ event: "passkey_enrolled", detail: `passkey ${key.id.slice(0, 8)}…` }, now);
    return key;
  }
}

export const LOG_DETAIL_MAX = 1200;

/** A copy of a vault result with a minted key's secret removed (for the log, Ben's screen, storage after collect). */
export function withoutSecret(result: unknown): unknown {
  const key = (result as { key?: unknown } | null)?.key;
  if (!key || typeof key !== "object" || !("value" in key)) return result;
  const { value: _drop, ...rest } = key as Record<string, unknown>;
  return { ...(result as object), key: rest };
}

// The job's evidence for the log, always valid JSON. If it is too long, the token-id lists are
// shortened to their first 10 with their full counts and "truncated": true (Codex r2 #5); the
// complete result stays on the grant record.
export function logDetail(result: unknown): string {
  const full = JSON.stringify(result);
  if (full.length <= LOG_DETAIL_MAX) return full;
  const r = result as { audit?: { new_since_setup?: string[]; minted_still_listed?: string[] } };
  const cut = (ids: string[] = []) => ({ first: ids.slice(0, 10), total: ids.length });
  const short = JSON.stringify({
    ...r,
    audit: { ...r.audit, new_since_setup: cut(r.audit?.new_since_setup), minted_still_listed: cut(r.audit?.minted_still_listed) },
    truncated: true,
  });
  return short.length <= LOG_DETAIL_MAX ? short : JSON.stringify({ truncated: true, ok: (result as { ok?: unknown }).ok === true, note: "see grant record" });
}

async function saltFor(label: string): Promise<string> {
  return b64url(await sha256(enc.encode(label)));
}

function hexToBytes(h: string): Uint8Array {
  return Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
}

function challengeCarries(challenge: string, hash: string): boolean {
  const bytes = fromB64url(challenge);
  return bytes.length === 48 && hex(bytes.slice(16)) === hash;
}

export class MemoryStore implements Store {
  private data = new Map<string, unknown>();
  async get<T>(key: string) {
    return structuredClone(this.data.get(key)) as T | undefined;
  }
  async put<T>(key: string, value: T) {
    this.data.set(key, structuredClone(value));
  }
  async delete(key: string) {
    return this.data.delete(key);
  }
  async list<T>({ prefix }: { prefix: string }) {
    const keys = [...this.data.keys()].filter((k) => k.startsWith(prefix)).sort();
    return new Map(keys.map((k) => [k, structuredClone(this.data.get(k)) as T]));
  }
}
