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
import { ascii, name, plainChanges } from "./ghplain.ts";
import { JOBS, type Job, type JobName } from "./jobs.ts";
import { currentKey, fingerprint, keyRev, type CboxKey } from "./cboxkey.ts";
import type { Headcount, VaultApi, VaultCardApi, VaultRunApi } from "../vault/src/api.ts";
import { ALREADY_USED, APPROVAL_API_VERSION, REFUSED_BEFORE_RUN, TOO_OLD } from "../vault/src/approval.ts";
export type VaultStage = "before" | "used" | "old" | "unknown";
import { RecorderError, type Receipt, type Recorder, type Stage } from "./recorder.ts";

export const APPROVE_WINDOW_MS = 10 * 60_000; // ask -> approve
/** How long a c-box key change waits for the vault to take the new generation before answering Ben anyway. */
export const KEY_REV_WAIT_MS = 5_000;
export const COLLECT_WINDOW_MS = 5 * 60_000; // approve -> collect
export const MAX_PENDING = 3; // grants one requester may have waiting for Ben at once
export const CHALLENGE_TTL_MS = 5 * 60_000;
export const ROUTE_REFUSALS_PER_DAY = 20;
export const ALERT_TIMEOUT_MS = 5_000; // a result-unrecorded push to Ben's phone
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

// "stopped": approved, but its approval could not be recorded (or the c-box key changed while it
// was being recorded), so nothing runs and it cannot be collected; the agent asks again.
export type GrantStatus = "pending" | "approved" | "collected" | "stopped";

// Where an agent request came from: the address Cloudflare saw, and the route's check of the c-box
// signature (cboxkey.ts), run only for jobs that hand out keys.
export interface Source {
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
  // What the Observatory's recorder has receipted for this grant (card 97a2e83d): the SHA-256 of the
  // request record's bytes (later records name the request by it), then the approval and result
  // record numbers. A grant with no request receipt is never approved or collected. `verdict` is the
  // number of the "overseer: not checked" record (card 6da30339); a grant without it is never approved.
  recorded?: { request: string; verdict?: number; approval?: number; result?: number };
  // Card entries only (card 85818ab1; src/carddesk.ts): the card id; each stage's full signed receipt (returned to the
  // agent, U6); the result record's exact bytes, frozen before the first send so every resend is identical (V1, W1);
  // and whether a held answer was erased after the collect window (V3).
  card?: string;
  receipts?: Partial<Record<Stage, Omit<Receipt, "body">>>;
  result_body?: string;
  answer_erased?: true;
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

export interface PasskeyPin {
  id: string;
  key: string; // the COSE public key, base64url
  rp_hash: string;
  origin_hash: string;
}

interface Challenge {
  purpose: "approve" | "enroll" | "check" | "setup" | "card";
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
    ...(r.widened ?? []).map((k) =>
      k.why === "headcount_key_needs_setup"
        ? `Cloudflare: the nightly check's own key was made before its permission was recorded. Ask the agent for the setup tap (one Face ID) [${name(k.id)}]`
        : k.why === "headcount_key_not_list_only"
        ? `Cloudflare: the nightly check's own key can now do more than list keys. Tell the agent now [${name(k.id)}]`
        : `Cloudflare: a key you kept can now do more than you approved, or more than read-only. If you did not widen it, tell the agent now [${name(k.id)}] (${name(k.why)})`,
    ),
    ...r.cleanup.map((k) =>
      k.recorded
        ? `Cloudflare: a short vault key not yet deleted, ${k.expired ? "already expired" : `usable until ${name(k.expires_on)}`}; the vault deletes it at your next Cloudflare tap [${name(k.id)}]`
        : `Cloudflare: a key named like the vault's own short keys that the vault did not make, ${k.expired ? "already expired" : `usable until ${name(k.expires_on)}`}. The vault will not delete it. If you did not make it, tell the agent now; delete it in the Cloudflare dashboard [${name(k.id)}]`,
    ),
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
  return lines.map(ascii).join("\n");
}

export type Alarm = (ok: boolean, detail: string) => Promise<void>;

/**
 * Pings healthchecks.io: the check URL for all-clear, its /fail with the detail otherwise. Its phone
 * alert does not carry that detail (VERIFIED for its message templates: they have no ping body), so a
 * failed count is ALSO pushed straight to Ben's phone with the detail through Pushover, the same sender
 * as approval pushes.
 */
export function headcountAlarm(url: string | undefined, pushover: PushoverKeys = {}, fetchFn: typeof fetch = fetch): Alarm | undefined {
  if (!url || !/^https:\/\/hc-ping\.com\/[0-9a-f-]{36}$/.test(url.trim())) return undefined;
  const send = phoneSender(pushover, fetchFn);
  return async (ok, detail) => {
    const res = await fetchFn(ok ? url.trim() : `${url.trim()}/fail`, { method: "POST", body: detail });
    if (!res.ok) throw new Error(`healthchecks answered ${res.status}`);
    if (ok) return;
    if (!send) throw new Error("no phone push set: the phone alert will not name the keys");
    await send("Front desk nightly check: needs you", detail);
  };
}

// Tells Ben's phone a request is waiting; a tap opens its approve page. Throws when Pushover did not take it.
export type Push = (what: string, approveUrl: string) => Promise<void>;

/** Pushover's user key and app token (dashboard secrets), each 30 letters and digits. */
export interface PushoverKeys {
  user?: string;
  token?: string;
}

/**
 * One push per request (card a830d543), through Pushover (card W2 6d0acbc8 retired the old fallback).
 * It carries what is asked and the approve link, never a secret: the link still needs Ben's Access login
 * and his passkey. MAX_PENDING bounds how many can arrive. Throws "pushover answered NNN" or
 * "pushover unreachable" when it did not take it.
 */
export function approvalPush(pushover: PushoverKeys = {}, fetchFn: typeof fetch = fetch): Push | undefined {
  const send = phoneSender(pushover, fetchFn);
  return send && ((what, approveUrl) => send("Front desk: approve?", what.slice(0, 300), approveUrl));
}

/** A plain message to Ben's phone (no link), or undefined when no push service is set up. */
export function phoneAlert(pushover: PushoverKeys = {}, fetchFn: typeof fetch = fetch): Alert | undefined {
  const send = phoneSender(pushover, fetchFn);
  return send && ((title, text) => send(title, text));
}
export type Alert = (title: string, text: string) => Promise<void>;

/**
 * Sends one message to Ben's phone through Pushover, the only phone route (card W2 6d0acbc8).
 * Undefined when Pushover is not set up.
 */
function phoneSender(pushover: PushoverKeys, fetchFn: typeof fetch) {
  const key = /^[A-Za-z0-9]{30}$/;
  const po = pushover.user && pushover.token && key.test(pushover.user.trim()) && key.test(pushover.token.trim())
    ? { user: pushover.user.trim(), token: pushover.token.trim() } : undefined;
  if (!po) return undefined;
  return async (title: string, text: string, url?: string) => {
    // Pushover takes at most 1024 characters per message.
    const body = new URLSearchParams({ token: po.token, user: po.user, title, message: text.slice(0, 1024), ...(url ? { url, url_title: "Open to approve" } : {}) });
    // A thrown fetch error is reduced to fixed words: its message could carry a key.
    const status = await fetchFn("https://api.pushover.net/1/messages.json", { method: "POST", body }).then((r) => r.status, () => 0);
    if (status >= 200 && status < 300) return;
    throw new Error(status ? `pushover answered ${status}` : "pushover unreachable");
  };
}

// Test seam: lets a test pause an approval between verification and commit.
export interface DeskHooks {
  afterVerify?: (grantId: string) => Promise<void>;
  // The vault Worker (service binding VAULT); absent in tests that do not need it. Its card calls (VaultCardApi) are
  // used only by src/carddesk.ts, which checks they are there.
  vault?: VaultApi & Partial<VaultCardApi> & Partial<Pick<VaultRunApi, "setKeyRev">>;
  // The Observatory's recorder (recorder.ts). Absent = not set up: every request is refused.
  recorder?: Recorder;
  // Ben's phone, for a job that ran but whose result could not be recorded (phoneAlert).
  alert?: Alert;
}

// The public parts of Ben's passkey answer, kept so the Observatory can check the signature itself
// (phase 3b). Never the PRF output, the user handle or extension results.
export function assertionOf(r: AuthenticationResponseJSON) {
  return { passkey_id: r.id, authenticator_data: r.response.authenticatorData, client_data_json: r.response.clientDataJSON, signature: r.response.signature };
}

// The passkey secret a browser sent with its answer, if it is 32 bytes.
export function prfOf(input: unknown): string | null {
  const prf = (input as { prf?: unknown } | null)?.prf;
  try {
    return typeof prf === "string" && fromB64url(prf).length === 32 ? prf : null;
  } catch {
    return null;
  }
}

const isVault = (job: JobName) => (JOBS[job] as Job).vault === true;

/**
 * Where a failed vault call stopped, from its exact error message only (card bb86abf0 R6): "before" = a
 * vault refusal raised before it recorded the grant as used, so nothing ran; "used" = the grant was already
 * used once, so it may have run; "old" = too old to admit, which does not tell whether it ran before;
 * anything else, including an unknown message, is "unknown".
 */
export function vaultStage(message: string): VaultStage {
  if ((REFUSED_BEFORE_RUN as readonly string[]).includes(message)) return "before";
  if (message === TOO_OLD) return "old";
  return message === ALREADY_USED ? "used" : "unknown";
}

// Members marked `protected` are shared with CardDesk (src/carddesk.ts), the card routes' rules.
export class Desk {
  protected store: Store;
  protected site: Site;
  protected hooks: DeskHooks;
  constructor(store: Store, site: Site, hooks: DeskHooks = {}) {
    this.store = store;
    this.site = site;
    this.hooks = hooks;
  }

  protected grantFacts(g: Grant) {
    return { grant_id: g.id, job: g.job, params: g.params, reason: g.reason, requester: g.requester, expires_at: g.expires_at };
  }

  // One record to the Observatory. Any failure is logged and becomes recorder_unavailable: the caller
  // stops before anything runs (card 97a2e83d).
  // `body`: frozen bytes to resend exactly (a card entry's result, V1).
  protected async record(g: Grant, stage: Stage, fields: Record<string, unknown>, now: number, body?: string): Promise<Receipt> {
    try {
      if (!this.hooks.recorder) throw new RecorderError("recorder not set");
      const r = { grant: g.id, stage, job: g.job, ...(stage === "request" ? {} : { request: g.recorded?.request }), ...fields };
      return await this.hooks.recorder(r, body);
    } catch (e) {
      const why = e instanceof RecorderError ? e.message : "recorder failed";
      await this.log({ event: "refused", ...this.grantFacts(g), detail: `${stage} not recorded: ${why}` }, now);
      throw new DeskError("recorder_unavailable", 503);
    }
  }

  // After an effect: never throws, since the effect has happened; a miss is logged for Ben.
  private async recordResult(id: string, ok: boolean, now: number): Promise<void> {
    const g = await this.grant(id);
    try {
      const r = await this.record(g, "result", { outcome: ok ? "done" : "failed", at: now }, now);
      const latest = await this.grant(id);
      await this.store.put(`grant:${id}`, { ...latest, recorded: { ...latest.recorded!, result: r.seq } });
    } catch {
      await this.log({ event: "result_unrecorded", ...this.grantFacts(g) }, now);
      // The job already ran, so Ben hears of it now; the hourly checker does not flag a missing result.
      // Bounded, so a stalled push service cannot hold back the job's answer.
      let timer: ReturnType<typeof setTimeout> | undefined;
      const late = new Promise<never>((_, reject) => (timer = setTimeout(() => reject(new Error("push timed out")), ALERT_TIMEOUT_MS)));
      const told = await Promise.race([
        Promise.resolve().then(() => {
          if (!this.hooks.alert) throw new Error("no phone push set");
          return this.hooks.alert("Front desk: a job ran but was not fully recorded", `Job ${g.job} ran, but the Observatory did not take its result record. Tell the agent: grant ${g.id}.`);
        }),
        late,
      ])
        .then(() => "", () => "failed")
        .finally(() => clearTimeout(timer));
      if (told) await this.log({ event: "alert_failed", ...this.grantFacts(g), detail: "result_unrecorded alert did not reach Ben's phone" }, now);
    }
  }

  // Ends an approved grant that must not run: it can no longer be collected, and the log says why.
  private async stop(id: string, detail: string, now: number): Promise<void> {
    const latest = await this.grant(id);
    await this.store.put(`grant:${id}`, { ...latest, status: "stopped" });
    await this.log({ event: "stopped", ...this.grantFacts(latest), detail }, now);
  }

  protected async log(entry: Omit<LogEntry, "at">, now: number): Promise<void> {
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

  // What the Observatory pins to check Ben's approvals itself (card 7190ab0a): public values only.
  // The site name and origin go as SHA-256 hex, so no live hostname enters its public repo.
  async passkeyPins(): Promise<PasskeyPin[]> {
    const sha = async (s: string) => hex(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))));
    const [rp_hash, origin_hash] = [await sha(this.site.rpID), await sha(this.site.origin)];
    return (await this.passkeys()).map((k) => ({ id: k.id, key: b64url(new Uint8Array(k.publicKey)), rp_hash, origin_hash }));
  }

  async grant(id: string): Promise<Grant> {
    const g = await this.store.get<Grant>(`grant:${id}`);
    if (!g) throw new DeskError("no_such_grant", 404);
    // A grant stored for a job since taken off the list (cf.token.zone.read, card ae6147e4) is never
    // approved, run or collected.
    if (!Object.hasOwn(JOBS, g.job)) throw new DeskError("job_retired", 410);
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
    if ((JOBS[job] as Job).signed) await this.requireSigned(source, requester, job, now);
    // Bounds on what can wait for Ben, so a stolen login cannot flood his phone (Codex architecture r1 #4).
    const waiting = [...(await this.store.list<Grant>({ prefix: "grant:" })).values()].filter((x) => x.status === "pending" && x.expires_at > now);
    const refuseBusy = async (code: string) => {
      await this.log({ event: "refused", requester, job, detail: `${job}: ${code}` }, now);
      throw new DeskError(code, 429);
    };
    if (waiting.filter((x) => x.requester === requester).length >= MAX_PENDING) await refuseBusy("too_many_pending");
    if (job === "cbox.key.enroll" && waiting.some((x) => x.job === "cbox.key.enroll")) await refuseBusy("enroll_pending");
    // Whatever ip the agent sent is replaced with the address Cloudflare saw.
    const params: Record<string, string> | null = JOBS[job].validate(body.params);
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
    if (job === "cf.token.accept") {
      // Ben's screen names exactly the keys his tap accepts; the vault refuses if any changed since.
      const keys = await Promise.resolve()
        .then(() => {
          if (!this.hooks.vault) throw new Error("vault not connected");
          return this.hooks.vault.cfPreview();
        })
        .catch((e: Error) => {
          throw new DeskError(`cloudflare_preview_failed: ${e.message.slice(0, 100)}`, 502);
        });
      if (!keys.length) throw new DeskError("nothing_to_accept", 409);
      if (keys.length > 20) throw new DeskError("too_many_changes", 400);
      // Over the ceiling (or scope unreadable): never offered to Ben's tap; the vault refuses it too.
      const over = keys.find((k) => k.over);
      if (over) throw new DeskError(`over_ceiling: ${over.id}: ${over.over}`, 409);
      params.ids = keys.map((k) => k.id).join(",");
      params.names = keys.map((k) => k.name).join("\n");
      params.scopes = keys.map((k) => k.scope).join("\n");
    }
    if (typeof body.reason !== "string" || !body.reason.trim() || body.reason.length > 200) {
      throw new DeskError("bad_reason", 400);
    }
    const base = { id: crypto.randomUUID(), job, params, requester, expires_at: now + APPROVE_WINDOW_MS };
    const g: Grant = { ...base, reason: body.reason.trim(), created_at: now, hash: await grantHash(base), status: "pending" };
    if ((JOBS[job] as Job).signed) g.cbox_rev = await keyRev(this.store);
    // Recorded before the grant exists: no receipt, nothing for Ben to approve.
    const receipt = await this.record(g, "request", { params, requester, reason: g.reason, created_at: now, expires_at: g.expires_at, grant_hash: g.hash }, now);
    g.recorded = { request: receipt.sha256 };
    // No overseer exists yet, so the record says so plainly (card 6da30339). No receipt: no grant.
    g.recorded.verdict = (await this.record(g, "verdict", { overseer: "not_checked" }, now)).seq;
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
    if (g.card !== undefined) throw new DeskError("on_card", 409); // a card's entries are approved only on the card page (U6)
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

  protected async takeChallenge(response: { response: { clientDataJSON: string } }, purpose: Challenge["purpose"], now: number) {
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
      if (g.card !== undefined) throw new DeskError("on_card", 409);
      // Asked before recording began, or before verdicts were recorded (or never receipted): never approved.
      if (!g.recorded?.request || g.recorded.verdict === undefined) throw new DeskError("not_recorded", 409);
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
    // Committed as approved before the approval is recorded, so a replay finds it not pending while
    // the record is in flight; nothing runs, and collect refuses, until the approval receipt is in.
    await this.store.put(`grant:${g.id}`, { ...current, status: "approved", approved_at: now });
    await this.log({ event: "approved", ...this.grantFacts(g) }, now);
    let receipt: Receipt;
    try {
      receipt = await this.record(current, "approval", { grant_hash: g.hash, approved_at: now, assertion: assertionOf(response) }, now);
    } catch {
      // A 4xx, so Ben's page says "Not approved" (page.ts outcomeView): nothing ran, which is known.
      await this.stop(id, "approval not recorded; nothing ran", now);
      throw new DeskError("approval_not_recorded", 409);
    }
    // The record awaited the network, so other requests may have run: re-read and re-check.
    const recorded = await this.grant(id);
    if (recorded.cbox_rev !== undefined && recorded.cbox_rev !== (await keyRev(this.store))) {
      await this.stop(id, "the c-box key was removed or replaced while the approval was recorded; nothing ran", now);
      throw new DeskError("cbox_key_changed", 409);
    }
    const approved: Grant = { ...recorded, recorded: { ...recorded.recorded!, approval: receipt.seq } };
    await this.store.put(`grant:${g.id}`, approved);
    if (g.job === "cbox.key.enroll") {
      try {
        await this.enrollCboxKey(approved, now);
      } catch (e) {
        await this.recordResult(id, false, now);
        throw e;
      }
      await this.recordResult(id, true, now);
      return this.grant(id);
    }
    if (!prf) return approved;
    // Committed as approved first, so a replay finds it not pending while the vault works.
    let result: unknown;
    try {
      if (!this.hooks.vault) throw new Error("vault not connected");
      // A vault on another version would misread the call: refused before anything is sent (card bb86abf0 R6).
      if ((await this.hooks.vault.approvalApi().catch(() => null))?.version !== APPROVAL_API_VERSION) throw new Error("wrong_shape");
      // The vault checks Ben's passkey answer itself, for exactly these grant fields, and runs each grant once.
      const grant = { id: g.id, job: g.job, params: g.params, requester: g.requester, expires_at: g.expires_at };
      result = await this.hooks.vault.run({ grant, assertion: assertionOf(response), prf });
      const ok = (result as { ok?: unknown } | null)?.ok === true;
      await this.log({ event: ok ? "job_done" : "job_failed", ...this.grantFacts(g), detail: logDetail(withoutSecret(result)) }, now);
    } catch (e) {
      const message = e instanceof Error && typeof e.message === "string" ? e.message : "";
      result = { error: (message || "unknown error").slice(0, 120), vault_stage: vaultStage(message) };
      await this.log({ event: "job_failed", ...this.grantFacts(g), detail: (message || "unknown error").slice(0, 120) }, now);
    }
    await this.recordResult(id, (result as { ok?: unknown } | null)?.ok === true, now);
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
      r = { ok: false, tokens: -1, unexpected: [], stretched: [], missing: [], cleanup: [], github: { ok: false, changes: [] }, error: (e as Error).message.slice(0, 120) };
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
  protected async verifyPasskey(response: AuthenticationResponseJSON, challenge: string, fail: (detail: string) => Promise<void>) {
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
  protected async commitCounter(id: string, newCounter: number): Promise<void> {
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
    if (first.card !== undefined) throw new DeskError("on_card", 409); // collected only through GET /card/<id>
    // A key is handed only to a signed collect from the address it is pinned to (Codex architecture r1 #2).
    if ((JOBS[first.job] as Job).signed) await this.requireSigned(source, requester, first.job, now);
    // Re-read after the signature's crypto: everything from here to the write is storage calls only,
    // so two collects cannot both see "approved" (Codex architecture r2).
    const g = await this.grant(id);
    if (g.status === "pending") throw new DeskError("not_approved", 403);
    if (g.status === "collected") throw new DeskError("already_collected", 409);
    if (g.status === "stopped") throw new DeskError("stopped", 409);
    // Nothing is handed over or run without a recorded approval (card 97a2e83d). A grant from before
    // recording never gets one; for any other, the approval is still being recorded: ask again.
    if (!g.recorded?.request) throw new DeskError("not_recorded", 409);
    if (now > (g.approved_at ?? 0) + COLLECT_WINDOW_MS) {
      await this.eraseStaleSecrets(now);
      throw new DeskError("collect_window_closed", 410);
    }
    if (g.recorded.approval === undefined) throw new DeskError("not_ready", 409);
    // A vault job is approved before the vault finishes; until its result is in, there is nothing to collect.
    if ((JOBS[g.job] as Job).vault && g.result === undefined) throw new DeskError("not_ready", 409);
    if ((JOBS[g.job] as Job).signed) {
      if (g.cbox_rev !== (await keyRev(this.store))) throw new DeskError("cbox_key_changed", 409);
    }
    // The stored copy loses the key's secret: it is handed over this once.
    const collected: Grant = { ...g, status: "collected", collected_at: now, result: withoutSecret(g.result) };
    await this.store.put(`grant:${g.id}`, collected);
    const job = JOBS[g.job] as Job;
    const result = job.vault ? g.result : await job.run!(g.params);
    await this.log({ event: "collected", ...this.grantFacts(g) }, now);
    if (!job.vault && g.recorded.result === undefined) await this.recordResult(g.id, true, now);
    return { grant: collected, result };
  }

  // Runs the route's signature check; a failure is logged and refused.
  protected async requireSigned(source: Source, requester: string, job: string, now: number): Promise<void> {
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
    await this.tellVaultKeyRev(now);
  }

  /** Ben removes the c-box key (lost or stolen box): every signed request is refused until a new one is enrolled. */
  async removeCboxKey(now: number): Promise<string> {
    const k = await currentKey(this.store);
    if (!k) throw new DeskError("no_cbox_key", 404);
    await this.store.put("cbox:key", null);
    await this.store.put("cbox:rev", (await keyRev(this.store)) + 1);
    await this.log({ event: "cbox_key_removed", detail: `c-box key ${k.fingerprint} removed by Ben` }, now);
    await this.tellVaultKeyRev(now);
    return k.fingerprint;
  }

  /**
   * Moves the vault's own copy of the key generation (vault setKeyRev), so an open card or run the vault holds is
   * refused at its next step even if the desk did not check (card 85818ab1 R2). Best effort: the key is already removed
   * before this runs, and it waits at most KEY_REV_WAIT_MS for the vault -- every cardRun also carries the desk's live generation, which the vault compares to the card's.
   */
  protected async tellVaultKeyRev(now: number): Promise<void> {
    if (!this.hooks.vault?.setKeyRev) return;
    const rev = await keyRev(this.store);
    try {
      // Bounded: a hanging vault never holds Ben's removal answer for long (Codex r2 N3).
      let timer: ReturnType<typeof setTimeout> | undefined;
      await Promise.race([this.hooks.vault.setKeyRev(rev), new Promise((_, no) => (timer = setTimeout(() => no(new Error("timeout")), KEY_REV_WAIT_MS)))]).finally(() => clearTimeout(timer));
    } catch {
      await this.log({ event: "vault_key_rev_unsent", detail: `the vault was not told c-box key generation ${rev}; cards still check it at every step` }, now);
    }
  }

  async cboxKey(): Promise<CboxKey | undefined> {
    return currentKey(this.store);
  }

  // A minted key's secret not collected within the collect window is erased (Codex minted r1 #5).
  // Runs at each new /request and at a late collect -- not on page views -- so with no further
  // requests it stays stored (the key itself still expires within 15 minutes).
  protected async eraseStaleSecrets(now: number): Promise<void> {
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

export async function saltFor(label: string): Promise<string> {
  return b64url(await sha256(enc.encode(label)));
}

export function hexToBytes(h: string): Uint8Array {
  return Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
}

export function challengeCarries(challenge: string, hash: string): boolean {
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
