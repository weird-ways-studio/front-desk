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
import { JOBS, type JobName } from "./jobs.ts";

export const APPROVE_WINDOW_MS = 10 * 60_000; // ask -> approve
export const COLLECT_WINDOW_MS = 5 * 60_000; // approve -> collect
export const CHALLENGE_TTL_MS = 5 * 60_000;
export const ROUTE_REFUSALS_PER_DAY = 20;

// The subset of Durable Object storage the desk uses; MemoryStore implements it for tests.
export interface Store {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  list<T>(options: { prefix: string }): Promise<Map<string, T>>;
}

export type GrantStatus = "pending" | "approved" | "collected";

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
}

export interface Passkey {
  id: string;
  publicKey: number[];
  counter: number;
  enrolled_at: number;
}

interface Challenge {
  purpose: "approve" | "enroll";
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

// Test seam: lets a test pause an approval between verification and commit.
export interface DeskHooks {
  afterVerify?: (grantId: string) => Promise<void>;
}

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

  async request(input: unknown, requester: string, now: number): Promise<Grant> {
    const body = (input ?? {}) as { job?: unknown; params?: unknown; reason?: unknown };
    if (typeof body.job !== "string" || !Object.hasOwn(JOBS, body.job)) {
      await this.log({ event: "refused", requester, detail: `job not offered: ${String(body.job).slice(0, 60)}` }, now);
      throw new DeskError("job_not_offered", 400);
    }
    const job = body.job as JobName;
    const params = JOBS[job].validate(body.params);
    if (!params) throw new DeskError("bad_params", 400);
    if (typeof body.reason !== "string" || !body.reason.trim() || body.reason.length > 200) {
      throw new DeskError("bad_reason", 400);
    }
    const base = { id: crypto.randomUUID(), job, params, requester, expires_at: now + APPROVE_WINDOW_MS };
    const g: Grant = { ...base, reason: body.reason.trim(), created_at: now, hash: await grantHash(base), status: "pending" };
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
    return options;
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
    const key = await this.store.get<Passkey>(`passkey:${response.id}`);
    if (!key) {
      await this.log({ event: "refused", ...this.grantFacts(g), detail: "unknown passkey" }, now);
      throw new DeskError("unknown_passkey", 403);
    }
    let verified = false;
    let newCounter = key.counter;
    try {
      const result = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: this.site.origin,
        expectedRPID: this.site.rpID,
        credential: { id: key.id, publicKey: new Uint8Array(key.publicKey), counter: key.counter },
        requireUserVerification: true,
      });
      verified = result.verified;
      newCounter = result.authenticationInfo.newCounter;
    } catch (e) {
      await this.log({ event: "refused", ...this.grantFacts(g), detail: `passkey check failed: ${(e as Error).message.slice(0, 120)}` }, now);
      throw new DeskError("passkey_check_failed", 403);
    }
    if (!verified) throw new DeskError("passkey_check_failed", 403);
    await this.hooks.afterVerify?.(g.id);
    // Verification awaited crypto, so another request may have run meanwhile.
    // Re-read and commit with storage calls only, which the Durable Object does not interleave.
    const current = await this.pending(id, now);
    const currentKey = await this.store.get<Passkey>(`passkey:${key.id}`);
    // A counter that does not move forward means a replayed or cloned passkey (unless both stay 0,
    // which synced passkeys such as 1Password's report).
    if (!currentKey) throw new DeskError("unknown_passkey", 403);
    const inUse = newCounter > 0 || currentKey.counter > 0;
    if (inUse && newCounter <= currentKey.counter) throw new DeskError("stale_counter", 409);
    await this.store.put<Passkey>(`passkey:${key.id}`, { ...currentKey, counter: newCounter });
    const approved: Grant = { ...current, status: "approved", approved_at: now };
    await this.store.put(`grant:${g.id}`, approved);
    await this.log({ event: "approved", ...this.grantFacts(g) }, now);
    return approved;
  }

  // Marked collected before the job runs: two collects, or a crash mid-job, never run it twice.
  async collect(id: string, requester: string, now: number): Promise<{ grant: Grant; result: unknown }> {
    const g = await this.grant(id);
    if (g.requester !== requester) throw new DeskError("not_your_grant", 403);
    if (g.status === "pending") throw new DeskError("not_approved", 403);
    if (g.status === "collected") throw new DeskError("already_collected", 409);
    if (now > (g.approved_at ?? 0) + COLLECT_WINDOW_MS) throw new DeskError("collect_window_closed", 410);
    const collected: Grant = { ...g, status: "collected", collected_at: now };
    await this.store.put(`grant:${g.id}`, collected);
    const result = await JOBS[g.job].run(g.params);
    await this.log({ event: "collected", ...this.grantFacts(g) }, now);
    return { grant: collected, result };
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
  async list<T>({ prefix }: { prefix: string }) {
    const keys = [...this.data.keys()].filter((k) => k.startsWith(prefix)).sort();
    return new Map(keys.map((k) => [k, structuredClone(this.data.get(k)) as T]));
  }
}
