// Test helper (card 85818ab1): builds cards the way the desk will -- grants, the manifest, Ben's passkey answer over
// the card hash -- and the recorder's signed receipts for each entry's approval, with a test recorder key. Also a
// CardStore whose transactionSync really rolls back, and a hand-driven alarm clock.
import { b64url, grantHash } from "../src/desk.ts";
import { canonical, type PasskeyPin } from "../vault/src/passkey.ts";
import { cardHashOf, receiptSealed, type Manifest, type Receipt } from "../vault/src/cardcopy.ts";
import { CardBook, JOBS_VERSION, type CardGrant, type CardOptions, type CardStore, type RunEntry } from "../vault/src/cards.ts";
import { TEST_KEY, TEST_ORIGIN, TEST_PIN, TEST_RP } from "./vaultsign.ts";
import type { SoftKey } from "./softkey.ts";

const b64 = (b: ArrayBuffer | Uint8Array) => Buffer.from(new Uint8Array(b)).toString("base64");
const hex = (b: ArrayBuffer) => Buffer.from(new Uint8Array(b)).toString("hex");
const sha = async (t: string) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t)));

/** A recorder signing key for tests; its public key is passed to CardBook as `recorderKey`. */
export class TestRecorder {
  seq = 0;
  private pair: CryptoKeyPair;
  readonly pub: string;
  private constructor(pair: CryptoKeyPair, pub: string) {
    this.pair = pair;
    this.pub = pub;
  }
  static async create() {
    const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
    return new TestRecorder(pair, b64((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer));
  }
  /** Signs a receipt over `body` as the recorder answers it. `over` lets a test sign other fields than it reports. */
  async receipt(grant: string, stage: string, body: string, over: Partial<Receipt> = {}): Promise<Receipt> {
    const r: Receipt = { v: 1, seq: ++this.seq, key: `records/v1/${String(this.seq).padStart(12, "0")}.${grant}.${stage}.json`, grant, stage, sha256: await sha(body), recorded_at: new Date(1_800_000_000_000).toISOString(), ...over };
    return { ...r, sig: b64(await crypto.subtle.sign("Ed25519", this.pair.privateKey, receiptSealed(r))) };
  }
}

export interface TestCard { manifest: Manifest; grants: CardGrant[]; hashes: string[]; cardHash: string; assertion: { passkey_id: string; authenticator_data: string; client_data_json: string; signature: string } }

let n = 0;
/** A card of `jobs` (with params), requested at `t`, signed by `key` over the card hash (or over `signHash`). */
export async function makeCard(t: number, jobs: [string, Record<string, string>][], o: { key?: SoftKey; requester?: string; deadline?: number; jobsVersion?: number; signHash?: string; card?: string } = {}): Promise<TestCard> {
  const requester = o.requester ?? "c-box agent";
  const grants: CardGrant[] = jobs.map(([job, params]) => ({ id: `g-card-${++n}-xxxx`, job, params, requester, expires_at: t + 10 * 60_000 }));
  const hashes = await Promise.all(grants.map((g) => grantHash(g as Parameters<typeof grantHash>[0])));
  const manifest: Manifest = { kind: "card/v1", card: o.card ?? `c-card-${++n}-xxxx`, requester, entries: hashes, deadline: o.deadline ?? t + 25 * 60_000, jobs_version: o.jobsVersion ?? JOBS_VERSION };
  const cardHash = await cardHashOf(manifest);
  const signFor = o.signHash ?? cardHash;
  const challenge = b64url(new Uint8Array([...crypto.getRandomValues(new Uint8Array(16)), ...signFor.match(/../g)!.map((h) => parseInt(h, 16))]));
  const r = await (o.key ?? TEST_KEY).assert(challenge, TEST_RP, TEST_ORIGIN, { userVerified: true });
  return { manifest, grants, hashes, cardHash, assertion: { passkey_id: r.id, authenticator_data: r.response.authenticatorData, client_data_json: r.response.clientDataJSON, signature: r.response.signature } };
}

/** The approval record body the desk sends the recorder for entry `i` (exact bytes; the receipt hashes them). */
export function approvalBody(c: TestCard, i: number, over: Record<string, unknown> = {}): string {
  return JSON.stringify({ v: 1, grant: c.grants[i].id, stage: "approval", job: c.grants[i].job, request: "r".repeat(64), grant_hash: c.hashes[i], approved_at: 1, assertion: c.assertion, approval_kind: "card/v1", manifest: c.manifest, ...over });
}

/** A Durable Object storage stand-in: kv with a real rollback on throw, and one alarm time. */
export class MemoryCardStore implements CardStore {
  data = new Map<string, unknown>();
  alarmAt: number | null = null;
  faultOn = ""; // the next put whose key starts with this throws (an injected storage failure)
  transactionSync<T>(fn: () => T): T {
    const before = new Map([...this.data].map(([k, v]) => [k, structuredClone(v)]));
    try {
      return fn();
    } catch (e) {
      this.data = before;
      throw e;
    }
  }
  kv = {
    get: <T>(k: string) => structuredClone(this.data.get(k)) as T | undefined,
    put: <T>(k: string, v: T) => {
      if (this.faultOn && k.startsWith(this.faultOn)) {
        this.faultOn = "";
        throw new Error("injected storage fault");
      }
      this.data.set(k, structuredClone(v));
    },
    delete: (k: string) => this.data.delete(k),
    list: <T>(o: { prefix?: string } = {}) => [...this.data].filter(([k]) => k.startsWith(o.prefix ?? "")).sort().map(([k, v]) => [k, structuredClone(v)] as [string, T]),
  };
  // VaultLogic's async view of the same storage (vault.run, admit's `used`).
  get = async <T>(k: string) => this.kv.get<T>(k);
  put = async <T>(k: string, v: T) => this.kv.put(k, v);
  async getAlarm() {
    return this.alarmAt;
  }
  async setAlarm(at: number) {
    this.alarmAt = at;
  }
  async deleteAlarm() {
    this.alarmAt = null;
  }
  /** Everything stored, as text, to scan for a value that must never be kept. */
  dump() {
    return JSON.stringify([...this.data].map(([k, v]) => [k, v instanceof Map ? [...v] : v]));
  }
}

/** A card book on a fresh store with the test passkey and a test recorder; `clock.now` moves time. */
export async function cardBook(o: { runEntry?: RunEntry; pin?: PasskeyPin; opts?: CardOptions; t?: number } = {}) {
  const store = new MemoryCardStore();
  const rec = await TestRecorder.create();
  const clock = { now: o.t ?? 1_800_000_000_000 };
  const calls: string[] = [];
  const runEntry: RunEntry = o.runEntry ?? (async (job, params) => (calls.push(job), { ok: true, job, data: { read: params.zone ?? "audit" } }));
  const book = new CardBook(store, runEntry, o.pin ?? TEST_PIN, { now: () => clock.now, recorderKey: rec.pub, ...o.opts });
  return { store, rec, clock, book, calls };
}

/** The cardRun call the desk makes for entry `i`, with a valid signed receipt unless overridden. */
export async function runReq(c: TestCard, i: number, rec: TestRecorder, o: { body?: string; receipt?: Receipt; prf?: string; key_rev?: number } = {}) {
  const body = o.body ?? approvalBody(c, i);
  return { card: c.manifest.card, index: i, receipt: o.receipt ?? (await rec.receipt(c.grants[i].id, "approval", body)), approval_body: body, prf: o.prf ?? PRF, key_rev: o.key_rev ?? 1 };
}
export const openReq = (c: TestCard, key_rev = 1) => ({ manifest: c.manifest, grants: c.grants, assertion: c.assertion, key_rev });
export const PRF = Buffer.from(new Uint8Array(32).fill(9)).toString("base64url");
export { canonical };
