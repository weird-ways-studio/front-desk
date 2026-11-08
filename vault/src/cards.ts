// The card book (card 85818ab1; studio-os docs/specifications/studio-architecture/spike-08313e62/REFINE-85818ab1.md
// v2.2). A card is 1-2 ordinary grants Ben approves with ONE Face ID tap over the card hash; the vault runs them in
// order, each only after the Observatory has signed a receipt for that entry's approval. This file is the vault's
// side: open (check everything, store the book), run one entry (claim, call, settle), stop, status, ack, and the
// alarm that closes any card left open.
//
// Where atomicity comes from (Traceable): every state change is ONE `transactionSync` on the SQLite-backed Durable
// Object's synchronous `storage.kv` (as runs.ts). The job itself runs between the claim and the settle, so Stop can
// land while it is out. Crypto (passkey, receipt signature, hashes) is awaited BEFORE each transaction, never inside.
//
// Where the timer lives (document-framework-magic): Cloudflare calls VaultBox.alarm() in vault/src/index.ts when the
// time set by `storage.setAlarm` arrives; nothing in a request calls it. It runs `CardBook.alarm()` below. The time
// is always armed BEFORE the transaction that needs it commits (U7), so a crash in between leaves an early alarm that
// finds nothing due, never a card with no alarm. Proven in real workerd by test/cards.workerd.test.ts.
import { VaultError, secretBytes } from "./seal.ts";
import { approvalCheck, canonical, grantHashOf, sha256, unb64, type PasskeyPin } from "./passkey.ts";
import { CARD_RUN_MS, RECORDER_KEY, REPO_JOB, cardHashOf, parseManifest, receiptSealed, repoIdRefusal, type Manifest, type Receipt } from "./cardcopy.ts";
import type { GhSnapshot } from "./github.ts";

/** The desk checks this (cardApi) before any card call; a vault on another version is refused before anything is sent. */
export const CARD_API_VERSION = 1;
/** The vault's own list of jobs a card may hold (same values as the recorder's). Empty = off switch: every card refused. */
export const CARD_JOBS: readonly string[] = Object.freeze(["test.echo", "cf.zone.read", "cf.dns.list", "cf.audit.read", "gh.repo.create"]);
/** Bumped by any change to a card job's behavior; a card opened under another version cannot start an entry. 2: gh.repo.create (card 77ec1e64, T16). */
export const JOBS_VERSION = 2;
/** Entries one card may hold until the F9 measurement raises it (APPROACH §13; Ben D2, 2026-11-08). */
export const CARD_CAP = 2;
/** An answer is held until the card closed this long ago (the desk's COLLECT_WINDOW_MS), then deleted (V3). */
export const ANSWER_HOLD_MS = 5 * 60_000;
/** A closed book is kept this long after its deadline, then pruned by the alarm. */
export const BOOK_KEEP_MS = 7 * 86_400_000;

export type EntryState = "waiting" | "dispatching" | "done" | "failed" | "unknown" | "not_run";
export interface CardGrant { id: string; job: string; params: Record<string, string>; requester: string; expires_at: number }
interface Assertion { passkey_id: string; authenticator_data: string; client_data_json: string; signature: string }
/** What the desk sends at Ben's tap. `key_rev`: the desk's c-box key generation the card was requested under. */
export interface CardOpen { manifest: Manifest; grants: CardGrant[]; assertion: Assertion; key_rev: number }
/** One entry's start. No job or params: the vault runs the grant it froze at open (U1). */
export interface CardRun { card: string; index: number; receipt: Receipt; approval_body: string; prf: string; key_rev: number }

interface Entry { grant: CardGrant; hash: string; state: EntryState; at?: number; late?: string }
interface Book {
  card: string;
  hash: string; // the card hash Ben signed
  tap: string; // sha256 of the signed message (authenticator data + client data): the same tap again is "already open", any other is card_seen
  entries: Entry[];
  deadline: number;
  jobs_version: number;
  key_rev: number;
  opened_at: number;
  stopped?: string; // why the card will start nothing more
  closed_at?: number; // written once, when no entry can change any more
}
/**
 * The durable record of a repo a card entry made (card 77ec1e64 Y1, Z2), key `gh.created:<grant>`. Written once, at
 * settle, and never erased with the answer, so a late result send still carries the id (`repoFacts`). `eligible`: the
 * entry settled `done` from `dispatching` with GitHub's created_at inside [card open, card deadline] and the id not yet
 * in the baseline -- only then may `repoRecorded` add it to the nightly list, once the recorder has receipted it.
 */
export interface GhCreated { grant: string; card: string; name: string; repo_id: string; created_at: string; eligible: boolean; recorded: boolean; why?: Ineligible }
/** Why a made repo is not eligible (Codex build r2 N1): the words Ben reads, and whether the nightly alarm names it, differ. */
export type Ineligible = "listed" | "window" | "repeat" | "bad_id" | "late";
export interface CardView {
  card: string;
  deadline: number;
  stopped?: string;
  closed_at?: number;
  entries: { grant: string; job: string; state: EntryState; at?: number; late?: string }[];
  answers: Record<number, unknown>; // only while held (closed_at + ANSWER_HOLD_MS); `held` says if they still are
  held: boolean;
}

/** Durable Object storage as the card book uses it; `DurableObjectStorage` fits, and tests pass a fake. */
export interface CardStore {
  transactionSync<T>(closure: () => T): T;
  kv: {
    get<T = unknown>(key: string): T | undefined;
    put<T>(key: string, value: T): void;
    delete(key: string): boolean;
    list<T = unknown>(options?: { prefix?: string }): Iterable<[string, T]>;
  };
  getAlarm(): Promise<number | null>;
  setAlarm(at: number): Promise<void>;
  deleteAlarm(): Promise<void>;
}

/** Runs one read job with the master key Ben's passkey secret opens (VaultLogic.runCardEntry). */
export type RunEntry = (job: string, params: Record<string, string>, prf: string) => Promise<unknown>;

export interface CardOptions { now?: () => number; pin?: PasskeyPin; recorderKey?: string; jobs?: readonly string[]; jobsVersion?: number }

const book = (id: string) => `card:${id}`;
const created = (grant: string) => `gh.created:${grant}`;
const answerKey = (id: string, i: number) => `cardans:${id}:${i}`;
const DUE = "cards_due";
const isText = (v: unknown): v is string => typeof v === "string";
const shapeOf = (v: unknown) => (v && typeof v === "object" && !Array.isArray(v) ? Object.keys(v).sort().join(",") : "");
const terminal = (s: EntryState) => s !== "waiting" && s !== "dispatching";

export class CardBook {
  private store: CardStore;
  private runEntry: RunEntry;
  private now: () => number;
  private pin: PasskeyPin | undefined;
  private recorderKey: string;
  private jobs: readonly string[];
  private jobsVersion: number;
  constructor(store: CardStore, runEntry: RunEntry, pin: PasskeyPin | undefined, o: CardOptions = {}) {
    this.store = store;
    this.runEntry = runEntry;
    this.pin = pin;
    this.now = o.now ?? Date.now;
    this.recorderKey = o.recorderKey ?? RECORDER_KEY;
    this.jobs = o.jobs ?? CARD_JOBS;
    this.jobsVersion = o.jobsVersion ?? JOBS_VERSION;
  }

  /**
   * Ben's tap: checks (a)-(g) of Outcome 2, then stores the book in one transaction. Every refusal is raised before
   * that transaction writes, so this call started nothing. The same tap sent again returns the book already open (U5).
   */
  async open(req: unknown, ...rest: unknown[]): Promise<CardView> {
    const r = req as CardOpen;
    if (rest.length || shapeOf(req) !== "assertion,grants,key_rev,manifest" || !Number.isSafeInteger(r.key_rev) || r.key_rev < 0) throw new VaultError("wrong_shape");
    if (!this.pin) throw new VaultError("no_pin");
    if (!this.jobs.length) throw new VaultError("cards_off");
    const m = parseManifest(r.manifest);
    if (typeof m === "string" || !Array.isArray(r.grants) || r.grants.length !== m.entries.length) throw new VaultError("bad_card");
    if (m.entries.length > CARD_CAP) throw new VaultError("too_many_entries");
    if (m.jobs_version !== this.jobsVersion) throw new VaultError("version_changed");
    const entries: Entry[] = [];
    for (const [i, g] of r.grants.entries()) {
      if (shapeOf(g) !== "expires_at,id,job,params,requester" || !isText(g.id) || !isText(g.job)) throw new VaultError("bad_card");
      const hash = await grantHashOf({ v: 1, grant: g.id, stage: "request", job: g.job, params: g.params, requester: g.requester, expires_at: g.expires_at });
      // Each grant, recomputed here from its own fields, is the manifest's entry at its own place (T1).
      if (!hash || hash !== m.entries[i] || g.requester !== m.requester || m.deadline > g.expires_at + CARD_RUN_MS) throw new VaultError("bad_card");
      if (!this.jobs.includes(g.job)) throw new VaultError("job_not_on_cards");
      entries.push({ grant: { id: g.id, job: g.job, params: { ...g.params }, requester: g.requester, expires_at: g.expires_at }, hash, state: "waiting" });
    }
    if (new Set(entries.map((e) => e.grant.id)).size !== entries.length) throw new VaultError("bad_card");
    const hash = await cardHashOf(m);
    if ((await approvalCheck(this.pin)({ v: 1, grant: m.card, stage: "approval", job: "card", assertion: r.assertion }, hash)) !== undefined) throw new VaultError("bad_assertion");
    // Keyed on what the passkey signed, never on the signature (Release Checklist 6.2: a signature has other encodings).
    const tap = await sha256(canonical([r.assertion.authenticator_data, r.assertion.client_data_json]));
    // Armed before the book exists (U7): a crash after this leaves an alarm that finds nothing due.
    await this.armBy(m.deadline + 1);
    return this.store.transactionSync(() => {
      const now = this.now();
      const kv = this.store.kv;
      const seen = kv.get<Book>(book(m.card));
      if (seen) {
        if (seen.hash === hash && seen.tap === tap) return this.view(seen, now);
        throw new VaultError("card_seen");
      }
      if (now > m.deadline) throw new VaultError("deadline_passed");
      // (g) Ben's tap lands inside every grant's approve window; so every grant that could still open a card is
      // still held in `used` (kept until expires_at + 5 min), and the check below has no gap.
      if (entries.some((e) => now > e.grant.expires_at)) throw new VaultError("too_late");
      const used = kv.get<Map<string, number>>("used");
      for (const e of entries) {
        if (used?.has(e.grant.id)) throw new VaultError("grant_used");
        if (kv.get(`cardgrant:${e.grant.id}`) !== undefined) throw new VaultError("grant_on_card");
      }
      const b: Book = { card: m.card, hash, tap, entries, deadline: m.deadline, jobs_version: m.jobs_version, key_rev: r.key_rev, opened_at: now };
      kv.put(book(m.card), b);
      for (const e of entries) kv.put(`cardgrant:${e.grant.id}`, m.card);
      kv.put(DUE, { ...(kv.get<Record<string, number>>(DUE) ?? {}), [m.card]: m.deadline + 1 });
      return this.view(b, now);
    });
  }

  /**
   * One entry: checks the recorder's signed receipt for its approval (crypto, before), claims it in one transaction,
   * runs it, then settles in one transaction. A claim of an entry that already left `waiting` runs nothing and
   * returns the current state (U5 class 2).
   */
  async run(req: unknown, ...rest: unknown[]): Promise<{ state: EntryState; answer?: unknown; card: CardView }> {
    const r = req as CardRun;
    if (rest.length || shapeOf(req) !== "approval_body,card,index,key_rev,prf,receipt" || !isText(r.card) || !Number.isSafeInteger(r.index) || !isText(r.approval_body) || !Number.isSafeInteger(r.key_rev)) throw new VaultError("wrong_shape");
    try {
      secretBytes(r.prf);
    } catch {
      throw new VaultError("wrong_shape");
    }
    const first = this.store.kv.get<Book>(book(r.card));
    if (!first) throw new VaultError("unknown_card");
    const entry = first.entries[r.index];
    if (!entry) throw new VaultError("bad_index");
    await this.checkApproval(r, first, entry);
    // The claim: everything re-read inside one transaction, with the vault's own clock (T16).
    const claimed = this.store.transactionSync((): { already: CardView } | { grant: CardGrant } => {
      const now = this.now();
      const b = this.store.kv.get<Book>(book(r.card))!;
      const e = b.entries[r.index];
      if (e.state !== "waiting") return { already: this.view(b, now) };
      if (b.stopped || b.closed_at !== undefined) throw new VaultError("card_stopped");
      if (now > b.deadline) throw new VaultError("deadline_passed"); // even with a valid receipt (T3, carried T2)
      if (!this.jobs.includes(e.grant.job)) throw new VaultError("cards_off"); // the switch stops open cards too (U2)
      if (b.entries.slice(0, r.index).some((x) => x.state !== "done")) throw new VaultError("out_of_order");
      if (b.jobs_version !== this.jobsVersion) throw new VaultError("version_changed");
      const vaultRev = this.store.kv.get<number>("cbox_rev") ?? 0;
      if (r.key_rev !== b.key_rev || vaultRev > b.key_rev) throw new VaultError("key_changed");
      e.state = "dispatching";
      e.at = now;
      this.store.kv.put(book(r.card), b);
      return { grant: e.grant };
    });
    if ("already" in claimed) return { state: claimed.already.entries[r.index].state, card: claimed.already };
    const { state, answer } = await this.call(claimed.grant, r.prf);
    return this.settle(r.card, r.index, state, answer);
  }

  /** The receipt is the recorder's, for this entry's approval, over exactly the body handed over, which is a card/v1 approval of this card. */
  private async checkApproval(r: CardRun, b: Book, e: Entry): Promise<void> {
    const rc = r.receipt as Receipt | null;
    if (!(await this.receiptOk(rc)) || rc!.stage !== "approval" || rc!.grant !== e.grant.id || (await sha256(r.approval_body)) !== rc!.sha256) throw new VaultError("bad_receipt");
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(r.approval_body);
    } catch {
      throw new VaultError("bad_approval");
    }
    const m = parseManifest(body?.manifest);
    if (body?.grant !== e.grant.id || body.stage !== "approval" || body.approval_kind !== "card/v1" || body.grant_hash !== e.hash || typeof m === "string" || (await cardHashOf(m)) !== b.hash) throw new VaultError("bad_approval");
  }

  /** True only for a receipt of the exact shape, signed by the pinned recorder key. */
  private async receiptOk(rc: Receipt | null): Promise<boolean> {
    if (shapeOf(rc) !== "grant,key,recorded_at,seq,sha256,sig,stage,v" || rc!.v !== 1 || !Number.isSafeInteger(rc!.seq) || ![rc!.key, rc!.recorded_at, rc!.sha256, rc!.sig, rc!.grant, rc!.stage].every(isText)) return false;
    try {
      const key = await crypto.subtle.importKey("raw", unb64(this.recorderKey), "Ed25519", false, ["verify"]);
      return await crypto.subtle.verify("Ed25519", key, unb64(rc!.sig!), receiptSealed(rc!));
    } catch {
      return false;
    }
  }

  /** The job itself. test.echo touches nothing; the reads use today's tap path. A definite error is `failed`; anything unreadable is `unknown`. */
  private async call(g: CardGrant, prf: string): Promise<{ state: EntryState; answer: unknown }> {
    if (g.job === "test.echo") return /^[a-z]{1,20}$/.test(g.params.word ?? "") ? { state: "done", answer: { ok: true, data: { echoed: g.params.word } } } : { state: "failed", answer: { ok: false, error: "bad_params" } };
    try {
      const answer = await this.runEntry(g.job, g.params, prf);
      const ok = (answer as { ok?: unknown } | null)?.ok;
      // gh.repo.create answers ok: null when the repo may exist (ghrepo.ts): unknown, with its facts kept (X4).
      if (ok === null && g.job === REPO_JOB) return { state: "unknown", answer };
      return ok === true ? { state: "done", answer } : ok === false ? { state: "failed", answer } : { state: "unknown", answer: { error: "unreadable answer" } };
    } catch (e) {
      return e instanceof VaultError ? { state: "failed", answer: { ok: false, error: e.message } } : { state: "unknown", answer: { error: "no answer from the job" } };
    }
  }

  /** After the job, one transaction. If the alarm already closed the entry as `unknown`, the outcome is kept as `late` and nothing else moves. */
  private async settle(card: string, index: number, state: EntryState, answer: unknown) {
    await this.armBy(this.now() + ANSWER_HOLD_MS); // the answer's expiry, armed before it is stored (V3)
    const out = this.store.transactionSync(() => {
      const now = this.now();
      const kv = this.store.kv;
      const b = kv.get<Book>(book(card))!;
      const e = b.entries[index];
      const repo = e.grant.job === REPO_JOB ? this.repoMade(b, e, state, answer) : undefined;
      if (e.state !== "dispatching") {
        e.late = state;
        kv.put(book(card), b);
        if (repo) kv.put(created(e.grant.id), { ...repo, eligible: false, why: repo.why ?? "late" }); // made after the alarm closed it: never eligible (Z2)
        return { state: e.state, card: this.view(b, now) };
      }
      if (repo) {
        kv.put(created(e.grant.id), repo);
        if (!repo.eligible) {
          // A repo the nightly list will not accept: the card ends, the checker alerts (X1). The stored answer says so,
          // so no sentence built from it can say "Done" (Codex build r1 #1).
          state = "unknown";
          answer = { ...(answer as object), ok: null, eligible: false, why: repo.why };
        }
      }
      e.state = state;
      e.at = now;
      kv.put(answerKey(card, index), answer);
      if (state !== "done") b.stopped ??= `entry ${index + 1} ${state}`;
      // A failure ends the card; so does the last entry, or this one finishing after Stop already ended the rest.
      if (state !== "done" || b.entries.every((x) => terminal(x.state))) this.close(b, now);
      kv.put(book(card), b);
      this.due(b);
      return { state, card: this.view(b, now) };
    });
    await this.rearm();
    return out;
  }

  /**
   * Inside settle's transaction: the record of a repo GitHub reported as made (`done` with an id and a time), or
   * undefined. Eligible (the late path in settle overrides it to false, so only an entry settled from `dispatching`) only if created inside [open, deadline] by GitHub's clock, the
   * grant has no record yet, and the id is not already in the baseline (X1, Z2, T15).
   */
  private repoMade(b: Book, e: Entry, state: EntryState, answer: unknown): GhCreated | undefined {
    const a = answer as { repo_id?: unknown; created_at?: unknown; name?: unknown } | null;
    if (state !== "done" || typeof a?.repo_id !== "string" || typeof a.created_at !== "string" || a.name !== e.grant.params.name) return undefined;
    const at = Date.parse(a.created_at);
    const base = this.store.kv.get<GhSnapshot | null>("gh.baseline");
    const line = `${a.name}:${a.repo_id}`;
    // Settled from `dispatching` is decided by the caller: the late path (alarm already closed it) stores why: "late".
    // GitHub's created_at has whole seconds: the window starts at the whole second the card opened (Codex build r1 #4).
    const inWindow = Number.isFinite(at) && at >= Math.floor(b.opened_at / 1000) * 1000 && at <= b.deadline;
    const why: Ineligible | undefined =
      (base?.repo_ids ?? []).includes(line) ? "listed"
      : !inWindow ? "window"
      : this.store.kv.get(created(e.grant.id)) !== undefined ? "repeat"
      : repoIdRefusal({ job: REPO_JOB, outcome: "done", repo_id: a.repo_id }) !== undefined ? "bad_id"
      : undefined;
    return { grant: e.grant.id, card: b.card, name: a.name, repo_id: a.repo_id, created_at: a.created_at, eligible: why === undefined, recorded: false, ...(why ? { why } : {}) };
  }

  /** The durable repo record for a grant, so the desk can build the frozen result body after the answer is erased (Y1). */
  repoFacts(grant: unknown): GhCreated | null {
    if (!isText(grant)) throw new VaultError("wrong_shape");
    return this.store.kv.get<GhCreated>(created(grant)) ?? null;
  }

  /**
   * The recorder has receipted a done gh.repo.create result: add the repo to the nightly list, once (Y1, Z1-Z3). The
   * receipt must be the recorder's, for this grant's `result`, over exactly `body`; the body must be that grant's done
   * gh.repo.create result naming the same repo id as the vault's own record, which must be eligible. No time limit on
   * when it arrives (Z2). A second call answers "already recorded" and changes nothing.
   */
  async repoRecorded(grant: unknown, body: unknown, receipt: unknown, ...rest: unknown[]): Promise<{ recorded: "now" | "already" }> {
    if (rest.length || !isText(grant) || !isText(body)) throw new VaultError("wrong_shape");
    const rc = receipt as Receipt | null;
    if (!(await this.receiptOk(rc)) || rc!.stage !== "result" || rc!.grant !== grant || (await sha256(body)) !== rc!.sha256) throw new VaultError("bad_receipt");
    let r: Record<string, unknown>;
    try {
      r = JSON.parse(body);
    } catch {
      throw new VaultError("bad_result");
    }
    const first = this.store.kv.get<GhCreated>(created(grant));
    if (!first) throw new VaultError("no_repo_record");
    if (r?.grant !== grant || r.stage !== "result" || r.job !== REPO_JOB || r.outcome !== "done" || repoIdRefusal(r) !== undefined || r.repo_id !== first.repo_id) throw new VaultError("bad_result");
    return this.store.transactionSync(() => {
      const kv = this.store.kv;
      const c = kv.get<GhCreated>(created(grant))!;
      if (c.recorded) return { recorded: "already" as const };
      if (!c.eligible) throw new VaultError("repo_not_eligible");
      const base = kv.get<GhSnapshot | null>("gh.baseline");
      if (!base) throw new VaultError("no_baseline");
      // Exactly these two lines, nothing else (T11); a line already there (Ben accepted it meanwhile) is not doubled.
      const add = (list: string[] | undefined, line: string) => (list ?? []).includes(line) ? [...(list ?? [])] : [...(list ?? []), line].sort();
      kv.put("gh.baseline", { ...base, repos: add(base.repos, `${c.name}:private`), repo_ids: add(base.repo_ids, `${c.name}:${c.repo_id}`) });
      kv.put(created(grant), { ...c, recorded: true });
      return { recorded: "now" as const };
    });
  }

  /** Ben's Stop: nothing more starts. An entry already out keeps running to its answer (T5). Idempotent. */
  async stop(card: unknown): Promise<CardView> {
    if (!isText(card)) throw new VaultError("wrong_shape");
    await this.armBy(this.now() + ANSWER_HOLD_MS);
    const v = this.store.transactionSync(() => {
      const now = this.now();
      const b = this.store.kv.get<Book>(book(card));
      if (!b) throw new VaultError("unknown_card");
      if (!b.stopped && b.closed_at === undefined) {
        b.stopped = "stopped by Ben";
        this.close(b, now);
        this.store.kv.put(book(card), b);
        this.due(b);
      }
      return this.view(b, now);
    });
    await this.rearm();
    return v;
  }

  /** The book, and each answer while held. Never the passkey secret. */
  status(card: unknown): CardView {
    if (!isText(card)) throw new VaultError("wrong_shape");
    const b = this.store.kv.get<Book>(book(card));
    if (!b) throw new VaultError("unknown_card");
    return this.view(b, this.now());
  }

  /** The desk has stored entry `index`'s answer: the vault's copy is deleted (V2). */
  ack(card: unknown, index: unknown): boolean {
    if (!isText(card) || !Number.isSafeInteger(index)) throw new VaultError("wrong_shape");
    return this.store.transactionSync(() => {
      const e = this.store.kv.get<Book>(book(card))?.entries[index as number];
      return e && terminal(e.state) ? this.store.kv.delete(answerKey(card, index as number)) : false;
    });
  }

  /**
   * The platform timer (called by VaultBox.alarm, vault/src/index.ts). Does all due work in one transaction:
   * closes open cards past their deadline (`dispatching` -> unknown, `waiting` -> not_run), deletes answers past
   * their hold, prunes books 7 days past their deadline; then re-arms to the earliest remaining due time.
   */
  async alarm(): Promise<void> {
    this.store.transactionSync(() => {
      const now = this.now();
      const kv = this.store.kv;
      const due = { ...(kv.get<Record<string, number>>(DUE) ?? {}) };
      for (const [id, at] of Object.entries(due)) {
        if (at > now) continue;
        const b = kv.get<Book>(book(id));
        if (!b) {
          delete due[id];
          continue;
        }
        if (b.closed_at === undefined && now > b.deadline) {
          for (const e of b.entries) if (!terminal(e.state)) e.state = e.state === "dispatching" ? "unknown" : "not_run";
          b.stopped ??= "deadline passed";
          this.close(b, now);
          kv.put(book(id), b);
        }
        if (b.closed_at !== undefined && now > b.closed_at + ANSWER_HOLD_MS) for (const [k] of [...kv.list({ prefix: `cardans:${id}:` })]) kv.delete(k);
        if (b.closed_at !== undefined && now > b.deadline + BOOK_KEEP_MS) {
          kv.delete(book(id));
          for (const e of b.entries) kv.delete(`cardgrant:${e.grant.id}`);
          delete due[id];
          continue;
        }
        due[id] = this.dueAt(b);
      }
      kv.put(DUE, due);
    });
    await this.rearm();
  }

  // Ends the card once: entries still `waiting` will never run. `closed_at` is written only if absent (V3).
  private close(b: Book, now: number) {
    for (const e of b.entries) if (e.state === "waiting") e.state = "not_run";
    // An entry still out (Stop during its call) closes the card when it settles, or the alarm does.
    if (!b.entries.some((e) => e.state === "dispatching")) b.closed_at ??= now;
  }

  // The card's next due work: its deadline while open; then its answers' expiry while any is held; then pruning.
  private dueAt(b: Book): number {
    if (b.closed_at === undefined) return b.deadline + 1;
    const held = [...this.store.kv.list({ prefix: `cardans:${b.card}:` })].length > 0;
    return held && this.now() <= b.closed_at + ANSWER_HOLD_MS ? b.closed_at + ANSWER_HOLD_MS + 1 : b.deadline + BOOK_KEEP_MS + 1;
  }
  private due(b: Book) {
    const kv = this.store.kv;
    kv.put(DUE, { ...(kv.get<Record<string, number>>(DUE) ?? {}), [b.card]: this.dueAt(b) });
  }

  // The alarm only ever moves earlier here; the handler (rearm) sets it to the true earliest.
  private async armBy(at: number) {
    const cur = await this.store.getAlarm();
    if (cur === null || cur > at) await this.store.setAlarm(at);
  }
  private async rearm() {
    const times = Object.values(this.store.kv.get<Record<string, number>>(DUE) ?? {});
    if (times.length) await this.store.setAlarm(Math.min(...times));
    else await this.store.deleteAlarm();
  }

  private view(b: Book, now: number): CardView {
    const held = b.closed_at === undefined || now <= b.closed_at + ANSWER_HOLD_MS;
    const answers: Record<number, unknown> = {};
    if (held) for (const [i] of b.entries.entries()) {
      const a = this.store.kv.get(answerKey(b.card, i));
      if (a !== undefined) answers[i] = a;
    }
    return {
      card: b.card, deadline: b.deadline, stopped: b.stopped, closed_at: b.closed_at, held, answers,
      entries: b.entries.map((e) => ({ grant: e.grant.id, job: e.grant.job, state: e.state, at: e.at, late: e.late })),
    };
  }
}
