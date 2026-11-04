// Runs (card ae6147e4, build 4a-2a; design studio-os docs/specifications/trust-but-verify/REFINE-phase4a2.md).
// A run is one Face ID tap that lets agents do read jobs, within a frozen list, until a deadline or a budget
// runs out. This file is the vault's run book: the run record, the one admission step, the release fence,
// stop and finish. Nothing here opens a run (4a-3 does, at Ben's tap) and no desk route calls it yet (4a-2b).
//
// Where atomicity really comes from (Traceable): each admit / release / stop is ONE `transactionSync` on the
// SQLite-backed Durable Object's synchronous storage (`storage.kv`). A synchronous closure cannot be
// interleaved by another request, and a throw inside it rolls back every write. The provider call happens
// between two transactions, so a stop can land while a call is out; release then refuses the answer.
// Proven in the real runtime by test/runs.workerd.test.ts.

import { Cloudflare, type Fetch } from "./cloudflare.ts";
import { VaultError } from "./seal.ts";
import { READ_JOBS, auditWindow, readWith } from "./vault.ts";

/** The desk checks this before it calls any run method; a vault without it is `vault_not_ready` (D9). */
export const RUN_API_VERSION = 1;
/** Jobs a run may ever hold, reviewed here; a run's frozen list must sit inside it (D9). Reads only. */
export const RUN_ELIGIBLE: readonly string[] = READ_JOBS;
export const RUN_BUDGET_MAX = 50;
/** One provider call longer than this counts as "no answer" (the unit stays spent). */
export const RUN_CALL_MS = 20_000;
const OP_ID = /^[A-Za-z0-9_-]{8,64}$/;

/** Durable Object storage as runs use it; `DurableObjectStorage` fits, and tests pass a fake. */
export interface RunStore {
  transactionSync<T>(closure: () => T): T;
  kv: {
    get<T = unknown>(key: string): T | undefined;
    put<T>(key: string, value: T): void;
    list<T = unknown>(options?: { prefix?: string }): Iterable<[string, T]>;
  };
}

export type RunState = "open" | "finished" | "stopped" | "expired";

/** Written by 4a-3 at Ben's run-open tap; everything an op is checked against is frozen here (D4). */
export interface RunRecord {
  id: string;
  generation: number;
  state: RunState;
  cards: string[];
  jobs: string[];
  account: string; // frozen account id
  zones: { name: string; id: string }[]; // frozen zone names and ids
  template: number;
  deadline: number; // absolute UTC ms, the approved one
  budget: { max: number; used: number };
  key_rev: number; // the c-box key revision when the run opened (D3)
  run_key_id?: string; // the run's Cloudflare key id; its value lives at runkey:<id>, never in a result
  opened_by: string; // the run-open grant id
}

type OpState = "admitted" | "released" | "withheld" | "failed";
interface Intent {
  op: string;
  run: string;
  n: number; // which unit of the budget
  job: string;
  generation: number;
  at: number;
  state: OpState;
  why?: string;
}

/** What one op asks for. `generation` and `key_rev` are what the desk verified on the signed request. */
export interface OpRequest {
  run: string;
  generation: number;
  key_rev: number;
  card: string;
  job: string;
  op: string;
  params: Record<string, string>;
}

/** The vault's answer. `agent` is the exact line the agent is told; `ben` the exact /log line (E4, F2). */
export type OpResult = { outcome: "done"; data: unknown; truncated?: boolean; agent: "done"; ben: string } | { outcome: "refused" | "failed" | "not_returned"; agent: string; ben: string };

const utc = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
const runKey = (id: string) => `run:${id}`;
const intentKey = (run: string, op: string) => `intent:${run}:${op}`;

export class RunBook {
  private store: RunStore;
  private fetch: Fetch;
  private now: () => number;
  constructor(store: RunStore, fetchFn: Fetch, now: () => number = Date.now) {
    this.store = store;
    this.fetch = fetchFn;
    this.now = now;
  }

  /** Records the c-box key revision the desk now trusts. Never goes down; open runs from an older one refuse (D3). */
  setKeyRev(rev: number): number {
    if (!Number.isSafeInteger(rev) || rev < 0) throw new VaultError("bad_key_rev");
    return this.store.transactionSync(() => {
      const cur = this.store.kv.get<number>("cbox_rev") ?? 0;
      if (rev > cur) this.store.kv.put("cbox_rev", rev);
      return Math.max(rev, cur);
    });
  }

  /** One op: admit (one transaction), call Cloudflare with the run's key, release (one transaction). */
  async op(req: OpRequest): Promise<OpResult> {
    let admitted: { run: RunRecord; key: string } | OpResult;
    try {
      admitted = this.store.transactionSync(() => this.admit(req));
    } catch {
      return { outcome: "failed", agent: "failed: vault storage error before the call; nothing was called", ben: `job_failed: run ${req.run} op ${req.op}: vault storage error, nothing called` };
    }
    if ("outcome" in admitted) return admitted;
    const { run, key } = admitted;
    const tag = `run ${run.id} op ${req.op}`;
    let answer: { data: unknown; truncated?: boolean };
    try {
      const timed: Fetch = (input, init) => this.fetch(input, { ...init, signal: AbortSignal.timeout(RUN_CALL_MS) });
      const zoneId = run.zones.find((z) => z.name === req.params.zone)?.id ?? "";
      answer = await readWith(req.job, run.account, zoneId, req.params)(new Cloudflare(key, timed));
    } catch (e) {
      const status = /^cf_(\d{3})/.exec((e as Error).message)?.[1];
      if (status) {
        this.close(run.id, req.op, "failed", `cloudflare refused ${status}`);
        return { outcome: "failed", agent: `failed: cloudflare refused (${status})`, ben: `job_failed: ${tag}: Cloudflare refused` };
      }
      // No answer: the intent stays "admitted" (counted, shown as unresolved on the run's status).
      return { outcome: "failed", agent: "failed: no answer from Cloudflare; this op counts against the budget", ben: `job_failed: ${tag}: no answer` };
    }
    let verdict: true | string;
    try {
      verdict = this.store.transactionSync(() => this.release(run.id, req.op));
    } catch {
      // Nothing was written (the transaction rolled back), so the op is not released: the answer is dropped.
      return { outcome: "failed", agent: "failed: Cloudflare answered but the vault could not save the release; answer not returned", ben: `job_failed: ${tag}: called, release not saved; answer withheld` };
    }
    if (verdict !== true) {
      const why = verdict;
      return { outcome: "not_returned", agent: `not returned: ${why.startsWith("c-box") ? why : `run ${why}`} before the answer was released`, ben: `${tag}: answer withheld (${why})` };
    }
    return { outcome: "done", ...answer, agent: "done", ben: `run_op: ${tag}: ${req.job} done` };
  }

  // Runs inside the admission transaction: no I/O, no await. Checks in a fixed order, then spends one unit
  // and writes the intent. Returns the run and its key, or the refusal.
  private admit(req: OpRequest): { run: RunRecord; key: string } | OpResult {
    const refuse = (code: string, ben: string): OpResult => ({ outcome: "refused", agent: `refused: ${code}`, ben: `refused: ${ben}` });
    const run = this.store.kv.get<RunRecord>(runKey(req.run));
    if (!run) return refuse("unknown_run", `run request for unknown run ${req.run}`);
    const R = `run ${run.id}`;
    if (run.state === "open" && this.now() >= run.deadline) this.end(run, "expired");
    if (run.state === "expired") return refuse(`run_ended (deadline ${utc(run.deadline)})`, `${R} ended at ${utc(run.deadline)}`);
    if (run.state !== "open") return refuse(`run_${run.state}`, `${R} is ${run.state}`);
    if (req.generation !== run.generation) return refuse("run_changed", `${R} changed since this request`);
    if (req.key_rev !== run.key_rev || (this.store.kv.get<number>("cbox_rev") ?? 0) !== run.key_rev) return refuse("cbox_key_changed", `${R}: c-box key changed since the run opened`);
    if (!run.cards.includes(req.card)) return refuse("card_not_in_run", `card ${req.card} is not in ${R}`);
    if (!run.jobs.includes(req.job) || !RUN_ELIGIBLE.includes(req.job)) return refuse("job_not_in_run", `job ${req.job} is not in ${R}`);
    const bad = this.outside(run, req.job, req.params);
    if (bad) return refuse(`params_outside_run (${bad})`, `${R}: ${bad} outside the run`);
    if (!OP_ID.test(String(req.op))) return refuse("params_outside_run (op)", `${R}: op outside the run`);
    if (this.store.kv.get(intentKey(run.id, req.op))) return refuse("op_replayed", `${R}: op ${req.op} sent twice`);
    const key = run.run_key_id ? this.store.kv.get<{ value: string }>(`runkey:${run.id}`)?.value : undefined;
    if (!key) return refuse("no_run_key", `${R} has no key`);
    if (run.budget.used >= run.budget.max) return refuse(`budget_spent (${run.budget.used} of ${run.budget.max} used)`, `${R} budget spent`);
    run.budget.used += 1;
    this.store.kv.put(runKey(run.id), run);
    const intent: Intent = { op: req.op, run: run.id, n: run.budget.used, job: req.job, generation: run.generation, at: this.now(), state: "admitted" };
    this.store.kv.put(intentKey(run.id, req.op), intent);
    return { run, key };
  }

  // The params fence (D4): only the fields a job takes, and only the run's frozen resources.
  private outside(run: RunRecord, job: string, params: Record<string, string>): string | undefined {
    const allowed = job === "cf.audit.read" ? ["since", "until"] : ["zone"];
    const extra = Object.keys(params ?? {}).find((k) => !allowed.includes(k));
    if (extra) return extra;
    if (job === "cf.audit.read") return auditWindow(params.since, params.until, this.now()) ? undefined : "since";
    return run.zones.some((z) => z.name === params.zone) ? undefined : "zone";
  }

  // Inside the release transaction: the answer goes out only if the run is still the same open run, the
  // c-box key is unchanged and the deadline has not passed (E3). Stop and finish are transactions on the same
  // object, so every op is released before a stop or refused after it.
  private release(id: string, op: string): true | string {
    const run = this.store.kv.get<RunRecord>(runKey(id));
    const intent = this.store.kv.get<Intent>(intentKey(id, op));
    if (!run || !intent) throw new VaultError("intent_missing");
    if (run.state === "open" && this.now() >= run.deadline) this.end(run, "expired");
    const keyOk = (this.store.kv.get<number>("cbox_rev") ?? 0) === run.key_rev;
    const ok = run.state === "open" && run.generation === intent.generation && keyOk;
    // Why it was withheld, in the words the agent reads: "run stopped", "run finished", "run ended", ...
    const why = run.state === "expired" ? "ended" : run.state !== "open" ? run.state : !keyOk ? "c-box key changed" : "changed";
    intent.state = ok ? "released" : "withheld";
    if (!ok) intent.why = why;
    this.store.kv.put(intentKey(id, op), intent);
    return ok ? true : why;
  }

  /** Marks an op that ended without an answer to release (Cloudflare refused). Best effort, its own transaction. */
  private close(id: string, op: string, state: OpState, why: string): void {
    try {
      this.store.transactionSync(() => {
        const intent = this.store.kv.get<Intent>(intentKey(id, op));
        if (intent) this.store.kv.put(intentKey(id, op), { ...intent, state, why });
      });
    } catch {
      // Left "admitted": the run's status shows it unresolved, which is the truth we can still tell.
    }
  }

  /** Ends a run inside the caller's transaction: sets the state and bumps the generation (the fence). */
  private end(run: RunRecord, state: Exclude<RunState, "open">): void {
    run.state = state;
    run.generation += 1;
    this.store.kv.put(runKey(run.id), run);
  }

  /** Ben's stop or the agent's finish: the fence is written first, in one transaction, never behind anything (D7). */
  endRun(id: string, how: "stopped" | "finished"): { state: RunState; generation: number } {
    return this.store.transactionSync(() => {
      const run = this.store.kv.get<RunRecord>(runKey(id));
      if (!run) throw new VaultError("unknown_run");
      if (run.state === "open") this.end(run, this.now() >= run.deadline ? "expired" : how);
      return { state: run.state, generation: run.generation };
    });
  }

  /** What a run page shows: the record without any key value, and each op's state read back from storage. */
  status(id: string): { run: Omit<RunRecord, "run_key_id"> & { has_key: boolean }; ops: { op: string; n: number; job: string; state: OpState; why?: string }[]; unresolved: number } {
    const run = this.store.kv.get<RunRecord>(runKey(id));
    if (!run) throw new VaultError("unknown_run");
    const ops = [...this.store.kv.list<Intent>({ prefix: `intent:${id}:` })].map(([, i]) => ({ op: i.op, n: i.n, job: i.job, state: i.state, ...(i.why ? { why: i.why } : {}) }));
    const { run_key_id, ...shown } = run;
    return { run: { ...shown, has_key: Boolean(run_key_id) }, ops, unresolved: ops.filter((o) => o.state === "admitted").length };
  }
}
