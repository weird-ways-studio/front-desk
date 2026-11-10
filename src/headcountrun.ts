// Headcount runs agents can read (card build 5 6ab972c8; studio-os REFINE-6ab972c8-night.md v2.1, which calls them
// "nights"). A run is one pass of the scheduled count (Desk.headcount, cron in wrangler.jsonc); it is named by when
// it started, never as a "night", because the schedule, a retry or a manual run need not fall at night (Ben,
// 2026-11-10).
//
// Each run first takes a running number (`hcrun:attempt`), then publishes a summary of its result under
// `hcrun:n:<seq>`; the last KEEP summaries are kept. GET /headcount (agent only) returns them, and judge() turns
// them into one verdict so a missing, stale, errored or cut-off run is never read as clean:
//   PASS     the run was clean (all of it: Cloudflare and GitHub), nothing missing in between;
//   FAIL     the run alarmed;
//   UNPROVEN anything else -- no run, a gap, an unpublished run, errors, a cut-off list, a bad time.
// The summary holds counts, error codes from a fixed list and repo names only: no key or token ids or names, no
// members, owners, invitations, App, PAT or deploy-key entries, and no text from any error message.

import type { Headcount } from "../vault/src/api.ts";

export const KEEP = 14; // summaries kept
export const LIST_MAX = 50; // entries per repo list
// Longest allowed time between two runs' starts: the cron in wrangler.jsonc runs once a day (04:17 UTC), plus
// two hours' slack. A schedule change must change this too (test: "GAP_MS fits the cron").
export const GAP_MS = 26 * 3600_000;
// Clock drift allowed between the desk (which stamps runs) and the reader (`now`).
export const SKEW_MS = 5 * 60_000;

// The GitHub change kinds a summary counts by name (GhSnapshot's lists plus the vault's unreceipted-repo line).
// `repos` lines go to the two lists instead; anything else counts under "other".
const KINDS = ["repo_ids", "members", "owners", "outside", "invites", "apps", "pats", "deploy_keys", "rulesets", "repo_result_unrecorded"] as const;

export interface RunAttempt {
  seq: number;
  started_at: string;
}

export interface RunSummary {
  seq: number;
  started_at: string;
  completed_at: string;
  ok: boolean;
  cloudflare: { tokens: number; unexpected: number; stretched: number; missing: number; cleanup: number; widened: number };
  github: { ok: boolean; repos_added: string[]; repos_removed: string[]; other_changes: Record<string, number> };
  errors: ("headcount_failed" | "github_failed")[];
  truncated: boolean;
}

export interface RunView {
  none?: true;
  attempt: RunAttempt | null;
  runs: RunSummary[]; // newest first
}

const iso = (ms: number) => new Date(ms).toISOString();
const runKey = (seq: number) => `hcrun:n:${String(seq).padStart(12, "0")}`;

/** The summary of one finished run, built from the structured result only (never from the log text). */
export function runSummary(r: Headcount, attempt: RunAttempt, completedAt: number): RunSummary {
  const added: string[] = [], removed: string[] = [];
  const other: Record<string, number> = {};
  for (const line of r.github?.changes ?? []) {
    const repo = /^repos ([+-])(.*)$/s.exec(line);
    if (repo) {
      (repo[1] === "+" ? added : removed).push(repo[2]);
      continue;
    }
    const kind = /^([a-z_]+)(?: [+-]|:)/.exec(line)?.[1];
    const k = kind && (KINDS as readonly string[]).includes(kind) ? kind : "other";
    other[k] = (other[k] ?? 0) + 1;
  }
  const errors: RunSummary["errors"] = [];
  if (r.error) errors.push("headcount_failed");
  if (r.github?.error) errors.push("github_failed");
  return {
    seq: attempt.seq,
    started_at: attempt.started_at,
    completed_at: iso(completedAt),
    ok: r.ok === true,
    cloudflare: {
      tokens: r.tokens,
      unexpected: r.unexpected.length,
      stretched: r.stretched.length,
      missing: r.missing.length,
      cleanup: r.cleanup.length,
      widened: (r.widened ?? []).length,
    },
    github: { ok: r.github?.ok === true, repos_added: added.slice(0, LIST_MAX), repos_removed: removed.slice(0, LIST_MAX), other_changes: other },
    errors,
    truncated: added.length > LIST_MAX || removed.length > LIST_MAX,
  };
}

interface RunStore {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  list<T>(options: { prefix: string }): Promise<Map<string, T>>;
  delete(key: string): Promise<boolean>;
}

/** Takes the next running number, before the run reads anything. */
export async function beginRun(store: RunStore, now: number): Promise<RunAttempt> {
  const prev = await store.get<RunAttempt>("hcrun:attempt");
  const attempt = { seq: (prev?.seq ?? 0) + 1, started_at: iso(now) };
  await store.put("hcrun:attempt", attempt);
  return attempt;
}

/** Publishes one summary and drops all but the newest KEEP. */
export async function saveRun(store: RunStore, s: RunSummary): Promise<void> {
  await store.put(runKey(s.seq), s);
  const keys = [...(await store.list({ prefix: "hcrun:n:" })).keys()].sort();
  for (const k of keys.slice(0, Math.max(0, keys.length - KEEP))) await store.delete(k);
}

/** What GET /headcount returns. Reads only. */
export async function readRuns(store: RunStore): Promise<RunView> {
  const attempt = (await store.get<RunAttempt>("hcrun:attempt")) ?? null;
  const runs = [...(await store.list<RunSummary>({ prefix: "hcrun:n:" })).entries()].sort(([a], [b]) => (a < b ? 1 : -1)).map(([, v]) => v);
  return runs.length ? { attempt, runs } : { none: true, attempt, runs };
}

export type Verdict = "PASS" | "FAIL" | "UNPROVEN";
export interface Judged {
  verdict: Verdict;
  line: string; // one plain line, starting with the verdict
}

const ms = (s: unknown) => (typeof s === "string" && /^\d{4}-\d{2}-\d{2}T/.test(s) ? Date.parse(s) : NaN);
const when = (t: number) => `${iso(t).slice(0, 16).replace("T", " ")} UTC`;
const say = (verdict: Verdict, why: string): Judged => ({ verdict, line: `${verdict}: ${why}` });

/** What a run flagged, as "kind count" pairs (no names), for a FAIL line. */
function counts(n: RunSummary): string {
  const c = n.cloudflare, g = n.github;
  const parts = [
    ...Object.entries(c).filter(([k, v]) => k !== "tokens" && v).map(([k, v]) => `cloudflare ${k} ${v}`),
    ...(g.repos_added.length ? [`repos added ${g.repos_added.length}`] : []),
    ...(g.repos_removed.length ? [`repos removed ${g.repos_removed.length}`] : []),
    ...Object.entries(g.other_changes).map(([k, v]) => `${k} ${v}`),
  ];
  return parts.join(", ") || "none listed";
}

// The repo's name in a `name:visibility` entry: the text before the last ':'.
const repoNamed = (n: RunSummary, repo?: string) => !!repo && n.github.repos_added.some((e) => e.slice(0, e.lastIndexOf(":")) === repo);

/** The FAIL line for a run that alarmed: names the repo when the run listed it as added. */
function alarmed(n: RunSummary, repo?: string): Judged {
  return repoNamed(n, repo) ? say("FAIL", `repo ${repo} was flagged by the headcount run that started ${when(ms(n.started_at))}`) : say("FAIL", `the headcount run that started ${when(ms(n.started_at))} alarmed (${counts(n)})`);
}

/** One run on its own: errors first (unconfirmed), then a cut-off list (unconfirmed, G1), then the alarm, then clean. */
function single(n: RunSummary, repo?: string): Judged {
  const at = when(ms(n.started_at));
  if (!Array.isArray(n.errors) || n.errors.length) return say("UNPROVEN", `the headcount run that started ${at} could not finish its check (${(n.errors ?? []).join(", ") || "errors unreadable"})`);
  if (n.truncated !== false) return say("UNPROVEN", `the headcount run that started ${at} had more changes than the summary lists`);
  if (n.ok !== true || repoNamed(n, repo)) return alarmed(n, repo);
  if (n.github?.ok !== true) return say("UNPROVEN", `the headcount run that started ${at} did not confirm GitHub`);
  return say("PASS", `the headcount run that started ${at} was clean (Cloudflare and GitHub)${repo ? `; repo ${repo} did not set it off` : ""}`);
}

/**
 * The verdict an agent acts on.
 * - No `after` (is the desk's check healthy now?): the newest run must have published, have started within
 *   GAP_MS of `now`, and be clean.
 * - With `after` (did a change at that time set off the alarm?): the first run that COMPLETED after it is the
 *   one judged, never a later one. Its predecessor (seq - 1) must be kept (it then completed at or before
 *   `after`, or it would be the one judged) and have started at most GAP_MS earlier; otherwise a run may be missing in between. A run that started at
 *   or before `after` may have read GitHub before the change: it can FAIL (it alarmed) but never PASS.
 */
export function judge(view: RunView, now: number, opts: { after?: number; repo?: string } = {}): Judged {
  const runs = Array.isArray(view?.runs) ? view.runs : [];
  if (!runs.length) return say("UNPROVEN", "no headcount run has been published yet");
  for (const n of runs) if (Number.isNaN(ms(n.started_at)) || Number.isNaN(ms(n.completed_at)) || !Number.isSafeInteger(n.seq)) return say("UNPROVEN", "a stored run has an unreadable time or number");
  const newest = runs.reduce((a, b) => (b.seq > a.seq ? b : a));
  const attempt = view.attempt;
  if (attempt && (!Number.isSafeInteger(attempt.seq) || Number.isNaN(ms(attempt.started_at)))) return say("UNPROVEN", "the last run's marker is unreadable");
  // Times must be possible (Codex build r1 #4): nothing later than now (beyond SKEW_MS), no run completing before it
  // started, and starts rising with the run number. Otherwise the history cannot be trusted.
  const bySeq = [...runs].sort((a, b) => a.seq - b.seq);
  const future = (t: number) => t > now + SKEW_MS;
  if (bySeq.some((n) => future(ms(n.started_at)) || future(ms(n.completed_at)) || ms(n.completed_at) < ms(n.started_at)) || (attempt && future(ms(attempt.started_at)))) return say("UNPROVEN", "a stored run has an impossible time (in the future, or completed before it started)");
  if (bySeq.some((n, i) => i > 0 && (n.seq === bySeq[i - 1].seq || ms(n.started_at) <= ms(bySeq[i - 1].started_at)))) return say("UNPROVEN", "the stored runs are out of order");

  if (opts.after === undefined) {
    if (attempt && attempt.seq > newest.seq) return say("UNPROVEN", `the last run (started ${when(ms(attempt.started_at))}) is still running or did not publish`);
    if (now - ms(newest.started_at) > GAP_MS) return say("UNPROVEN", `the newest run started ${when(ms(newest.started_at))}, more than 26 hours ago`);
    return single(newest, opts.repo);
  }

  const after = opts.after;
  const done = runs.filter((n) => ms(n.completed_at) > after).sort((a, b) => a.seq - b.seq);
  if (!done.length) {
    const running = attempt && attempt.seq > newest.seq ? `; the last run (started ${when(ms(attempt.started_at))}) is still running or did not publish` : "";
    return say("UNPROVEN", `no headcount run has completed after ${when(after)} yet${running}`);
  }
  const c = done[0];
  const prev = runs.find((n) => n.seq === c.seq - 1);
  if (!prev) return say("UNPROVEN", `the run before the headcount run that started ${when(ms(c.started_at))} is not in the history (missed, unpublished or too old)`);
  if (ms(c.started_at) - ms(prev.started_at) > GAP_MS) return say("UNPROVEN", `more than 26 hours between the headcount run that started ${when(ms(prev.started_at))} and the next; a run may be missing`);
  if (ms(c.started_at) <= after) {
    if (Array.isArray(c.errors) && !c.errors.length && c.ok !== true) return alarmed(c, opts.repo);
    return say("UNPROVEN", `the headcount run that started ${when(ms(c.started_at))} overlapped ${when(after)}; its read may predate the change. This run cannot prove the change clean, and later runs do not replace it`);
  }
  return single(c, opts.repo);
}
