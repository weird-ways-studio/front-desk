// Job gh.repo.create (card 77ec1e64; studio-os spike-08313e62/REFINE-77ec1e64.md v2.2, planned shape from
// face-id-access/REFINE-C6a-2.md 2.1-2.9): the vault makes ONE empty private repo in weird-ways-studio with the
// repo-maker App, inside one card entry. It holds no approval logic: the card book (cards.ts) decides whether it may
// run, and settles its result. It never writes the nightly baseline: that waits for the recorder's receipt
// (CardBook.repoRecorded, Y1/Z1-Z3).
//
// The 13 GitHub calls on the success path (X5): App check 1, installation checks 2, two narrowed mints, ruleset
// list + rule read, existence read, create, two revokes, two revoke probes.

import { VaultError } from "./seal.ts";
import { GitHub, ORG, checkApp, checkInstallation, installationKey } from "./github.ts";

/** A repo name the job accepts: lower-case letters, digits and single dashes, 2-64 long. Shared with src/jobs.ts. */
export const REPO_NAME = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;
export const validRepoName = (n: unknown): n is string => typeof n === "string" && REPO_NAME.test(n) && !n.includes("--");
/** The rule whose bypass list must be empty (Ben D4): anyone on it could reach main without his PR approval. */
export const PROTECT_RULE = { repo: "front-desk", name: "protect-main" } as const;
// The two narrowed keys (REFINE Fit "Tool"). The creation key cannot delete or transfer; the rule-read key works on
// front-desk only, because GitHub shows bypass_actors only to a caller with write access to the ruleset.
export const CREATE_PERMS = { repository_creation: "write", metadata: "read" } as const;
export const RULE_READ = { permissions: { administration: "write" }, repositories: [PROTECT_RULE.repo] } as const;

export interface KeyFacts {
  purpose: "rule-read" | "create";
  expires_at?: string; // GitHub's, as answered at the mint
  revoke_status?: number | string; // HTTP status of DELETE /installation/token, or "error"
  probe_status?: number | string; // HTTP status of the probe with the deleted key: only 401 proves it dead
  revoke: "proven" | "unproven";
}

/**
 * What the step did. `ok` is the card book's entry state (cards.ts CardBook.call): true = done (created as asked),
 * false = failed (a definite refusal; nothing was created), null = unknown (it may exist: check GitHub). Cleanup notes
 * never replace a fact already recorded (C6a-2 Codex r1 #1).
 */
export interface RepoCreateResult {
  ok: boolean | null;
  created: "confirmed" | "absent" | "unknown" | "not_as_asked";
  name: string;
  repo_id?: string; // digits, GitHub's repository id (the recorder requires it on a done result)
  created_at?: string; // GitHub's, the card book checks it against the card window (Z2)
  keys: KeyFacts[];
  refusal?: string;
  notes: string[];
}

const raw = (e: unknown) => (e instanceof Error ? e.message : "unknown error").slice(0, 120);

type Fetch = (i: string, init?: RequestInit) => Promise<Response>;

/** The status of one call, never its body; a network failure is "error". */
const statusOf = (gh: GitHub, method: string, path: string): Promise<number | "error"> => gh.send(method, path).then((res) => res.status, () => "error" as const);

/**
 * Mints a narrowed key, uses it, and in `finally` deletes it and probes it: the key never leaves this function, and
 * only its expiry and the two statuses are kept (threat T7).
 */
async function withRepoKey<T>(app: GitHub, installation: number, narrow: unknown, facts: KeyFacts, fetchFn: Fetch, use: (gh: GitHub) => Promise<T>): Promise<T> {
  const k = await installationKey(app, installation, narrow as { permissions: Record<string, string> });
  if (typeof k?.token !== "string" || !k.token) throw new VaultError(`${facts.purpose}_key_unreadable`);
  facts.expires_at = typeof k.expires_at === "string" ? k.expires_at.slice(0, 40) : undefined;
  const gh = new GitHub(k.token, fetchFn);
  try {
    return await use(gh);
  } finally {
    facts.revoke_status = await statusOf(gh, "DELETE", "/installation/token");
    facts.probe_status = await statusOf(gh, "GET", "/installation/repositories?per_page=1");
    facts.revoke = facts.probe_status === 401 ? "proven" : "unproven";
  }
}

/** Refuses unless front-desk's `protect-main` rule exists once and its bypass list is present and empty (D4, T8). */
async function bypassEmpty(gh: GitHub): Promise<void> {
  let rule: { bypass_actors?: unknown };
  try {
    const list = await gh.call<{ id?: unknown; name?: unknown }[]>("GET", `/repos/${ORG}/${PROTECT_RULE.repo}/rulesets?per_page=100`);
    const hits = Array.isArray(list) ? list.filter((r) => r?.name === PROTECT_RULE.name) : [];
    if (hits.length !== 1 || !Number.isSafeInteger(hits[0].id)) throw new VaultError("bypass_unreadable: protect-main not found once");
    rule = await gh.call("GET", `/repos/${ORG}/${PROTECT_RULE.repo}/rulesets/${hits[0].id}`);
  } catch (e) {
    throw e instanceof VaultError && e.message.startsWith("bypass_") ? e : new VaultError(`bypass_unreadable: ${raw(e)}`);
  }
  const actors = rule?.bypass_actors;
  if (!Array.isArray(actors)) throw new VaultError("bypass_unreadable: no bypass list shown");
  if (actors.length) throw new VaultError(`bypass_on_protect_main: ${actors.map((a) => `${(a as { actor_type?: unknown })?.actor_type}#${(a as { actor_id?: unknown })?.actor_id}`).join(",").slice(0, 80)}`);
}

/**
 * A create answer that proves nothing was made, or undefined (Codex build r1 #3). Only GitHub's documented refusals
 * for this endpoint count -- 403 Forbidden and 422 Validation failed -- and only with a readable error body; anything
 * else (another status, an unreadable body) leaves `unknown`. A 422 whose error names the `name` field as already
 * existing is the race where another repo took the name after the existence check: `repo_exists` (rule v7 recovery).
 * The structured code is VERIFIED in GitHub's REST troubleshooting docs ("Validation failed": already_exists); the exact
 * live payload of this endpoint is not. An unmatched 422 still refuses, as create_refused.
 */
export function definiteRefusal(status: number, body: { message?: unknown; errors?: unknown } | undefined): string | undefined {
  if ((status !== 403 && status !== 422) || typeof body?.message !== "string") return undefined;
  const errs = Array.isArray(body.errors) ? (body.errors as { field?: unknown; code?: unknown; message?: unknown }[]) : [];
  // GitHub's documented structured code `already_exists`, or its `custom` form whose message says so (Codex build r2 #3).
  const taken = (e: { field?: unknown; code?: unknown; message?: unknown }) => e?.field === "name" && (e.code === "already_exists" || (typeof e.message === "string" && /already exists/i.test(e.message)));
  if (status === 422 && errs.some(taken)) return "repo_exists";
  return `create_refused: gh_${status}`;
}

/**
 * The step itself (C6a-2 shape 2.2-2.9). `app` is signed in with the repo-maker App's key, opened by Ben's tap. Every
 * refusal before the create call is `failed` with nothing made; after the call, anything not exactly as asked is
 * `unknown` (the card ends and the Observatory checker alerts).
 */
export async function createRepo(app: GitHub, installation: number, name: string, fetchFn: Fetch): Promise<RepoCreateResult> {
  const r: RepoCreateResult = { ok: false, created: "absent", name, keys: [], notes: [] };
  // X3: the vault's own check, before any network call (the desk checks too; a signed card can still hold a bad name).
  if (!validRepoName(name)) return { ...r, refusal: "bad_params" };
  try {
    await checkApp(app, "main");
    await checkInstallation(app, installation, "main");
    const ruleKey: KeyFacts = { purpose: "rule-read", revoke: "unproven" };
    r.keys.push(ruleKey);
    await withRepoKey(app, installation, RULE_READ, ruleKey, fetchFn, bypassEmpty);
    const createKey: KeyFacts = { purpose: "create", revoke: "unproven" };
    r.keys.push(createKey);
    await withRepoKey(app, installation, { permissions: CREATE_PERMS }, createKey, fetchFn, async (gh) => {
      // Check before write (T10): 404 is the only answer that lets the create go ahead.
      const exists = await gh.call("GET", `/repos/${ORG}/${name}`).then(() => 200, (e: unknown) => (raw(e).startsWith("gh_404:") ? 404 : raw(e)));
      if (exists === 200) throw new VaultError("repo_exists");
      if (exists !== 404) throw new VaultError(`existence_unreadable: ${exists}`);
      // From here on a lost or odd answer may mean the repo exists: never `absent` without a definite 4xx refusal.
      r.created = "unknown";
      let res: Response;
      try {
        res = await gh.send("POST", `/orgs/${ORG}/repos`, { name, private: true, auto_init: false, has_wiki: false });
      } catch (e) {
        r.notes.push(`create: no answer (${raw(e)})`);
        return;
      }
      const body = (await res.json().catch(() => undefined)) as { id?: unknown; name?: unknown; private?: unknown; owner?: { login?: unknown }; created_at?: unknown; message?: unknown; errors?: unknown } | undefined;
      const refusal = definiteRefusal(res.status, body);
      if (refusal) {
        r.created = "absent";
        throw new VaultError(refusal);
      }
      if (res.status !== 201 || !body) {
        r.notes.push(`create: unexpected answer ${res.status}`);
        return;
      }
      if (Number.isSafeInteger(body.id) && (body.id as number) > 0) r.repo_id = String(body.id);
      if (typeof body.created_at === "string" && Number.isFinite(Date.parse(body.created_at))) r.created_at = body.created_at;
      const asAsked = body.private === true && body.owner?.login === ORG && body.name === name && r.repo_id !== undefined && r.created_at !== undefined;
      r.created = asAsked ? "confirmed" : "not_as_asked";
      if (!asAsked) r.notes.push(`create: GitHub's answer differs from what was asked (private ${String(body.private)}, owner ${String(body.owner?.login).slice(0, 40)}, name ${String(body.name).slice(0, 64)})`);
    });
  } catch (e) {
    if (r.created === "unknown" || r.created === "not_as_asked" || r.created === "confirmed") r.notes.push(`after create: ${raw(e)}`);
    else r.refusal = raw(e);
  }
  for (const k of r.keys) if (k.revoke !== "proven") r.notes.push(`${k.purpose} key: revoke unproven (delete ${k.revoke_status ?? "not sent"}, probe ${k.probe_status ?? "not sent"})`);
  r.ok = r.created === "confirmed" ? true : r.created === "absent" ? false : null;
  return r;
}
