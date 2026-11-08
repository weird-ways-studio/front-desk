// The fixed list of jobs an agent may ask for. Anything not listed here is
// refused at /request, and a stored grant for a job no longer listed is refused
// (desk.ts grant()). A job marked `vault` runs inside the vault Worker
// (vault/src/vault.ts) at Ben's tap, with the master key his passkey unlocks.
// The agents' menu (GET /menu, `node scripts/agent.mjs menu`) is generated from this list.

import { STUDIO_ZONES } from "../vault/src/zones.ts";
import { AUDIT_MAX_DAYS, auditWindow } from "../vault/src/vault.ts";
import { isP256Spki } from "./cboxkey.ts";
import { baselineDone, name, plainChanges } from "./ghplain.ts";
import { validRepoName } from "../vault/src/ghrepo.ts";
import type { CfAcceptResult, GhBaselineResult, HeadcountSetupResult, ReadResult, RepoCreateResult } from "../vault/src/api.ts";

// What Ben reads on the approval screen, built from the stored grant (instruction.orient-the-person):
// what approving does, anything to check, what happens when he taps, and the exact text folded below.
export interface Guide {
  does: string;
  sections?: { heading: string; items: string[] }[];
  warn?: string;
  expect: string;
  exact?: string;
}

// How a job runs (card ae6147e4). tap: Ben approves this one job with Face ID; the agent never holds a
// key. run: inside a run Ben opened with one tap, read-only (not built yet: 4a-2/4a-3). key: a key on the
// c-box for a named project that cannot deploy by merge (none today, so none built).
export type Mode = "tap" | "run" | "key";

export interface Job {
  mode: Mode;
  // For the agents' menu: what it does and on what, and the params it takes. Static, no values.
  menu: { does: string; on: string; params: string };
  explain(params: Record<string, string>): Guide;
  // The sentence Ben reads after his tap. `result` is undefined for a job that runs when the agent collects.
  done(result: unknown): string;
  // Returns clean params, or null to refuse.
  validate(params: unknown): Record<string, string> | null;
  // Runs at collect. Vault jobs have no run here: they run at approval, in the vault.
  run?(params: Record<string, string>): Promise<unknown>;
  vault?: true;
  // The request and the collect must carry the enrolled c-box key's signature (src/cboxkey.ts), so a
  // stolen front-desk login alone cannot collect the answer.
  signed?: true;
  // Offered only on a card (card 77ec1e64 finding 3): /request refuses it `card_only`, and the vault's run() refuses
  // it `job_not_offered`, so there is one approval path to build and review.
  cardOnly?: true;
}

// A failed vault job in words: what is known to be left behind, then the vault's own reason in
// brackets for the agent. Each job says what its failure leaves (Codex readable r1 #9).
type Failed = { ok?: unknown; error?: unknown } & Record<string, unknown>;
// Earlier short vault keys this tap's sweep could not confirm deleted, in words (Codex 4a-1 r1 #2).
function leftoverNote(result: unknown): string {
  const n = ((result as { leftover?: unknown[] } | null | undefined)?.leftover ?? []).length;
  return n ? ` Also: ${n} short vault key${n === 1 ? "" : "s"} from an earlier tap could not be confirmed deleted; the vault tries again at your next Cloudflare tap and the nightly check lists ${n === 1 ? "it" : "them"} until then.` : "";
}

function withLeftover(result: unknown, done: (r: unknown) => string): string {
  return done(result) + leftoverNote(result);
}

// Why the vault refused before recording the grant as used, in plain words (card bb86abf0 R6).
const REFUSAL_WORDS: Record<string, string> = {
  wrong_shape: "the front desk and the vault were on different versions, probably for a moment during an update",
  no_pin: "no passkey is pinned in the vault",
  bad_grant: "the request's details were not in the form the vault accepts",
  bad_assertion: "your Face ID answer did not check out for this exact request",
  card_grant: "this request is part of a card, and runs only from the card's own page",
};

// A vault call that threw (vault_stage set by Desk.approve): three messages, by where the vault stopped.
function stageWords(r: Failed): string | null {
  const why = typeof r.error === "string" ? r.error : "unknown";
  // Scoped to this attempt: the vault refused before recording the grant, so this attempt started nothing. It
  // cannot say no earlier attempt ran (a buggy desk could call twice), so Ben checks first (Codex build r2 #1).
  if (r.vault_stage === "before" && Object.hasOwn(REFUSAL_WORDS, why)) return `This attempt did not run: the vault refused it because ${REFUSAL_WORDS[why]}. Check this request's result, then ask for it again if nothing happened. [${why}]`;
  if (r.vault_stage === "old") return `This approval is too old to use. It may have run once already, so check its result before asking again. [${why}]`;
  if (r.vault_stage === "used") return `This approval was already used once, so it may have run. Check its result before asking again. [${why}]`;
  if (r.vault_stage !== undefined) return `It is not known whether this ran. Check its result before asking again. [${why}]`;
  return null;
}

function notDone(result: unknown, left: (r: Failed) => string): string | null {
  const r = result as Failed | null | undefined;
  if (r === undefined || r === null) return "Not done: no answer came back from the vault, so it is unknown what ran. Do not tap again; tell the agent: [no result]";
  if (r.ok === true) return null;
  const staged = stageWords(r);
  if (staged !== null) return staged;
  const why = typeof r.error === "string" ? r.error : "a check did not pass";
  const deleteFailed = typeof r.error === "string" && /delete failed/.test(r.error) ? " A key the vault made could not be deleted: the nightly check lists it until it is gone." : "";
  return `Not done. ${left(r)}${deleteFailed} Tell the agent the words in brackets: [${why}]`;
}

const READ_EXPECT =
  "Face ID unlocks the vault for a moment. It makes two internal keys good for 5 minutes (one to find the zone, one to read it), reads, deletes both, and passes only the answer to the agent.";

/** The sentence Ben reads after a read job's tap. */
function readDone(result: unknown): string {
  return withLeftover(result, (result) =>
    notDone(result, () => "No answer went to the agent, and no key either.") ??
    `Done. The agent gets the answer now${(result as Partial<ReadResult>).truncated ? " (the list was long, so it was cut)" : ""}; the internal keys were deleted. Nothing else to do.`,
  );
}

// Exactly one param, a studio zone: anything extra is refused, not dropped.
function zoneOnly(params: unknown): Record<string, string> | null {
  const p = (params ?? {}) as { zone?: unknown };
  return params && typeof params === "object" && Object.keys(params).length === 1 && typeof p.zone === "string" && STUDIO_ZONES.includes(p.zone) ? { zone: p.zone } : null;
}

/** Ben's N2 answer (2026-11-08), shown verbatim on the card for every new repo (REFINE-77ec1e64 Outcome 3). */
export const REPO_REACH = "The new repo is reachable by the studio's GitHub App (the repo-maker) with the powers it has on every studio repo.";

/** The sentence after a gh.repo.create entry: only what is true (C6a-2 planned shape 1). */
function repoDone(result: unknown): string {
  const r = result as (Partial<RepoCreateResult> & { error?: unknown }) | null | undefined;
  const unknown = (what: string) => `Unknown: it is not known whether the repo was made as asked. Check github.com/weird-ways-studio before asking again.${keys} [created: ${what}]`;
  const keys = (r?.keys ?? []).some((k) => k.revoke !== "proven") ? " One of the vault's short repo-maker keys could not be proven deleted; it stops working by itself within the hour." : "";
  // No answer, or the vault refused before the job ran: the shared words (stageWords, notDone).
  if (!r || typeof r !== "object" || r.created === undefined) return (r?.ok === true ? null : notDone(result, () => "Nothing was made.")) ?? unknown("no facts");
  if (r.created === "confirmed" && (r as { eligible?: unknown }).eligible === false) {
    // Each reason gets its own words: an already-listed repo raises no alarm (Codex build r2 N1).
    const why = String((r as { why?: unknown }).why ?? "unknown");
    if (why === "listed") return `Not done as planned: weird-ways-studio/${r.name} exists and was already on the nightly check's list with this same id, so nothing was added and the check expects it. Tell the agent: the repo is there.${keys} [created: already_listed]`;
    return `Not done as planned: weird-ways-studio/${r.name} exists, but the nightly check will not add it by itself (${why === "window" ? "GitHub says it was made outside this card's time" : "its record could not be checked"}). Tonight's alarm names it; if it is yours, accept it with the GitHub list approval.${keys} [created: not_eligible: ${why}]`;
  }
  if (r.created === "confirmed") return `Done. weird-ways-studio/${r.name} exists, empty and private. Tonight's check expects it once the Observatory has recorded this result; until then the nightly alarm names it.${keys} Nothing else to do.`;
  if (r.created === "absent") return r.refusal === "repo_exists" ? `Not done. A repository with that name already exists, so nothing was made.${keys} Tell the agent the words in brackets: [repo_exists]` : `Not done. Nothing was made.${keys} Tell the agent the words in brackets: [${String(r.refusal ?? "a check did not pass")}]`;
  return unknown(String(r.created));
}

const ONE_STANDING_KEY = "It never expires: it stays in the vault so the count runs each night without you. A new standing key, by your choice.";

export const JOBS = {
  "test.echo": {
    mode: "tap",
    menu: { does: "Test only: echoes a word back. Touches nothing.", on: "nothing", params: "word: a-z, 1-20 letters" },
    explain: (p) => ({
      does: `Test only: the front desk echoes the word "${p.word}". It touches nothing.`,
      expect: "Face ID, then the agent collects the echo. Nothing else changes.",
    }),
    done: () => `Approved. The agent collects the echo now; nothing else to do.`,
    validate: (params) => {
      const word = (params as { word?: unknown } | null)?.word;
      return typeof word === "string" && /^[a-z]{1,20}$/.test(word) ? { word } : null;
    },
    run: async (p) => ({ echoed: p.word }),
  },
  // Ben's approval stores the key (Desk.enrollCboxKey); the front desk adds fingerprint and replaces.
  "cbox.key.enroll": {
    mode: "tap",
    menu: { does: "Trust a new c-box signing key (Ben checks the fingerprint).", on: "the front desk", params: "key: P-256 public key, base64url SPKI" },
    explain: (p) => ({
      does: `Trust a new c-box signing key${p.replaces === "none" ? "" : ", REPLACING the current one"}. Requests signed with it count as coming from the c-box.`,
      warn: `Check: the agent must have just shown you this same fingerprint in chat: ${p.fingerprint}. If it did not, or it differs, do not approve: the agent's login may be stolen.`,
      expect: "Face ID, then the key is trusted at once.",
      exact: `Fingerprint ${p.fingerprint}${p.replaces === "none" ? "" : `; replaces ${p.replaces}`}`,
    }),
    done: () => "Done. The new c-box key is trusted. Nothing else to do.",
    validate: (params) => {
      const key = (params as { key?: unknown } | null)?.key;
      return isP256Spki(key) ? ({ key } as Record<string, string>) : null;
    },
    run: async (p) => ({ enrolled: p.fingerprint }),
  },
  // cf.token.zone.read (a 15-minute key printed to the agent) is retired: the read jobs below do the
  // reading in the vault and hand over only the answer (card ae6147e4 4a-1).
  "cf.zone.read": {
    mode: "tap",
    menu: { does: "Read a zone's basic details: status, plan, name servers.", on: "one studio zone", params: "zone: a studio zone" },
    explain: (p) => ({
      does: `Cloudflare, read only: the basic details of ${p.zone} (status, plan, name servers), for the agent. Nothing is changed and no key goes to the agent.`,
      expect: READ_EXPECT,
      exact: `Zone ${p.zone}; read only`,
    }),
    done: readDone,
    validate: zoneOnly,
    vault: true,
    signed: true,
  },
  "cf.dns.list": {
    mode: "tap",
    menu: { does: `Read every DNS record of a zone (up to 500).`, on: "one studio zone", params: "zone: a studio zone" },
    explain: (p) => ({
      does: `Cloudflare, read only: every DNS record of ${p.zone}, for the agent. Nothing is changed and no key goes to the agent.`,
      expect: READ_EXPECT,
      exact: `Zone ${p.zone}; DNS records; read only`,
    }),
    done: readDone,
    validate: zoneOnly,
    vault: true,
    signed: true,
  },
  "cf.audit.read": {
    mode: "tap",
    menu: { does: `Read the account's change log: who changed what, when (up to 300 entries).`, on: "the main Cloudflare account", params: `since, until: UTC times like 2026-11-03T00:00:00Z, at most ${AUDIT_MAX_DAYS} days apart, not in the future` },
    explain: (p) => ({
      does: `Cloudflare, read only: the account's change log (who changed what) from ${p.since} to ${p.until}, for the agent. Nothing is changed and no key goes to the agent.`,
      warn: "To read the log, the vault's short key can also read the account's settings and member list for those 5 minutes. It stays inside the vault.",
      expect: "Face ID unlocks the vault for a moment. It makes one internal key good for 5 minutes, reads the log, deletes the key, and passes only the answer to the agent.",
      exact: `Account change log; ${p.since} to ${p.until} (UTC); read only`,
    }),
    done: readDone,
    validate: (params) => {
      const { since, until } = (params ?? {}) as { since?: unknown; until?: unknown };
      return params && Object.keys(params).length === 2 && auditWindow(since, until, Date.now()) ? { since: since as string, until: until as string } : null;
    },
    vault: true,
    signed: true,
  },
  // The vault mints the nightly headcount's own key (vault/src/vault.ts setupHeadcount). Card C5c-2.
  "cf.token.headcount.setup": {
    mode: "tap",
    menu: { does: "Make or replace the nightly count's list-only key.", on: "the main Cloudflare account", params: "none" },
    explain: () => ({
      does: `Make the nightly headcount key: it can LIST the names of every Cloudflare key in the studio account, and nothing else. It cannot make, change or delete keys, and cannot read their secrets. ${ONE_STANDING_KEY}`,
      expect: "Face ID unlocks the vault for a moment. It makes the key, checks it is refused when it tries to make a key, and keeps it inside the vault for the nightly count. Running this again replaces it.",
    }),
    done: (r) => withLeftover(r, (r) => notDone(r, (x) => ((x as unknown as Partial<HeadcountSetupResult>).key_id ? "The nightly count keeps its previous key; the new one did not pass its checks and is deleted." : "The nightly count keeps its previous key.")) ?? "Done. The nightly count has its list-only key, and it was refused when it tried to make one. Nothing else to do."),
    validate: (params) => (params && typeof params === "object" && Object.keys(params).length === 0 ? {} : null),
    vault: true,
  },
  // The vault locks the GitHub App key and records the nightly count's expected list (vault/src/vault.ts ghBaseline). Card C6a-1.
  "gh.app.baseline": {
    mode: "tap",
    menu: { does: "Accept what can reach the studio's GitHub as the nightly check's list.", on: "the weird-ways-studio GitHub org", params: "none (the desk adds the changes)" },
    explain: (p) => {
      const lines = p.changes && p.changes !== "none" ? p.changes.split("\n") : [];
      return {
        does: lines.length
          ? "GitHub: accept everything below as what the nightly check expects can reach the studio's code. The first time, this also locks the main GitHub App's key to your passkey."
          : "GitHub: nothing has changed since the last list you accepted. Approving just re-checks both Apps.",
        sections: plainChanges(lines),
        warn: lines.length ? "If you do not recognise every line, do not approve: it may be someone else's access." : undefined,
        expect: "Face ID unlocks the vault for a moment. It locks the main App's key (first time only), checks both Apps still behave, and saves this list. If GitHub changed since this page was made, nothing is accepted and you will see why.",
        exact: lines.join("\n") || undefined,
      };
    },
    done: (r) =>
      notDone(r, (x) => `The list was not saved, so the nightly check still expects the previous one.${(x as unknown as Partial<GhBaselineResult>).main?.locked_to_passkey_now ? " The main App's key is now locked to your passkey; that part is done and safe." : ""}`) ??
      baselineDone(r as GhBaselineResult),
    // The agent sends no params; the front desk adds `changes` and `snapshot` from the vault (desk.ts request).
    validate: (params) => (params && typeof params === "object" && Object.keys(params).length === 0 ? {} : null),
    vault: true,
  },
  // Adds Cloudflare keys the nightly count flagged to what it expects (vault/src/vault.ts acceptKeys).
  "cf.token.accept": {
    mode: "tap",
    menu: { does: "Tell the nightly check that flagged Cloudflare keys are Ben's.", on: "the main Cloudflare account", params: "none (the desk adds the keys)" },
    explain: (p) => {
      const ids = (p.ids ?? "").split(",");
      const names = (p.names ?? "").split("\n");
      const scopes = (p.scopes ?? "").split("\n");
      return {
        does: `Cloudflare: keep ${ids.length === 1 ? "this key" : "these keys"} as yours, so the nightly check stops flagging ${ids.length === 1 ? "it" : "them"}. Not made by the front desk. Each is read-only; the nightly check alarms if one ever changes: what it can do, where it works from, or how long it lasts. Nothing is made, changed or deleted in Cloudflare.`,
        sections: [{ heading: `Keys not made by the front desk: ${ids.length}`, items: ids.map((id, i) => `${name(names[i] ?? "")} [${id}]`) }],
        warn: "If you do not recognise every key, do not approve: it may be someone else's access.",
        expect: "Face ID unlocks the vault for a moment. It checks each key is still in the account, still unexpected, still exactly what Cloudflare showed when this page was made, and still read-only. Then it keeps them. If anything changed, nothing is accepted and you will see why.",
        exact: ids.map((id, i) => `${id}: ${scopes[i] ?? ""}`).join("\n"),
      };
    },
    done: (r) => withLeftover(r, (r) =>
      notDone(r, () => "Nothing was added, so the nightly check still flags these keys.") ??
      `Done. The nightly check now expects ${((r as Partial<CfAcceptResult>).accepted?.length ?? 0) === 1 ? "this key" : "these keys"}. Nothing else to do.`),
    // The agent sends no params; the front desk adds `ids` and `names` from the vault (desk.ts request).
    validate: (params) => (params && typeof params === "object" && Object.keys(params).length === 0 ? {} : null),
    vault: true,
  },
  // The vault makes one empty private repo with the repo-maker App, inside a card entry (vault/src/ghrepo.ts;
  // card 77ec1e64). Card only. The nightly check adds it to its list once the Observatory recorded the result.
  "gh.repo.create": {
    mode: "tap",
    menu: { does: "Make one empty private repository in the studio's GitHub org (card only).", on: "the weird-ways-studio GitHub org", params: "name: lower-case letters, digits and single dashes, 2-64 long" },
    explain: (p) => ({
      does: `GitHub: make an empty private repository named "${p.name}" in weird-ways-studio, using the repo-maker App. ${REPO_REACH}`,
      expect: "Face ID unlocks the vault for a moment. It checks the repo-maker App, checks nobody can skip your review on front-desk's main, checks the name is free, makes the repo with a key that can only create repositories, then deletes both of its short keys and proves them dead. The agent adds the code itself afterwards.",
      exact: `Repository weird-ways-studio/${p.name}; private; empty`,
    }),
    done: repoDone,
    validate: (params) => {
      const name = (params as { name?: unknown } | null)?.name;
      return params && typeof params === "object" && Object.keys(params).join() === "name" && validRepoName(name) ? { name } : null;
    },
    vault: true,
    signed: true,
    cardOnly: true,
  },
} satisfies Record<string, Job>;

export type JobName = keyof typeof JOBS;

/** The agents' menu, generated from JOBS (served at GET /menu). Adding a job is a pull request Ben merges. */
/**
 * Jobs the desk lets onto a card (card 85818ab1): the read-only or touch-nothing jobs, plus gh.repo.create (card
 * 77ec1e64, card only) -- the same five as the vault's
 * CARD_JOBS (vault/src/cards.ts) and the Observatory's CARD_ELIGIBLE. Each side checks its own list.
 */
export const CARD_ELIGIBLE: readonly JobName[] = Object.freeze(["test.echo", "cf.zone.read", "cf.dns.list", "cf.audit.read", "gh.repo.create"] as JobName[]);

export function menu() {
  return {
    jobs: Object.entries(JOBS as Record<string, Job>).map(([job, j]) => ({ job, mode: j.mode, ...j.menu, signed: !!j.signed, ...(j.cardOnly ? { card_only: true } : {}) })),
    modes: { tap: "Ben approves this one job with Face ID; you never hold a key.", run: "Inside a run Ben opened (not built yet).", key: "A key on the c-box (none offered)." },
    new_job: "Not on the list? Propose it as a pull request to front-desk src/jobs.ts (and vault/src/vault.ts for a vault job); it exists once Ben merges it.",
    card: `Several of ${CARD_ELIGIBLE.join(", ")} on one Face ID tap, run in order: node scripts/agent.mjs post <desk>/card '{"entries":[{"job":...,"params":{...},"reason":"..."}]}', then node scripts/agent.mjs get <desk>/card/<card> once Ben's page says done. At most 2 entries for now.`,
    ask: "node scripts/agent.mjs post <desk>/request '{\"job\":...,\"params\":{...},\"reason\":\"<card id>: why\"}', then node scripts/agent.mjs wait <collect-url>",
  };
}
