// The fixed list of jobs an agent may ask for. Anything not listed here is
// refused at /request, and a stored grant for a job no longer listed is refused
// (desk.ts grant()). A job marked `vault` runs inside the vault Worker
// (vault/src/vault.ts) at Ben's tap, with the master key his passkey unlocks.
// The agents' menu (GET /menu, `node scripts/agent.mjs menu`) is generated from this list.

import { STUDIO_ZONES } from "../vault/src/zones.ts";
import { AUDIT_MAX_DAYS, auditWindow } from "../vault/src/vault.ts";
import { isP256Spki } from "./cboxkey.ts";
import { baselineDone, name, plainChanges } from "./ghplain.ts";
import type { CfAcceptResult, GhBaselineResult, HeadcountSetupResult, ProbeResult, ReadResult } from "../vault/src/api.ts";

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
}

// A failed vault job in words: what is known to be left behind, then the vault's own reason in
// brackets for the agent. Each job says what its failure leaves (Codex readable r1 #9).
type Failed = { ok?: unknown; error?: unknown } & Record<string, unknown>;
function notDone(result: unknown, left: (r: Failed) => string): string | null {
  const r = result as Failed | null | undefined;
  if (r === undefined || r === null) return "Not done: no answer came back from the vault, so it is unknown what ran. Do not tap again; tell the agent: [no result]";
  if (r.ok === true) return null;
  const why = typeof r.error === "string" ? r.error : "a check did not pass";
  const deleteFailed = typeof r.error === "string" && /delete failed/.test(r.error) ? " A key the vault made could not be deleted: the nightly check lists it until it is gone." : "";
  return `Not done. ${left(r)}${deleteFailed} Tell the agent the words in brackets: [${why}]`;
}

const READ_EXPECT =
  "Face ID unlocks the vault for a moment. It makes two internal keys good for 5 minutes (one to find the zone, one to read it), reads, deletes both, and passes only the answer to the agent.";

/** The sentence Ben reads after a read job's tap. */
function readDone(result: unknown): string {
  return (
    notDone(result, () => "No answer went to the agent, and no key either.") ??
    `Done. The agent gets the answer now${(result as Partial<ReadResult>).truncated ? " (the list was long, so it was cut)" : ""}; the internal keys were deleted. Nothing else to do.`
  );
}

// Exactly one param, a studio zone: anything extra is refused, not dropped.
function zoneOnly(params: unknown): Record<string, string> | null {
  const p = (params ?? {}) as { zone?: unknown };
  return params && typeof params === "object" && Object.keys(params).length === 1 && typeof p.zone === "string" && STUDIO_ZONES.includes(p.zone) ? { zone: p.zone } : null;
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
  "cf.dns.txt.probe": {
    mode: "tap",
    menu: { does: "Test: adds one harmless TXT record, checks it, removes it.", on: "one studio zone", params: "zone: a studio zone" },
    explain: (p) => ({
      does: `Cloudflare test on ${p.zone}: add one harmless TXT record, check it is there, then remove it.`,
      expect: "Face ID unlocks the vault for a moment. It makes two keys good for 5 minutes (one to find the zone, one to edit its DNS), runs the test, and deletes both keys.",
      exact: `Record: _front-desk-probe.${p.zone} (TXT)`,
    }),
    done: (r) =>
      notDone(r, (x) => {
        const p = x as unknown as Partial<ProbeResult>;
        const stuck = [p.added && !p.removed ? "the test record may still be in DNS" : "", (p.minted ?? []).some((t) => !t.deleted) ? "a 5-minute key was not deleted (it expires on its own)" : ""].filter(Boolean);
        return stuck.length ? `Left behind: ${stuck.join("; ")}.` : "Nothing was left behind.";
      }) ?? "Done. The test record was added, seen and removed, and both short keys were deleted. Nothing else to do.",
    validate: (params) => {
      const zone = (params as { zone?: unknown } | null)?.zone;
      return typeof zone === "string" && STUDIO_ZONES.includes(zone) ? { zone } : null;
    },
    vault: true,
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
    done: (r) => notDone(r, (x) => ((x as unknown as Partial<HeadcountSetupResult>).key_id ? "The nightly count keeps its previous key; the new one did not pass its checks and is deleted." : "The nightly count keeps its previous key.")) ?? "Done. The nightly count has its list-only key, and it was refused when it tried to make one. Nothing else to do.",
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
      return {
        does: `Cloudflare: tell the nightly check ${ids.length === 1 ? "this key is" : "these keys are"} yours, so it stops flagging ${ids.length === 1 ? "it" : "them"}. Nothing is made, changed or deleted in Cloudflare.`,
        sections: [{ heading: `Keys: ${ids.length}`, items: ids.map((id, i) => `${name(names[i] ?? "")} [${id}]`) }],
        warn: "If you do not recognise every key, do not approve: it may be someone else's access.",
        expect: "Face ID unlocks the vault for a moment. It checks each key is still in the account and still unexpected, then adds them to what the nightly check expects. If anything changed since this page was made, nothing is accepted and you will see why.",
      };
    },
    done: (r) =>
      notDone(r, () => "Nothing was added, so the nightly check still flags these keys.") ??
      `Done. The nightly check now expects ${((r as Partial<CfAcceptResult>).accepted?.length ?? 0) === 1 ? "this key" : "these keys"}. Nothing else to do.`,
    // The agent sends no params; the front desk adds `ids` and `names` from the vault (desk.ts request).
    validate: (params) => (params && typeof params === "object" && Object.keys(params).length === 0 ? {} : null),
    vault: true,
  },
} satisfies Record<string, Job>;

export type JobName = keyof typeof JOBS;

/** The agents' menu, generated from JOBS (served at GET /menu). Adding a job is a pull request Ben merges. */
export function menu() {
  return {
    jobs: Object.entries(JOBS as Record<string, Job>).map(([job, j]) => ({ job, mode: j.mode, ...j.menu, signed: !!j.signed })),
    modes: { tap: "Ben approves this one job with Face ID; you never hold a key.", run: "Inside a run Ben opened (not built yet).", key: "A key on the c-box (none offered)." },
    new_job: "Not on the list? Propose it as a pull request to front-desk src/jobs.ts (and vault/src/vault.ts for a vault job); it exists once Ben merges it.",
    ask: "node scripts/agent.mjs post <desk>/request '{\"job\":...,\"params\":{...},\"reason\":\"<card id>: why\"}', then node scripts/agent.mjs wait <collect-url>",
  };
}
