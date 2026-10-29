// The fixed list of jobs an agent may ask for. Anything not listed here is
// refused at /request. A job marked `vault` runs inside the vault Worker
// (vault/src/vault.ts) at Ben's tap, with the master key his passkey unlocks.

import { STUDIO_ZONES } from "../vault/src/zones.ts";
import { MAX_KEY_MINUTES, isIPv4 } from "../vault/src/vault.ts";
import { isP256Spki } from "./cboxkey.ts";
import { baselineDone, plainChanges } from "./ghplain.ts";
import type { GhBaselineResult } from "../vault/src/api.ts";

// What Ben reads on the approval screen, built from the stored grant (instruction.orient-the-person):
// what approving does, anything to check, what happens when he taps, and the exact text folded below.
export interface Guide {
  does: string;
  sections?: { heading: string; items: string[] }[];
  warn?: string;
  expect: string;
  exact?: string;
}

export interface Job {
  explain(params: Record<string, string>): Guide;
  // The sentence Ben reads after his tap. `result` is undefined for a job that runs when the agent collects.
  done(result: unknown): string;
  // Returns clean params, or null to refuse.
  validate(params: unknown): Record<string, string> | null;
  // Runs at collect. Vault jobs have no run here: they run at approval, in the vault.
  run?(params: Record<string, string>): Promise<unknown>;
  vault?: true;
  // The front desk adds the address the request came from (set by Cloudflare, not the agent)
  // as params.ip, so Ben sees it and the key works only from there.
  pinIp?: true;
}

// A failed vault job in words. The vault's own reason stays, in brackets, for the agent.
function notDone(result: unknown): string | null {
  const r = result as { ok?: unknown; error?: unknown } | null | undefined;
  if (r === undefined) return "Not done: the vault sent no result, so nothing is confirmed. Tell the agent: [no result]";
  if (r && r.ok === true) return null;
  const why = r && typeof r.error === "string" ? r.error : "a check did not pass";
  return `Not done: nothing was handed over or accepted. Send the agent the words in brackets so it can fix it: [${why}]`;
}

const ONE_STANDING_KEY = "This is a new standing key, by your choice.";

export const JOBS = {
  "test.echo": {
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
    explain: (p) => ({
      does: `Cloudflare test on ${p.zone}: add one harmless TXT record, check it is there, then remove it.`,
      expect: "Face ID unlocks the vault for a moment. It makes two keys good for 5 minutes (one to find the zone, one to edit its DNS), runs the test, and deletes both keys.",
      exact: `Record: _front-desk-probe.${p.zone} (TXT)`,
    }),
    done: (r) => notDone(r) ?? "Done. The test record was added, seen and removed, and both short keys were deleted. Nothing else to do.",
    validate: (params) => {
      const zone = (params as { zone?: unknown } | null)?.zone;
      return typeof zone === "string" && STUDIO_ZONES.includes(zone) ? { zone } : null;
    },
    vault: true,
  },
  // Ben's approval stores the key (Desk.enrollCboxKey); the front desk adds fingerprint and replaces.
  "cbox.key.enroll": {
    explain: (p) => ({
      does: `Trust a new c-box signing key${p.replaces === "none" ? "" : ", REPLACING the current one"}. Requests signed with it count as coming from the c-box.`,
      warn: "Only approve if the agent just showed you this same fingerprint in chat. A request you did not expect may mean the agent's login was stolen.",
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
  "cf.token.zone.read": {
    explain: (p) => ({
      does: `TEST key for the agent: it can read only the basic details of ${p.zone} (name, status, plan). Not its DNS, not its settings, and it can change nothing.`,
      expect: `Face ID unlocks the vault for a moment. It makes the key, checks it is refused from anywhere but the c-box, and hands it to the agent once. The key dies after ${p.minutes} minutes.`,
      exact: `Zone ${p.zone}; ${p.minutes} minutes; works only from ${p.ip}`,
    }),
    done: (r) => notDone(r) ?? "Done. The agent gets the key once; it expires on its own. Nothing else to do.",
    validate: (params) => {
      const { zone, minutes, ip } = (params ?? {}) as { zone?: unknown; minutes?: unknown; ip?: unknown };
      const okMinutes = typeof minutes === "string" && /^[1-9]\d?$/.test(minutes) && Number(minutes) <= MAX_KEY_MINUTES;
      return typeof zone === "string" && STUDIO_ZONES.includes(zone) && okMinutes && isIPv4(ip) ? { zone, minutes, ip: ip as string } : null;
    },
    vault: true,
    pinIp: true,
  },
  // The vault mints the nightly headcount's own key (vault/src/vault.ts setupHeadcount). Card C5c-2.
  "cf.token.headcount.setup": {
    explain: () => ({
      does: `Make the nightly headcount key: it can LIST the names of every Cloudflare key in the studio account, and nothing else. It cannot make, change or delete keys, and cannot read their secrets. ${ONE_STANDING_KEY}`,
      expect: "Face ID unlocks the vault for a moment. It makes the key, checks it is refused when it tries to make a key, and keeps it inside the vault for the nightly count. Running this again replaces it.",
    }),
    done: (r) => notDone(r) ?? "Done. The nightly count has its list-only key, and it was refused when it tried to make one. Nothing else to do.",
    validate: (params) => (params && typeof params === "object" && Object.keys(params).length === 0 ? {} : null),
    vault: true,
  },
  // The vault locks the GitHub App key and records the nightly count's expected list (vault/src/vault.ts ghBaseline). Card C6a-1.
  "gh.app.baseline": {
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
    done: (r) => notDone(r) ?? baselineDone(r as GhBaselineResult),
    // The agent sends no params; the front desk adds `changes` and `snapshot` from the vault (desk.ts request).
    validate: (params) => (params && typeof params === "object" && Object.keys(params).length === 0 ? {} : null),
    vault: true,
  },
} satisfies Record<string, Job>;

export type JobName = keyof typeof JOBS;
