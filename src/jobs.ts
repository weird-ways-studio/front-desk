// The fixed list of jobs an agent may ask for. Anything not listed here is
// refused at /request. A job marked `vault` runs inside the vault Worker
// (vault/src/vault.ts) at Ben's tap, with the master key his passkey unlocks.

import { STUDIO_ZONES } from "../vault/src/zones.ts";
import { MAX_KEY_MINUTES, isIPv4 } from "../vault/src/vault.ts";
import { isP256Spki } from "./cboxkey.ts";

export interface Job {
  // What Ben sees on the approval screen, built from the stored grant.
  describe(params: Record<string, string>): string;
  // Returns clean params, or null to refuse.
  validate(params: unknown): Record<string, string> | null;
  // Runs at collect. Vault jobs have no run here: they run at approval, in the vault.
  run?(params: Record<string, string>): Promise<unknown>;
  vault?: true;
  // The front desk adds the address the request came from (set by Cloudflare, not the agent)
  // as params.ip, so Ben sees it and the key works only from there.
  pinIp?: true;
}

export const JOBS = {
  "test.echo": {
    describe: (p) => `Test only: echo the word "${p.word}". Touches nothing.`,
    validate: (params) => {
      const word = (params as { word?: unknown } | null)?.word;
      return typeof word === "string" && /^[a-z]{1,20}$/.test(word) ? { word } : null;
    },
    run: async (p) => ({ echoed: p.word }),
  },
  "cf.dns.txt.probe": {
    describe: (p) =>
      `Cloudflare test: add one TXT record "_front-desk-probe.${p.zone}", check it, then remove it. Two keys good for 5 minutes are made for this (find the zone; edit its DNS) and deleted afterwards.`,
    validate: (params) => {
      const zone = (params as { zone?: unknown } | null)?.zone;
      return typeof zone === "string" && STUDIO_ZONES.includes(zone) ? { zone } : null;
    },
    vault: true,
  },
  // Ben's approval stores the key (Desk.enrollCboxKey); the front desk adds fingerprint and replaces.
  "cbox.key.enroll": {
    describe: (p) =>
      `Enroll the c-box signing key with fingerprint ${p.fingerprint}${p.replaces === "none" ? "" : `, REPLACING key ${p.replaces}`}. Requests signed with it count as coming from the c-box. Only approve if the agent just showed you this same fingerprint in chat. A request you did not expect may mean the agent's login was stolen.`,
    validate: (params) => {
      const key = (params as { key?: unknown } | null)?.key;
      return isP256Spki(key) ? ({ key } as Record<string, string>) : null;
    },
    run: async (p) => ({ enrolled: p.fingerprint }),
  },
  "cf.token.zone.read": {
    describe: (p) =>
      `TEST key for the agent: it can read only the basic details of zone "${p.zone}" (name, status, plan) -- not its DNS, not its settings, and it can change nothing. It expires after ${p.minutes} minutes and works only from the c-box (${p.ip}). Given to the agent once.`,
    validate: (params) => {
      const { zone, minutes, ip } = (params ?? {}) as { zone?: unknown; minutes?: unknown; ip?: unknown };
      const okMinutes = typeof minutes === "string" && /^[1-9]\d?$/.test(minutes) && Number(minutes) <= MAX_KEY_MINUTES;
      return typeof zone === "string" && STUDIO_ZONES.includes(zone) && okMinutes && isIPv4(ip) ? { zone, minutes, ip: ip as string } : null;
    },
    vault: true,
    pinIp: true,
  },
} satisfies Record<string, Job>;

export type JobName = keyof typeof JOBS;
