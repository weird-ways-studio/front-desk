// The fixed list of jobs an agent may ask for. Anything not listed here is
// refused at /request. A job marked `vault` runs inside the vault Worker
// (vault/src/vault.ts) at Ben's tap, with the master key his passkey unlocks.

import { STUDIO_ZONES } from "../vault/src/zones.ts";
import { MAX_KEY_MINUTES, isIPv4 } from "../vault/src/vault.ts";

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
  "cf.token.zone.read": {
    describe: (p) =>
      `Cloudflare key for the agent: read-only on zone "${p.zone}" (it can look at settings and DNS, change nothing). It expires after ${p.minutes} minutes and works only from ${p.ip}, the address that asked. Given to the agent once.`,
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
