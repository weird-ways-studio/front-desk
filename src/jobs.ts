// The fixed list of jobs an agent may ask for. Anything not listed here is
// refused at /request. A job marked `vault` runs inside the vault Worker
// (vault/src/vault.ts) at Ben's tap, with the master key his passkey unlocks.

export interface Job {
  // What Ben sees on the approval screen, built from the stored grant.
  describe(params: Record<string, string>): string;
  // Returns clean params, or null to refuse.
  validate(params: unknown): Record<string, string> | null;
  // Runs at collect. Vault jobs have no run here: they run at approval, in the vault.
  run?(params: Record<string, string>): Promise<unknown>;
  vault?: true;
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
      `Cloudflare test: add one TXT record "_front-desk-probe" to zone ${p.zone_id}, check it, then remove it. A DNS key good for 5 minutes is made for this and deleted afterwards.`,
    validate: (params) => {
      const zone = (params as { zone_id?: unknown } | null)?.zone_id;
      return typeof zone === "string" && /^[0-9a-f]{32}$/.test(zone) ? { zone_id: zone } : null;
    },
    vault: true,
  },
} satisfies Record<string, Job>;

export type JobName = keyof typeof JOBS;
