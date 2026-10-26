// The fixed list of jobs an agent may ask for. Anything not listed here is
// refused at /request. PR3a ships only a test job; real Cloudflare jobs come
// with the encrypted master key (PR3b).

export interface Job {
  // What Ben sees on the approval screen, built from the stored grant.
  describe(params: Record<string, string>): string;
  // Returns clean params, or null to refuse.
  validate(params: unknown): Record<string, string> | null;
  run(params: Record<string, string>): Promise<unknown>;
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
} satisfies Record<string, Job>;

export type JobName = keyof typeof JOBS;
