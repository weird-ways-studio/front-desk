// Test helper (card N2 5fdbf2ce part A): puts a complete, fresh nightly reach read and an accepted reach list into a
// vault store, so tests of the main GitHub count (github.test.ts, ghrepo.test.ts) start from a green reach part. The
// fold-in itself is tested through real reads in test/reach.test.ts.
import type { VaultStore } from "../vault/src/vault.ts";

export function seedReach(store: Pick<VaultStore, "kv">, repoIds: string[], at: number, app = { id: 101, installation: 1010 }): void {
  const gen = {
    id: "seed", seq: 1, purpose: "night", app_id: app.id, installation_id: app.installation, inventory: [...repoIds].sort(), rev: 1,
    repos: Object.fromEntries(repoIds.map((r) => [r.split(":")[0], { hooks: [], collabs: [] }])), org_hooks: [],
    started_at: at, failed: null, complete_at: at,
  };
  store.kv.put("gh.reach.seq", 1);
  store.kv.put("gh.reach.gen", gen);
  store.kv.put("gh.reach.night", gen);
  store.kv.put("gh.reach.complete", gen);
  store.kv.put("gh.reach.baseline", { repo_hooks: [], org_hooks: [], collaborators: [] });
}
