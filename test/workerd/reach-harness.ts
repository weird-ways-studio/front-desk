// Test-only desk Worker (card N2 5fdbf2ce, Codex build r1 #4): the desk's real Desk in a real SQLite Durable Object,
// calling the real vault (test/workerd/reach-vault-harness.ts) over a real service binding. Counts the calls this
// Durable Object makes to the vault per command (its subrequests). Commands arrive as POST {method, args}. Never deployed.
import { DurableObject } from "cloudflare:workers";
import { Desk } from "../../src/desk.ts";

type Vault = Record<string, (...a: unknown[]) => Promise<unknown>>;

export class ReachDesk extends DurableObject<{ VAULT: Vault }> {
  private counted() {
    let n = 0;
    const vault = new Proxy(this.env.VAULT, { get: (t, k) => (typeof t[k as string] === "function" ? (...a: unknown[]) => (n++, t[k as string](...a)) : t[k as string]) });
    const pushes: string[] = [];
    const desk = new Desk(this.ctx.storage, { origin: "", rpID: "" }, { vault: vault as never, alert: async (title, text) => void pushes.push(`${title}|${text}`) });
    return { desk, vault, pushes, calls: () => n };
  }
  async step(purpose?: "demand") {
    const c = this.counted();
    const progress = await c.desk.reachStep(purpose, Date.now());
    return { progress, desk_calls: c.calls(), pushes: c.pushes };
  }
  async night() {
    const c = this.counted();
    await c.desk.reachNight(Date.now());
    return { desk_calls: c.calls(), pushes: c.pushes };
  }
  async tap(req: unknown) {
    const c = this.counted();
    const result = await c.vault.run(req);
    return { result, desk_calls: c.calls() };
  }
  async log() {
    return [...(await this.ctx.storage.list<{ event: string; detail?: string }>({ prefix: "log:" })).values()].map((l) => `${l.event}: ${l.detail ?? ""}`);
  }
  vault(method: string, args: unknown[]) {
    return this.env.VAULT[method](...args);
  }
}

export default {
  async fetch(request: Request, env: { DESK: DurableObjectNamespace<ReachDesk> }) {
    const { method, args } = (await request.json()) as { method: string; args: unknown[] };
    const stub = env.DESK.get(env.DESK.idFromName("desk")) as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
    try {
      return Response.json({ ok: (await stub[method](...args)) ?? null });
    } catch (e) {
      return Response.json({ error: String((e as Error).message) });
    }
  },
};
