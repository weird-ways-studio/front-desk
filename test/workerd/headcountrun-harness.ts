// Test-only Worker for card build 5 6ab972c8: the headcount runs on real Durable Object storage (prefix list,
// delete, order, persistence), read through the real route. Never deployed. Driven by
// test/headcountrun.workerd.test.ts.
import { DurableObject } from "cloudflare:workers";
import { Desk } from "../../src/desk.ts";
import { route } from "../../src/routes.ts";
import type { Headcount } from "../../vault/src/api.ts";

const clean: Headcount = { ok: true, tokens: 4, unexpected: [], stretched: [], missing: [], cleanup: [], github: { ok: true, changes: [] } };

export class Box extends DurableObject {
  async cmd(method: string, args: unknown[]) {
    const store = this.ctx.storage;
    if (method === "runs") {
      // args: [first start ms, count, hours apart]
      const [start, n, hours] = args as number[];
      const vault = { headcount: async () => clean } as never;
      for (let i = 0; i < n; i++) {
        const t = start + i * hours * 3600_000;
        await new Desk(store, { origin: "", rpID: "" }, { vault }).headcount(async () => {}, t, () => t + 1000);
      }
      return null;
    }
    if (method === "get") {
      const res = await route(new Request("https://desk.example/headcount"), store, { caller: args[0] as "agent" | "owner" | "unknown", requester: "cbox" }, Date.now());
      return { status: res.status, body: await res.json() };
    }
    return null;
  }
}
export default {
  async fetch(request: Request, env: { BOX: DurableObjectNamespace }) {
    const { method, args } = (await request.json()) as { method: string; args: unknown[] };
    const stub = env.BOX.get(env.BOX.idFromName("desk")) as unknown as { cmd: (m: string, a: unknown[]) => Promise<unknown> };
    return Response.json((await stub.cmd(method, args)) ?? null);
  },
};
