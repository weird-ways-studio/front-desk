// Test-only Worker for two runtime facts the card book relies on (REFINE-85818ab1 Open facts 2-3), checked in
// real workerd by test/cardfacts.workerd.test.ts. Never deployed. `WithAlarm` stands for card-aware vault code,
// `NoAlarm` for older vault code with no alarm() handler (the change-over in the refinement's retention table).
import { DurableObject } from "cloudflare:workers";

export class WithAlarm extends DurableObject {
  async alarm() {
    await this.ctx.storage.put("fired", ((await this.ctx.storage.get<number>("fired")) ?? 0) + 1);
  }
  async cmd(method: string, args: unknown[]) {
    const s = this.ctx.storage;
    if (method === "arm") return void (await s.setAlarm(Date.now() + (args[0] as number)));
    if (method === "fired") return (await s.get("fired")) ?? 0;
    // Fact 3: a Map written by the async API (as approval.ts admit writes `used`) is read back as a Map by the
    // synchronous kv API inside transactionSync, and the other way round.
    if (method === "maps") {
      await s.put("used", new Map([["g1", 5]]));
      const viaKv = s.transactionSync(() => s.kv.get<Map<string, number>>("used"));
      s.transactionSync(() => s.kv.put("used2", new Map([["g2", 6]])));
      const viaAsync = await s.get<Map<string, number>>("used2");
      return { kv: viaKv instanceof Map ? [...viaKv] : String(viaKv), async: viaAsync instanceof Map ? [...viaAsync] : String(viaAsync) };
    }
    return null;
  }
}
export class NoAlarm extends DurableObject {
  async cmd() {
    return (await this.ctx.storage.get("fired")) ?? 0;
  }
}
export default {
  async fetch(request: Request, env: { BOX: DurableObjectNamespace }) {
    const { method, args } = (await request.json()) as { method: string; args: unknown[] };
    const stub = env.BOX.get(env.BOX.idFromName("vault")) as unknown as { cmd: (m: string, a: unknown[]) => Promise<unknown> };
    return Response.json((await stub.cmd(method, args)) ?? null);
  },
};
