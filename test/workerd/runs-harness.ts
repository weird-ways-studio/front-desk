// Test-only Worker: the vault's real run book (vault/src/runs.ts) inside a real SQLite Durable Object, so the
// race, rollback and restart proofs run on workerd's own transactionSync (D5). Never deployed: bundled by
// test/runs.workerd.test.ts into a temp dir and loaded into Miniflare. Commands arrive as POST {method, args}.
import { DurableObject } from "cloudflare:workers";
import { RunBook, type RunStore } from "../../vault/src/runs.ts";

let calls = 0; // provider calls this isolate made

export class HarnessBox extends DurableObject {
  private faultOn = "";
  private book(): RunBook {
    const real = this.ctx.storage;
    const store: RunStore = {
      transactionSync: (fn) => real.transactionSync(fn),
      kv: {
        get: (k) => real.kv.get(k),
        list: (o) => real.kv.list(o),
        put: (k, v) => {
          if (this.faultOn && k.startsWith(this.faultOn)) {
            this.faultOn = "";
            throw new Error("injected storage fault");
          }
          real.kv.put(k, v);
        },
      },
    };
    const fakeCloudflare = async () => {
      calls += 1;
      await new Promise((r) => setTimeout(r, 30)); // the call is out long enough for the other request to run
      return Response.json({ success: true, result: { id: "zone", name: "benculbert.com" } });
    };
    return new RunBook(store, fakeCloudflare);
  }
  seed(run: unknown, rev: number) {
    this.ctx.storage.kv.put("run:R1", run);
    this.ctx.storage.kv.put("runkey:R1", { id: "rk1", value: "harness-key" });
    this.ctx.storage.kv.put("cbox_rev", rev);
  }
  fault(prefix: string) {
    this.faultOn = prefix;
  }
  op(req: never) {
    return this.book().op(req);
  }
  // The reply is lost after the release committed: the run book finishes, then the RPC reply fails on the way
  // back to the caller (as a dropped connection would). Nothing of the answer may reach the caller.
  async opReplyLost(req: never) {
    await this.book().op(req);
    throw new Error("reply lost");
  }
  status() {
    return { ...this.book().status("R1"), calls, intents: [...this.ctx.storage.kv.list({ prefix: "intent:" })].length };
  }
}

export default {
  async fetch(request: Request, env: { BOX: DurableObjectNamespace<HarnessBox> }) {
    const stub = env.BOX.get(env.BOX.idFromName("vault")) as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
    const cmds = (await request.json()) as { method: string; args: unknown[] }[];
    // Several commands in one request are sent at once, so they race inside the Durable Object.
    // A failed call comes back as { error } only: whatever it was carrying is gone, as on a real lost reply.
    return Response.json(await Promise.all(cmds.map((c) => stub[c.method](...c.args).catch((e: Error) => ({ error: String(e.message) })))));
  },
};
