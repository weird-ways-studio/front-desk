// Test-only Worker: the vault's real card book (vault/src/cards.ts) inside a real SQLite Durable Object with a real
// alarm, for test/cards.workerd.test.ts. Never deployed. The test passkey pin and recorder key arrive by a `setup`
// command and are kept in storage, so a restarted object (same persist dir) still has them. Each job takes `jobMs`
// (set by `mode`); -1 means it never answers, as when Safari closes or the desk's invocation is cancelled.
import { DurableObject } from "cloudflare:workers";
import { CardBook } from "../../vault/src/cards.ts";
import type { PasskeyPin } from "../../vault/src/passkey.ts";

let calls = 0;

export class CardsBox extends DurableObject {
  private book(): CardBook {
    const s = this.ctx.storage;
    const cfg = s.kv.get<{ pin: PasskeyPin; recorderKey: string; jobMs: number }>("harness")!;
    const runEntry = async () => {
      calls += 1;
      if (cfg.jobMs < 0) await new Promise(() => {});
      await new Promise((r) => setTimeout(r, cfg.jobMs));
      return { ok: true, data: "read" };
    };
    return new CardBook(s, runEntry, cfg.pin, { recorderKey: cfg.recorderKey });
  }
  setup(pin: PasskeyPin, recorderKey: string, jobMs: number) {
    this.ctx.storage.kv.put("harness", { pin, recorderKey, jobMs });
  }
  mode(jobMs: number) {
    this.ctx.storage.kv.put("harness", { ...this.ctx.storage.kv.get<object>("harness"), jobMs });
  }
  open(req: unknown) {
    return this.book().open(req);
  }
  run(req: unknown) {
    return this.book().run(req);
  }
  stop(card: string) {
    return this.book().stop(card);
  }
  async status(card: string) {
    return { ...this.book().status(card), calls, alarm: await this.ctx.storage.getAlarm() };
  }
  // Cloudflare's timer calls this; nothing in a request does.
  async alarm() {
    await this.book().alarm();
  }
}

export default {
  async fetch(request: Request, env: { BOX: DurableObjectNamespace<CardsBox> }) {
    const stub = env.BOX.get(env.BOX.idFromName("vault")) as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
    const cmds = (await request.json()) as { method: string; args: unknown[] }[];
    // Several commands in one request are sent at once, so they race inside the Durable Object.
    const out = await Promise.all(cmds.map((c) => stub[c.method](...c.args).then((v) => v ?? null, (e: Error) => ({ error: e.message }))));
    return Response.json(out);
  },
};
