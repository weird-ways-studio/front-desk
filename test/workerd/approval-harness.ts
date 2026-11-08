// Test-only Worker (card bb86abf0): the vault's real run() -- passkey check plus the one admission step --
// inside a real SQLite Durable Object, so the once-only race and restart proofs run on workerd's own storage.
// Never deployed: bundled by test/approval.workerd.test.ts into a temp dir and loaded into Miniflare.
// Commands arrive as POST [{method, args}]; several in one request run at once.
import { DurableObject } from "cloudflare:workers";
import { VaultLogic } from "../../vault/src/vault.ts";
import type { PasskeyPin } from "../../vault/src/passkey.ts";

let calls = 0; // Cloudflare calls this isolate made (none expected: the harness vault holds no key)
let clock = 0; // the vault's clock, read when it asks (setClock); 0 = use the time passed to run()
// A pause inside the vault's signature check (Codex build r1 #2): the next crypto.subtle.verify waits here.
let gate: { release: () => void; inside: boolean } | null = null;

export class HarnessBox extends DurableObject {
  run(req: unknown, pin: PasskeyPin, now: number) {
    const vault = new VaultLogic(this.ctx.storage, async () => (calls++, Response.json({ success: false })), () => clock || now, pin);
    return vault.run(req);
  }
  setClock(t: number) {
    clock = t;
  }
  pauseNextVerify() {
    const original = crypto.subtle.verify;
    let release!: () => void;
    const open = new Promise<void>((r) => (release = r));
    gate = { release, inside: false };
    const g = gate;
    crypto.subtle.verify = (async (...args: Parameters<SubtleCrypto["verify"]>) => {
      crypto.subtle.verify = original;
      g.inside = true;
      await open;
      return original.apply(crypto.subtle, args);
    }) as SubtleCrypto["verify"];
  }
  paused() {
    return gate?.inside === true;
  }
  release() {
    gate?.release();
  }
  async used() {
    const m = await this.ctx.storage.get<Map<string, number>>("used");
    return { ids: m ? [...m.keys()] : [], calls };
  }
}

export default {
  async fetch(request: Request, env: { BOX: DurableObjectNamespace<HarnessBox> }) {
    const stub = env.BOX.get(env.BOX.idFromName("vault")) as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
    const cmds = (await request.json()) as { method: string; args: unknown[] }[];
    return Response.json(await Promise.all(cmds.map((c) => stub[c.method](...c.args).then((r) => ({ ok: r }), (e: Error) => ({ error: String(e.message) })))));
  },
};
