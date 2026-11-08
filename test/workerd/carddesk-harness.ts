// Test-only Worker (card 85818ab1, Codex build r1 R6): the desk's real CardDesk (src/carddesk.ts) inside a real
// SQLite Durable Object, driving the REAL vault entry point (vault/src/index.ts, bundled with only its passkey pin
// and recorder key swapped for test ones) over a real service binding. Never deployed. The recorder is the
// in-memory FakeRecorder signing real receipt/v1 receipts with the test recorder key, since the Observatory is
// another account. Commands arrive as POST [{method, args}]; several in one request run at once.
import { DurableObject } from "cloudflare:workers";
import { CardDesk } from "../../src/carddesk.ts";
import { receiptSealed, type Receipt } from "../../vault/src/cardcopy.ts";
import type { DeskHooks } from "../../src/desk.ts";
import { FakeRecorder } from "../fakerecorder.ts";
import { SoftKey } from "../softkey.ts";

const site = { origin: "https://desk.example", rpID: "desk.example" };
const signed = { checkSignature: async () => {} };
const PRF = btoa(String.fromCharCode(...new Uint8Array(32).fill(7))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64 = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b)));
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");

// Kept per isolate: the key, the recorder and the test switches (a restart is not part of these tests).
let key: SoftKey | undefined;
const fr = new FakeRecorder();
let gate: { stage: string; nth: number; seen: number; inside: boolean; release: () => void; open: Promise<void> } | null = null;
let loseRun = 0; // the next N cardRun calls complete in the vault, then the desk sees "network connection lost"

export class HarnessDesk extends DurableObject<{ VAULT: NonNullable<DeskHooks["vault"]> }> {
  private desk(): CardDesk {
    const real = this.env.VAULT;
    // A thin pass-through: every call crosses the real binding. Only `loseRun` drops a reply after the vault answered.
    const vault = new Proxy(real, {
      get: (t, name) => {
        const f = (t as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>)[name as string];
        if (name !== "cardRun") return f;
        return async (...a: unknown[]) => {
          const out = await f(...a);
          if (loseRun > 0) {
            loseRun--;
            throw new Error("network connection lost");
          }
          return out;
        };
      },
    });
    const recorder = async (record: Parameters<FakeRecorder["send"]>[0], body?: string) => {
      if (gate && record.stage === gate.stage && ++gate.seen === gate.nth) {
        gate.inside = true;
        await gate.open;
      }
      return fr.send(record, body);
    };
    return new CardDesk(this.ctx.storage, site, { vault, recorder });
  }
  async setup(k: { id: string; jwk: JsonWebKey }, recorderJwk: JsonWebKey) {
    key = await SoftKey.imported(k);
    // Node labels an Ed25519 JWK alg "Ed25519"; workerd wants "EdDSA" or none, so the label is dropped.
    const { alg: _alg, ...jwk } = recorderJwk;
    const priv = await crypto.subtle.importKey("jwk", jwk, "Ed25519", false, ["sign"]);
    let seq = 0;
    fr.signer = {
      async receipt(grant: string, stage: string, body: string) {
        seq += 1;
        const r = { v: 1 as const, seq, key: `records/v1/${String(seq).padStart(12, "0")}.${grant}.${stage}.json`, grant, stage, sha256: hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body))), recorded_at: new Date().toISOString() } as Receipt;
        return { ...r, sig: b64(await crypto.subtle.sign("Ed25519", priv, receiptSealed(r))) };
      },
    };
    const d = this.desk();
    await d.enroll(await key.register(await d.enrollOptions(Date.now()), site.origin), Date.now());
    return true;
  }
  async request(entries: unknown, requester = "agent") {
    return (await this.desk().requestCard({ entries }, requester, Date.now(), signed)).card;
  }
  async tap(id: string) {
    const d = this.desk();
    const o = await d.cardOptions(id, Date.now());
    const r = await key!.assert(o.challenge, site.rpID, site.origin);
    return d.approveCard(id, { ...r, prf: PRF } as never, Date.now());
  }
  stop(id: string) {
    return this.desk().stopCard(id, Date.now());
  }
  collect(id: string, requester = "agent") {
    return this.desk().collectCard(id, requester, Date.now(), signed);
  }
  // The vault's own view, straight over the binding.
  vaultStatus(id: string) {
    return this.env.VAULT.cardStatus!(id);
  }
  pause(stage: string, nth: number) {
    let release!: () => void;
    const open = new Promise<void>((r) => (release = r));
    gate = { stage, nth, seen: 0, inside: false, release, open };
  }
  paused() {
    return gate?.inside === true;
  }
  release() {
    gate?.release();
    gate = null;
  }
  loseNextRun(n = 1) {
    loseRun = n;
  }
  async putKey() {
    await this.ctx.storage.put("cbox:key", { spki: "x", fingerprint: "aaaa-bbbb-cccc-dddd", enrolled_at: Date.now(), grant_id: "g0" });
  }
  removeKey() {
    return this.desk().removeCboxKey(Date.now());
  }
  async events() {
    return [...(await this.ctx.storage.list<{ event: string; detail?: string }>({ prefix: "log:" })).values()].map((l) => `${l.event}${l.detail ? `: ${l.detail}` : ""}`);
  }
  stages() {
    return fr.records.map((r) => `${r.grant}:${r.stage}`);
  }
}

export default {
  async fetch(request: Request, env: { DESK: DurableObjectNamespace<HarnessDesk> }) {
    const stub = env.DESK.get(env.DESK.idFromName("desk")) as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
    const cmds = (await request.json()) as { method: string; args: unknown[] }[];
    return Response.json(await Promise.all(cmds.map((c) => stub[c.method](...c.args).then((r) => ({ ok: r ?? null }), (e: Error) => ({ error: String(e.message) })))));
  },
};
