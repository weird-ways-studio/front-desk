// Test-only desk Worker (card N2 5fdbf2ce, Codex build r1 #4): the desk's real Desk in a real SQLite Durable Object,
// calling the real vault (test/workerd/reach-vault-harness.ts) over a real service binding. Counts the calls this
// Durable Object makes to the vault per command (its subrequests). Commands arrive as POST {method, args}. Never deployed.
import { DurableObject } from "cloudflare:workers";
import { Desk } from "../../src/desk.ts";
import { FakeRecorder } from "../fakerecorder.ts";
import { SoftKey } from "../softkey.ts";

// The same origin the test pins in the vault (test/vaultsign.ts TEST_ORIGIN / TEST_RP), so Ben's tap checks out there.
const site = { origin: "https://desk.example", rpID: "desk.example" };
const PRF = btoa(String.fromCharCode(...new Uint8Array(32).fill(7))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
let key: SoftKey | undefined;
// The Observatory's recorder stands in-process (another account); each send is one outside call in production.
const fr = new FakeRecorder();

type Vault = Record<string, (...a: unknown[]) => Promise<unknown>>;

export class ReachDesk extends DurableObject<{ VAULT: Vault }> {
  private counted() {
    let n = 0;
    const vault = new Proxy(this.env.VAULT, { get: (t, k) => (typeof t[k as string] === "function" ? (...a: unknown[]) => (n++, t[k as string](...a)) : t[k as string]) });
    const pushes: string[] = [];
    const sent = fr.sent.length;
    const desk = new Desk(this.ctx.storage, site, { vault: vault as never, recorder: fr.send, alert: async (title, text) => void pushes.push(`${title}|${text}`) });
    return { desk, vault, pushes, calls: () => n, recorder: () => fr.sent.length - sent };
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
  // Ben's passkey enrolled on this desk (the vault pins the same key: reach-vault-harness setTest).
  async enroll(k: { id: string; jwk: JsonWebKey }) {
    key = await SoftKey.imported(k);
    const d = this.counted().desk;
    await d.enroll(await key.register(await d.enrollOptions(Date.now()), site.origin), Date.now());
    return true;
  }
  // The agent's /request for gh.reach.baseline, through production Desk.request (preview, recorder sends).
  // `now`: the vault's test clock, so the grant's expiry and the vault's agree.
  async requestReach(now: number) {
    const c = this.counted();
    const g = await c.desk.request({ job: "gh.reach.baseline", params: {}, reason: "accept webhooks" }, "agent", now);
    return { id: g.id, desk_calls: c.calls(), recorder_sends: c.recorder() };
  }
  // Ben's tap, through production Desk.approve: API-version check, recorder sends, vault.run.
  async approveReach(id: string, now: number) {
    const c = this.counted();
    const o = await c.desk.approvalOptions(id, now);
    const r = await key!.assert(o.challenge, site.rpID, site.origin);
    const g = await c.desk.approve(id, { ...r, prf: PRF } as never, now);
    return { result: g.result, desk_calls: c.calls(), recorder_sends: c.recorder() };
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
