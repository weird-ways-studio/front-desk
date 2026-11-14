// Test-only vault Worker (card N2 5fdbf2ce, Codex build r1 #4): the REAL vault entry point (vault/src/index.ts) with
// two test seams only -- the clock (so the protected window and the 20-minute approval do not depend on when the test
// runs) and the passkey pin (a test cannot sign as Ben's phone) -- plus seed/peek of vault storage. Every outbound
// fetch goes to the test's counting fake GitHub (Miniflare outboundService). Never deployed.
import Vault, { VaultBox } from "../../vault/src/index.ts";
import { VaultLogic } from "../../vault/src/vault.ts";
import type { PasskeyPin } from "../../vault/src/passkey.ts";

let clock = Date.now();
let pin: PasskeyPin | undefined;

export class ReachBox extends VaultBox {
  setTest(t: number, p: PasskeyPin) {
    clock = t;
    pin = p;
  }
  seed(entries: [string, unknown][]) {
    this.ctx.storage.transactionSync(() => entries.forEach(([k, v]) => this.ctx.storage.kv.put(k, v)));
  }
  peek(key: string) {
    return this.ctx.storage.kv.get(key) ?? null;
  }
}
// VaultBox.logic() is private in TypeScript; the harness replaces it on the prototype (the only change in behaviour).
(ReachBox.prototype as unknown as { logic: () => VaultLogic }).logic = function (this: ReachBox) {
  return new VaultLogic((this as unknown as { ctx: DurableObjectState }).ctx.storage as never, (input, init) => fetch(input, init), () => clock, pin);
};

export default class ReachVault extends Vault {
  private harnessBox() {
    const env = (this as unknown as { env: { BOX: DurableObjectNamespace<ReachBox> } }).env;
    return env.BOX.get(env.BOX.idFromName("vault"));
  }
  setTest(t: number, p: PasskeyPin) {
    return this.harnessBox().setTest(t, p);
  }
  seed(entries: [string, unknown][]) {
    return this.harnessBox().seed(entries);
  }
  peek(key: string) {
    return this.harnessBox().peek(key);
  }
}
