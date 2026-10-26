// The vault Worker. It has no web address (workers_dev false, no routes in
// vault/wrangler.jsonc); the only way in is the front desk's service binding VAULT,
// which calls the methods below over RPC. It loads no libraries -- only the runtime
// (cloudflare:workers, WebCrypto, fetch) and the files beside it. Rules: vault.ts.

import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
import { VaultLogic } from "./vault.ts";

interface Env {
  BOX: DurableObjectNamespace<VaultBox>;
}

/** One Durable Object holds the sealed master key, so setup and jobs run one at a time. */
export class VaultBox extends DurableObject<Env> {
  private logic() {
    return new VaultLogic(this.ctx.storage, (input, init) => fetch(input, init));
  }
  status() {
    return this.logic().status();
  }
  setup(prf: string, parent: string) {
    return this.logic().setup(prf, parent);
  }
  run(job: string, params: Record<string, string>, prf: string) {
    return this.logic().run(job, params, prf);
  }
}

/** What the front desk calls. Types: vault/src/api.ts. */
export default class Vault extends WorkerEntrypoint<Env> {
  async fetch(): Promise<Response> {
    return new Response("not found", { status: 404 });
  }
  private box() {
    return this.env.BOX.get(this.env.BOX.idFromName("vault"));
  }
  status() {
    return this.box().status();
  }
  setup(prf: string, parent: string) {
    return this.box().setup(prf, parent);
  }
  run(job: string, params: Record<string, string>, prf: string) {
    return this.box().run(job, params, prf);
  }
}
