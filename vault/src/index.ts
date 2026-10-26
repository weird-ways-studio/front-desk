// The vault Worker. Two ways in, both declared in vault/wrangler.jsonc:
// - RPC from the front desk's service binding VAULT (methods on the default export below);
// - its own workers.dev address, behind the account-wide Cloudflare Access login, which serves
//   only the one-time setup page (setup.ts) and answers 404 once a key is stored.
// It loads no libraries -- only the runtime (cloudflare:workers, WebCrypto, fetch) and the files
// beside it. Rules: vault.ts.

import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
import { emailOf, handleSetup } from "./setup.ts";
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
  // The caller's email is worked out by the Worker from ctx.access and passed in (never a header).
  page(request: Request, email: string) {
    return handleSetup(request, this.logic(), email);
  }
  run(job: string, params: Record<string, string>, prf: string) {
    return this.logic().run(job, params, prf);
  }
}

/** What the front desk calls (types: vault/src/api.ts), plus the setup page. */
export default class Vault extends WorkerEntrypoint<Env> {
  async fetch(request: Request): Promise<Response> {
    return this.box().page(request, await emailOf(this.ctx.access));
  }
  private box() {
    return this.env.BOX.get(this.env.BOX.idFromName("vault"));
  }
  status() {
    return this.box().status();
  }
  run(job: string, params: Record<string, string>, prf: string) {
    return this.box().run(job, params, prf);
  }
}
