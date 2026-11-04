// The vault Worker. Two ways in, both declared in vault/wrangler.jsonc:
// - RPC from the front desk's service binding VAULT (methods on the default export below);
// - its own workers.dev address, behind the account-wide Cloudflare Access login, which serves
//   only the one-time setup page (setup.ts) and answers 404 once a key is stored.
// It loads no libraries -- only the runtime (cloudflare:workers, WebCrypto, fetch) and the files
// beside it. Rules: vault.ts.

import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
import { emailOf, handleSetup } from "./setup.ts";
import { VaultLogic } from "./vault.ts";
import { RUN_API_VERSION, RunBook, type OpRequest } from "./runs.ts";

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
  headcount() {
    return this.logic().headcount();
  }
  ghPreview() {
    return this.logic().ghPreview();
  }
  cfPreview() {
    return this.logic().cfPreview();
  }
  // Runs (card ae6147e4 4a-2a; rules in runs.ts). No desk route calls these until 4a-2b, and no run can be
  // opened until 4a-3, so in production every op refuses unknown_run.
  private runs() {
    return new RunBook(this.ctx.storage, (input, init) => fetch(input, init));
  }
  runOp(req: OpRequest) {
    return this.runs().op(req);
  }
  runEnd(id: string, how: "stopped" | "finished") {
    return this.runs().endRun(id, how);
  }
  runStatus(id: string) {
    return this.runs().status(id);
  }
  setKeyRev(rev: number) {
    return this.runs().setKeyRev(rev);
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
  // The nightly count, called by the front desk's cron (../../src/index.ts scheduled). No tap; reads only.
  headcount() {
    return this.box().headcount();
  }
  // What job gh.app.baseline would accept, for Ben's approval screen (called at /request). Reads only.
  ghPreview() {
    return this.box().ghPreview();
  }
  // What job cf.token.accept would accept, for Ben's approval screen (called at /request). Reads only.
  cfPreview() {
    return this.box().cfPreview();
  }
  // Runs (4a-2a). The desk checks runApi() first and refuses `vault_not_ready` on a vault without it (D9).
  runApi() {
    return { version: RUN_API_VERSION };
  }
  runOp(req: OpRequest) {
    return this.box().runOp(req);
  }
  runEnd(id: string, how: "stopped" | "finished") {
    return this.box().runEnd(id, how);
  }
  runStatus(id: string) {
    return this.box().runStatus(id);
  }
  // Called by the desk whenever the c-box key is removed or replaced, before it acknowledges the change (D3).
  setKeyRev(rev: number) {
    return this.box().setKeyRev(rev);
  }
}
