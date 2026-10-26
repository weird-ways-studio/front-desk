// The front desk Worker. Cloudflare calls the default export's fetch() for every
// request (entry point set by `main` in wrangler.jsonc). All state lives in one
// Durable Object, FrontDesk, so requests are handled one at a time against one
// store -- that is what makes "approve once, collect once" hold. Routes: routes.ts.

import { DurableObject } from "cloudflare:workers";
import { route } from "./routes.ts";

export class FrontDesk extends DurableObject {
  async fetch(request: Request): Promise<Response> {
    return route(request, this.ctx.storage);
  }
}

interface Env {
  DESK: DurableObjectNamespace<FrontDesk>;
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return env.DESK.get(env.DESK.idFromName("desk")).fetch(request);
  },
};
