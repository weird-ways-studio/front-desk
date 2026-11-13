// A tiny Cloudflare API client: one bearer token, one fetch. Errors become VaultError
// with the status and Cloudflare's first error message, never the token.

import { VaultError } from "./seal.ts";

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

const API = "https://api.cloudflare.com/client/v4";

type Envelope<T> = { success?: unknown; result?: T; errors?: { message?: string; code?: number }[] };

/**
 * What one tap's Cloudflare key changes did (card 139071ea R1, R8). `made` and `deleted` hold only ids Cloudflare
 * positively confirmed; `open` counts attempts that ended neither confirmed nor as a recognized refusal. One record per
 * tap, shared by every client that tap makes (the master, and the headcount key that tries the must-fail mint).
 */
export interface Effects { made: string[]; deleted: string[]; open: number }
export const newEffects = (): Effects => ({ made: [], deleted: [], open: 0 });
// The contract bound per list (R10), shared with the desk and the Observatory. One tap can confirm at most 2 creates
// and 12 deletes (OLD_HEADCOUNT_DELETES + 4), so no list is ever cut short.
export const CF_LIST_MAX = 16;
export type CfField = { made: string[]; deleted: string[] } | "unknown";

/** The `cf` an answer carries: the lists only when every attempted change resolved, else "unknown" (R8). */
export function effectsField(fx: Effects): CfField {
  if (fx.open !== 0 || fx.made.length > CF_LIST_MAX || fx.deleted.length > CF_LIST_MAX) return "unknown";
  return { made: [...fx.made], deleted: [...fx.deleted] };
}

const KEY_ID = /^[0-9a-f]{32}$/;
// A refusal Cloudflare states plainly: the request was rejected, so nothing changed (N1). A 404 closes a delete too.
const REFUSED = [400, 401, 403, 429];

export class Cloudflare {
  private token: string;
  private fetch: Fetch;
  private fx: Effects | undefined;
  constructor(token: string, fetchFn: Fetch, fx?: Effects) {
    this.token = token;
    this.fetch = fetchFn;
    this.fx = fx;
  }

  /** Calls one endpoint and returns its `result`, or throws cf_<status>. Never for a key create or delete. */
  async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const { res, json } = await this.send<T>(method, path, body);
    return this.answer(res, json ?? {});
  }

  /** Creates one key. Counted in `made` only when Cloudflare positively confirms it (R8). Throws as `call` does. */
  create<T extends { id: string; value: string }>(path: string, body: unknown): Promise<T> {
    return this.change<T>("create", "POST", path, body);
  }

  /** Deletes key `id`. Counted in `deleted` only when Cloudflare positively confirms it (R8, R2). Throws as `call` does. */
  remove(account: string, id: string): Promise<unknown> {
    return this.change("delete", "DELETE", `/accounts/${account}/tokens/${id}`, undefined, id);
  }

  private async change<T>(kind: "create" | "delete", method: string, path: string, body: unknown, id?: string): Promise<T> {
    const fx = this.fx;
    if (!fx) throw new VaultError("no_effects_record");
    fx.open++; // lowered only when this same attempt resolves; a throw below leaves it raised
    const { res, json } = await this.send<T>(method, path, body);
    if (json && res.ok && json.success === true) {
      const r = json.result as { id?: unknown; value?: unknown } | null | undefined;
      if (kind === "create" && typeof r?.id === "string" && KEY_ID.test(r.id) && r.value !== undefined) {
        fx.made.push(r.id);
        fx.open--;
      } else if (kind === "delete" && (r?.id === undefined || r.id === id)) {
        fx.deleted.push(id!);
        fx.open--;
      }
    } else if (json && json.success === false && (REFUSED.includes(res.status) || (kind === "delete" && res.status === 404))) {
      fx.open--;
    }
    return this.answer(res, json ?? {});
  }

  private async send<T>(method: string, path: string, body?: unknown): Promise<{ res: Response; json: Envelope<T> | undefined }> {
    const res = await this.fetch(API + path, {
      method,
      headers: { authorization: `Bearer ${this.token}`, ...(body ? { "content-type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const parsed: unknown = await res.json().catch(() => undefined);
    return { res, json: parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Envelope<T>) : undefined };
  }

  private answer<T>(res: Response, json: Envelope<T>): T {
    if (!res.ok || json.success === false) {
      const code = json.errors?.[0]?.code;
      // The provider's error code is kept ("cf_403[9109]: ..."), so callers can tell refusals apart.
      throw new VaultError(`cf_${res.status}${typeof code === "number" ? `[${code}]` : ""}: ${String(json.errors?.[0]?.message ?? "no message").slice(0, 100)}`);
    }
    return json.result as T;
  }
}
