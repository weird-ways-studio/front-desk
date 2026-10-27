// A tiny Cloudflare API client: one bearer token, one fetch. Errors become VaultError
// with the status and Cloudflare's first error message, never the token.

import { VaultError } from "./seal.ts";

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

const API = "https://api.cloudflare.com/client/v4";

export class Cloudflare {
  private token: string;
  private fetch: Fetch;
  constructor(token: string, fetchFn: Fetch) {
    this.token = token;
    this.fetch = fetchFn;
  }

  /** Calls one endpoint and returns its `result`, or throws cf_<status>. */
  async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.fetch(API + path, {
      method,
      headers: { authorization: `Bearer ${this.token}`, ...(body ? { "content-type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const json = (await res.json().catch(() => ({}))) as { success?: boolean; result?: T; errors?: { message?: string; code?: number }[] };
    if (!res.ok || json.success === false) {
      const code = json.errors?.[0]?.code;
      // The provider's error code is kept ("cf_403[9109]: ..."), so callers can tell refusals apart.
      throw new VaultError(`cf_${res.status}${typeof code === "number" ? `[${code}]` : ""}: ${String(json.errors?.[0]?.message ?? "no message").slice(0, 100)}`);
    }
    return json.result as T;
  }
}
