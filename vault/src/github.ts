// A tiny GitHub client for the vault: signs in as a GitHub App with WebCrypto (no libraries),
// mints installation keys, and lists who and what can reach the organization (the nightly count).
// Errors become VaultError with the status and GitHub's message, never a key.
// Permission names and endpoints: VERIFIED 2026-10-28 against docs.github.com
// "Permissions required for GitHub Apps" (card C6a 8c48215f).

import { VaultError, b64url } from "./seal.ts";
import type { Fetch } from "./cloudflare.ts";

export const ORG = "weird-ways-studio";
const API = "https://api.github.com";
const enc = new TextEncoder();

// What each App may do. The headcount App only reads; its key is kept unsealed for the nightly run.
// The main App's key is sealed to Ben's passkey; its jobs come in C6a-2.
export const PERMISSIONS = {
  headcount: { organization_administration: "read", members: "read", organization_personal_access_tokens: "read", administration: "read", metadata: "read" },
  main: { administration: "write", contents: "write", metadata: "read" },
} as const;
export type AppKind = keyof typeof PERMISSIONS;

/** The manifest GitHub registers the App from (manifest flow); `origin` is the vault's own address. */
export function manifest(kind: AppKind, origin: string): string {
  return JSON.stringify({
    name: kind === "main" ? "WWS front desk" : "WWS front desk headcount",
    url: `https://github.com/${ORG}`,
    // No webhooks: GitHub requires a URL when hook_attributes is given, so it is set but switched off.
    hook_attributes: { url: `${origin}/github/hook`, active: false },
    redirect_url: `${origin}/github/created/${kind}`,
    setup_url: `${origin}/github/installed/${kind}`,
    public: false,
    default_permissions: PERMISSIONS[kind],
    default_events: [],
  });
}

// --- The App's key. GitHub hands out PKCS#1 (the PEM form labelled "RSA"); WebCrypto imports
// only PKCS#8, which is the same key wrapped with the RSA algorithm name. ---

const der = (tag: number, body: number[]): number[] => {
  const n = body.length;
  const len = n < 128 ? [n] : n < 256 ? [0x81, n] : n < 65536 ? [0x82, n >> 8, n & 255] : [0x83, n >> 16, (n >> 8) & 255, n & 255];
  return [tag, ...len, ...body];
};
// AlgorithmIdentifier { rsaEncryption 1.2.840.113549.1.1.1, NULL }
const RSA_ALG = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
const PEM = /-----BEGIN (RSA )?PRIVATE KEY-----([A-Za-z0-9+/=\s]+)-----END (RSA )?PRIVATE KEY-----/;

/** Turns GitHub's PEM into PKCS#8 bytes (base64url) the vault stores, or refuses. */
export function pkcs8FromPem(pem: unknown): string {
  const m = typeof pem === "string" ? pem.match(PEM) : null;
  if (!m) throw new VaultError("bad_app_key");
  const raw = [...atob(m[2].replace(/\s+/g, ""))].map((c) => c.charCodeAt(0));
  const bytes = m[1] ? der(0x30, [0x02, 0x01, 0x00, ...RSA_ALG, ...der(0x04, raw)]) : raw;
  return b64url(Uint8Array.from(bytes));
}

/** A 9-minute App sign-in (JWT, RS256), as GitHub asks: issued 60 s back for clock drift, at most 10 minutes. */
export async function appJwt(appId: number, pkcs8: string, now: number): Promise<string> {
  const bytes = Uint8Array.from(atob(pkcs8.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("pkcs8", bytes, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  } catch {
    throw new VaultError("bad_app_key");
  }
  const s = Math.floor(now / 1000);
  const part = (o: unknown) => b64url(enc.encode(JSON.stringify(o)));
  const body = `${part({ alg: "RS256", typ: "JWT" })}.${part({ iat: s - 60, exp: s + 540, iss: String(appId) })}`;
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(body));
  return `${body}.${b64url(new Uint8Array(sig))}`;
}

export class GitHub {
  private auth: string;
  private fetch: Fetch;
  constructor(auth: string, fetchFn: Fetch) {
    this.auth = auth;
    this.fetch = fetchFn;
  }

  /** Calls one endpoint and returns its JSON, or throws gh_<status>: <message>. */
  async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.fetch(API + path, {
      method,
      headers: {
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        // GitHub refuses API calls without a User-Agent.
        "user-agent": "front-desk-vault",
        ...(this.auth ? { authorization: `Bearer ${this.auth}` } : {}),
        ...(body ? { "content-type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const json = (await res.json().catch(() => ({}))) as { message?: string };
    if (!res.ok) throw new VaultError(`gh_${res.status}: ${String(json.message ?? "no message").slice(0, 100)}`);
    return json as T;
  }
}

const LEVEL: Record<string, number> = { read: 1, write: 2, admin: 3 };

/** Refuses unless every permission GitHub reports is in `allowed` at the same or a lower level. */
export function checkPermissions(reported: unknown, allowed: Record<string, string>, what: string): void {
  const extra = Object.entries((reported ?? {}) as Record<string, string>).filter(([k, v]) => !allowed[k] || !(LEVEL[v] <= LEVEL[allowed[k]]));
  if (extra.length) throw new VaultError(`${what}_permissions_too_wide: ${extra.map(([k, v]) => `${k}=${v}`).join(",").slice(0, 80)}`);
}

/** The App as GitHub registered it: refused if its permissions are wider than the kind allows (Codex C6a-1 r1 #1). */
export async function checkApp(app: GitHub, kind: AppKind): Promise<void> {
  const me = await app.call<{ permissions?: unknown }>("GET", "/app");
  checkPermissions(me.permissions, PERMISSIONS[kind], "app");
}

/** Trades the one-hour code from GitHub's redirect for the new App (no sign-in needed; the code is the proof). */
export async function convert(code: string, fetchFn: Fetch): Promise<{ id: number; slug: string; pem: string }> {
  if (!/^[A-Za-z0-9]{10,64}$/.test(code)) throw new VaultError("bad_code");
  const app = await new GitHub("", fetchFn).call<{ id?: unknown; slug?: unknown; pem?: unknown; owner?: { login?: unknown } }>("POST", `/app-manifests/${code}/conversions`);
  if (typeof app.id !== "number" || typeof app.slug !== "string" || typeof app.pem !== "string") throw new VaultError("bad_conversion");
  if (app.owner?.login !== ORG) throw new VaultError("app_not_in_org");
  return { id: app.id, slug: app.slug, pem: app.pem };
}

/** The App's installation in the org, checked through the App's own sign-in: on all repositories, nowhere else. */
// Run at install and again before every headcount read, so the watcher cannot lose sight of a repo
// or gain power without the count failing (Codex C6a-1 r1 #1, #3).
export async function checkInstallation(app: GitHub, installationId: number, kind: AppKind): Promise<void> {
  const inst = await app.call<{ account?: { login?: string }; repository_selection?: string; permissions?: unknown }>("GET", `/app/installations/${installationId}`);
  if (inst.account?.login !== ORG) throw new VaultError("installation_not_in_org");
  if (inst.repository_selection !== "all") throw new VaultError("installation_not_all_repositories");
  checkPermissions(inst.permissions, PERMISSIONS[kind], "installation");
  const all = await app.call<{ id: number }[]>("GET", "/app/installations");
  if (all.length !== 1) throw new VaultError("app_installed_elsewhere");
}

/** A one-hour installation key, optionally narrowed; GitHub refuses permissions the App lacks. */
export function installationKey(app: GitHub, installationId: number, narrow?: { permissions?: Record<string, string>; repositories?: string[] }) {
  return app.call<{ token: string; expires_at: string }>("POST", `/app/installations/${installationId}/access_tokens`, narrow);
}

// What can reach the org, as names and ids only (no secrets). Each list is one page of 100; a full
// page fails closed rather than counting half (the org has 2 members and 23 repos today).
export interface GhSnapshot {
  repos: string[]; // "name:private|public" -- a repo leaving the watcher's view shows here
  members: string[];
  outside: string[];
  invites: string[];
  apps: string[]; // installed Apps, "slug#installation id:repository selection:permissions"
  pats: string[]; // fine-grained tokens with org access, "owner:id"
  deploy_keys: string[]; // "repo:key id"
  // Public repos only (the free plan has none on private ones): "repo:id:enforcement:<hash of the whole rule>",
  // so an in-place edit (a removed approval, a new target) changes the entry (Codex C6a-1 r1 #2).
  rulesets: string[];
}

/** Lists everything in GhSnapshot with one read-only installation key (about 8 calls plus one per repo). */
export async function snapshot(gh: GitHub): Promise<GhSnapshot> {
  const page = async <T>(path: string): Promise<T[]> => {
    const items = await gh.call<T[]>("GET", `${path}${path.includes("?") ? "&" : "?"}per_page=100`);
    if (items.length >= 100) throw new VaultError(`too_many: ${path}`);
    return items;
  };
  const login = (u: { login: string }) => u.login;
  const repos = await page<{ name: string; private: boolean }>(`/orgs/${ORG}/repos?type=all`);
  const installs = await gh.call<{ installations: { id: number; app_slug: string; repository_selection: string; permissions: Record<string, string> }[] }>("GET", `/orgs/${ORG}/installations?per_page=100`);
  if (installs.installations.length >= 100) throw new VaultError("too_many: installations");
  const perms = (p: Record<string, string>) => Object.keys(p ?? {}).sort().map((k) => `${k}=${p[k]}`).join(",");
  const s: GhSnapshot = {
    repos: repos.map((r) => `${r.name}:${r.private ? "private" : "public"}`),
    members: (await page<{ login: string }>(`/orgs/${ORG}/members`)).map(login),
    outside: (await page<{ login: string }>(`/orgs/${ORG}/outside_collaborators`)).map(login),
    invites: (await page<{ login: string | null; email: string | null }>(`/orgs/${ORG}/invitations`)).map((i) => i.login ?? i.email ?? "?"),
    apps: installs.installations.map((i) => `${i.app_slug}#${i.id}:${i.repository_selection}:${perms(i.permissions)}`),
    pats: (await page<{ id: number; owner: { login: string } }>(`/orgs/${ORG}/personal-access-tokens`)).map((t) => `${t.owner.login}:${t.id}`),
    deploy_keys: [],
    rulesets: [],
  };
  for (const r of repos) {
    s.deploy_keys.push(...(await page<{ id: number }>(`/repos/${ORG}/${r.name}/keys`)).map((k) => `${r.name}:${k.id}`));
    if (r.private) continue;
    for (const x of await page<{ id: number }>(`/repos/${ORG}/${r.name}/rulesets`)) {
      const rule = await gh.call<Record<string, unknown>>("GET", `/repos/${ORG}/${r.name}/rulesets/${x.id}`);
      // Everything that decides what the rule does. bypass_actors is hashed when GitHub shows it to a
      // read-only App (FROM MEMORY: it may not; the first live run records which).
      const what = { target: rule.target, enforcement: rule.enforcement, conditions: rule.conditions, rules: rule.rules, bypass_actors: rule.bypass_actors ?? null };
      s.rulesets.push(`${r.name}:${x.id}:${rule.enforcement}:${(await sha256Hex(canonical(what))).slice(0, 16)}`);
    }
  }
  for (const list of Object.values(s)) list.sort();
  return s;
}

/** JSON with object keys sorted, so the same content always hashes the same. */
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v ?? null);
}

export async function sha256Hex(text: string): Promise<string> {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Every entry added or gone since the baseline, as "kind +entry" / "kind -entry". */
export function diff(base: GhSnapshot, now: GhSnapshot): string[] {
  const out: string[] = [];
  for (const kind of Object.keys(now) as (keyof GhSnapshot)[]) {
    const was = base[kind] ?? [];
    for (const x of now[kind]) if (!was.includes(x)) out.push(`${kind} +${x}`);
    for (const x of was) if (!now[kind].includes(x)) out.push(`${kind} -${x}`);
  }
  return out;
}
