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
// The main App (the repo-maker) has its key sealed to Ben's passkey. repository_creation joins for job gh.repo.create
// (card 77ec1e64): Ben adds it on GitHub only AFTER this vault is deployed, or checkApp would refuse the App meanwhile.
export const PERMISSIONS = {
  // Webhooks read (card N2 5fdbf2ce): allowed here BEFORE Ben grants them on GitHub (the 77ec1e64 order).
  headcount: { organization_administration: "read", members: "read", organization_personal_access_tokens: "read", administration: "read", metadata: "read", repository_hooks: "read", organization_hooks: "read" },
  main: { administration: "write", contents: "write", metadata: "read", repository_creation: "write" },
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
    const res = await this.send(method, path, body);
    const json = (await res.json().catch(() => ({}))) as { message?: string };
    if (!res.ok) throw new VaultError(`gh_${res.status}: ${String(json.message ?? "no message").slice(0, 100)}`);
    return json as T;
  }

  /** The raw answer, for callers that must tell statuses apart (ghrepo.ts: a create reply, a revoke probe). */
  // `redirect: "manual"` on reach reads: a redirect is a failure, never followed (it would also count as a subrequest).
  send(method: string, path: string, body?: unknown, redirect?: "manual"): Promise<Response> {
    return this.fetch(API + path, {
      method,
      ...(redirect ? { redirect } : {}),
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
  }
}

const LEVEL: Record<string, number> = { read: 1, write: 2, admin: 3 };

/** Refuses unless every permission GitHub reports is in `allowed` at the same or a lower level. */
export function checkPermissions(reported: unknown, allowed: Record<string, string>, what: string): void {
  // No permissions shown is not "nothing too wide": the check cannot run, so it refuses (fail closed).
  if (!reported || typeof reported !== "object" || Array.isArray(reported) || !Object.keys(reported).length) throw new VaultError(`${what}_permissions_unknown`);
  const extra = Object.entries(reported as Record<string, string>).filter(([k, v]) => !allowed[k] || !(LEVEL[v] <= LEVEL[allowed[k]]));
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
  // "name:GitHub repository id" (card 77ec1e64 finding 1): a repo deleted and re-made under the same name between
  // two nights has a new id, so it shows here even though `repos` is unchanged. Job-made repos are matched by id.
  repo_ids: string[];
  members: string[];
  owners: string[]; // members with the org owner role -- a promotion keeps the member list unchanged
  outside: string[];
  invites: string[];
  apps: string[]; // installed Apps, "slug#installation id:repository selection:permissions"
  pats: string[]; // fine-grained tokens with org access, "owner:id"
  deploy_keys: string[]; // "repo:key id"
  // Public repos only (the free plan has none on private ones): "repo:id:enforcement:<the whole rule as JSON>",
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
  const repos = await page<{ name: string; private: boolean; id: unknown }>(`/orgs/${ORG}/repos?type=all`);
  // An id that is not a positive whole number cannot be matched: the list fails closed, never half-counted.
  if (!repos.every((r) => Number.isSafeInteger(r.id) && (r.id as number) > 0)) throw new VaultError("bad_repo_id");
  const installs = await gh.call<{ installations: { id: number; app_slug: string; repository_selection: string; permissions: Record<string, string> }[] }>("GET", `/orgs/${ORG}/installations?per_page=100`);
  if (installs.installations.length >= 100) throw new VaultError("too_many: installations");
  const perms = (p: Record<string, string>) => Object.keys(p ?? {}).sort().map((k) => `${k}=${p[k]}`).join(",");
  const s: GhSnapshot = {
    repos: repos.map((r) => `${r.name}:${r.private ? "private" : "public"}`),
    repo_ids: repos.map((r) => `${r.name}:${r.id}`),
    members: (await page<{ login: string }>(`/orgs/${ORG}/members`)).map(login),
    owners: (await page<{ login: string }>(`/orgs/${ORG}/members?role=admin`)).map(login),
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
      // Written out in full, so Ben's screen shows what protection changed, not a code (Codex C6a-1 r2 #11).
      s.rulesets.push(`${r.name}:${x.id}:${rule.enforcement}:${canonical(what)}`);
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
export function diff<T extends object>(base: T, now: T): string[] {
  const out: string[] = [];
  const b = base as Record<string, string[] | undefined>, n = now as Record<string, string[]>;
  for (const kind of Object.keys(n)) {
    const was = b[kind] ?? [];
    for (const x of n[kind]) if (!was.includes(x)) out.push(`${kind} +${x}`);
    for (const x of was) if (!n[kind].includes(x)) out.push(`${kind} -${x}`);
  }
  return out;
}

// ---- Reach (card N2 5fdbf2ce; studio-os REFINE-5fdbf2ce-watcher-reach.md v1.3 sections 11-13): who and what GitHub
// sends code to or lets in, per repo. Raw URLs, paths, queries and config.secret never leave these functions: errors
// are fixed codes, hooks become "id:host:dest:events:active" where dest is a keyed fingerprint of the destination. ----

/** The one key a reach slice mints: nothing else. */
export const REACH_PERMS = { metadata: "read", repository_hooks: "read", organization_hooks: "read" } as const;
export interface ReachLists {
  repo_hooks: string[]; // "repo:id:host:dest:events:active"
  org_hooks: string[]; // "id:host:dest:events:active"
  collaborators: string[]; // "repo:login:role_name" as GitHub reports for affiliation=direct
}

// GitHub's own characters for repo names and logins: never ':', so "repo:login:role" and "repo:id:..." split exactly.
const GH_NAME = /^[A-Za-z0-9._-]+$/;
const shape = (ok: unknown): void => {
  if (!ok) throw new VaultError("reach_shape");
};

/** One page of a reach list, or a fixed code: 3xx, non-2xx, not an array, or a full page all fail the slice. */
export async function reachPage(gh: GitHub, path: string): Promise<Record<string, unknown>[]> {
  const res = await gh.send("GET", `${path}${path.includes("?") ? "&" : "?"}per_page=100`, undefined, "manual");
  if (res.status >= 300 && res.status < 400) throw new VaultError("reach_redirect");
  if (!res.ok) throw new VaultError(`reach_gh_${res.status}`);
  const items = (await res.json().catch(() => null)) as Record<string, unknown>[];
  shape(Array.isArray(items));
  if (items.length >= 100) throw new VaultError("reach_too_many");
  shape(items.every((x: unknown) => x && typeof x === "object"));
  return items;
}

/** The org's repos as the reach read keeps them: name, id, private. */
export async function reachRepos(gh: GitHub): Promise<{ name: string; id: number; private: boolean }[]> {
  const repos = await reachPage(gh, `/orgs/${ORG}/repos?type=all`);
  shape(repos.every((r) => typeof r.name === "string" && GH_NAME.test(r.name) && Number.isSafeInteger(r.id) && (r.id as number) > 0 && typeof r.private === "boolean"));
  return repos as unknown as { name: string; id: number; private: boolean }[];
}

/** A hook as "id:host:dest:events:active"; anything GitHub does not document for the fingerprint fails reach_shape. */
export async function hookEntry(h: Record<string, unknown>, key: CryptoKey): Promise<string> {
  const c = h.config as Record<string, unknown> | undefined;
  shape(Number.isSafeInteger(h.id) && c && typeof c === "object" && typeof c.url === "string" && Array.isArray(h.events) && h.events.every((e) => typeof e === "string") && typeof h.active === "boolean");
  let u: URL | undefined;
  try {
    u = new URL(c!.url as string);
  } catch {
    shape(false);
  }
  shape(u!.protocol === "https:" || u!.protocol === "http:");
  shape(c!.content_type === "json" || c!.content_type === "form");
  shape(["0", "1", 0, 1].includes(c!.insecure_ssl as string));
  const what = canonical({ url: c!.url, content_type: c!.content_type, insecure_ssl: String(c!.insecure_ssl), scheme: u!.protocol.slice(0, -1) });
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(what)));
  const dest = [...mac.slice(0, 6)].map((b) => b.toString(16).padStart(2, "0")).join("");
  // hostname, never host: a port goes into dest, not the entry. ':' (an IPv6 address) is stored as %3A, so the entry
  // always splits into exactly its fields (commit security review, finding 2).
  return `${h.id}:${u!.hostname.replace(/%/g, "%25").replace(/:/g, "%3A")}:${dest}:${[...(h.events as string[])].sort().join(",")}:${h.active}`;
}

/** One repo's hooks and direct collaborators; a private repo with nobody listed fails (a checked expectation). */
export async function reachRepo(gh: GitHub, r: { name: string; private: boolean }, key: CryptoKey): Promise<{ hooks: string[]; collabs: string[] }> {
  const hooks: string[] = [];
  for (const h of await reachPage(gh, `/repos/${ORG}/${r.name}/hooks`)) hooks.push(`${r.name}:${await hookEntry(h, key)}`);
  const people = await reachPage(gh, `/repos/${ORG}/${r.name}/collaborators?affiliation=direct`);
  shape(people.every((p) => typeof p.login === "string" && GH_NAME.test(p.login) && typeof p.role_name === "string"));
  if (r.private && !people.length) throw new VaultError("reach_collabs_empty");
  return { hooks: hooks.sort(), collabs: people.map((p) => `${r.name}:${p.login}:${p.role_name}`).sort() };
}

export async function reachOrgHooks(gh: GitHub, key: CryptoKey): Promise<string[]> {
  const out: string[] = [];
  for (const h of await reachPage(gh, `/orgs/${ORG}/hooks`)) out.push(await hookEntry(h, key));
  return out.sort();
}
