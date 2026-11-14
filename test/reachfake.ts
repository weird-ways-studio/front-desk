// The fake GitHub for the reach read (card N2 5fdbf2ce): the headcount App, its installation and the org's repos, hooks
// and collaborators. Shared by test/reach.test.ts (direct vault calls) and test/reach.workerd.test.ts (the vault's
// outbound fetch in real workerd). Records every call; fixtures use example.com and made-up names only.
import { generateKeyPairSync } from "node:crypto";
import { ORG, PERMISSIONS } from "../vault/src/github.ts";

export const pem = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs1", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } }).privateKey as string;
export const APP = 101;
export const INST = 1010;

export type Hook = Record<string, unknown>;
export const hook = (id: number, over: Hook = {}, config: Hook = {}): Hook => ({
  id, events: ["push"], active: true, ...over,
  config: { url: "https://example.com/hook", content_type: "json", insecure_ssl: "0", secret: "********", ...config },
});

export function fakeGitHub(n = 2) {
  const repos = Array.from({ length: n }, (_, i) => ({ name: `repo-${i}`, id: 5000 + i, private: i % 2 === 1 }));
  const org = {
    repos: repos as { name: string; id: unknown; private: unknown }[],
    hooks: {} as Record<string, unknown[]>,
    orgHooks: [] as unknown[],
    collabs: Object.fromEntries(repos.map((r) => [r.name, [{ login: "owner-a", role_name: "admin" }]])) as Record<string, unknown[]>,
  };
  const calls: { method: string; path: string; redirect?: string }[] = [];
  const minted: unknown[] = [];
  // A probe permission GitHub wrongly grants (R22); every other write ask is refused as GitHub does.
  // deleteFail: how GitHub answers the delete of a wrongly granted key ("403", "500", "throw" or "" = 204 and revoked).
  const faults = { grantWrite: "", deleteFail: "" };
  const deleted: string[] = [];
  const tokens = new Set<string>();
  // A test may answer any one path itself (a refusal, a redirect, a slow answer).
  let override: ((path: string) => Response | Promise<Response> | undefined) | undefined;
  let t = 0;
  const json = (b: unknown, status = 200) => Response.json(b, { status });
  const fetchFn = async (input: string, init?: RequestInit) => {
    const url = new URL(input);
    const path = url.pathname + url.search;
    const method = init?.method ?? "GET";
    calls.push({ method, path, redirect: init?.redirect });
    const auth = String((init?.headers as Record<string, string>)?.authorization ?? "").replace("Bearer ", "");
    const o = override?.(path);
    if (o) return o;
    if (auth.split(".").length === 3) {
      if (path === "/app") return json({ id: APP, permissions: PERMISSIONS.headcount });
      if (path === `/app/installations/${INST}`) return json({ account: { login: ORG }, repository_selection: "all", permissions: PERMISSIONS.headcount });
      if (path === "/app/installations") return json([{ id: INST }]);
      if (path === `/app/installations/${INST}/access_tokens` && method === "POST") {
        const asked = JSON.parse(String(init?.body ?? "{}"));
        const writes = Object.entries(asked.permissions ?? {}).filter(([, v]) => v !== "read").map(([k]) => k);
        if (writes.length && !(writes.length === 1 && writes[0] === faults.grantWrite)) return json({ message: "The level of access for permissions requested are not granted to this installation." }, 422);
        if (!writes.length) minted.push(asked);
        const k = `ghs_reach_${++t}`;
        tokens.add(k);
        return json({ token: k, expires_at: "2099-01-01T00:00:00Z" }, 201);
      }
    }
    if (tokens.has(auth)) {
      if (deleted.includes(auth)) return json({ message: "Bad credentials" }, 401);
      if (method === "DELETE" && path === "/installation/token") {
        if (faults.deleteFail === "throw") throw new TypeError("network connection lost");
        if (faults.deleteFail) return json({ message: "no" }, Number(faults.deleteFail));
        deleted.push(auth);
        return new Response(null, { status: 204 });
      }
      if (path.startsWith("/installation/repositories")) return json({ total_count: 1, repositories: [] });
      if (url.pathname === `/orgs/${ORG}/repos`) return json(org.repos);
      if (url.pathname === `/orgs/${ORG}/hooks`) return json(org.orgHooks);
      const m = url.pathname.match(new RegExp(`^/repos/${ORG}/([\\w-]+)/(hooks|collaborators)$`));
      if (m && m[2] === "hooks") return json(org.hooks[m[1]] ?? []);
      if (m && url.searchParams.get("affiliation") === "direct") return json(org.collabs[m[1]] ?? []);
    }
    return json({ message: `unexpected ${method} ${path}` }, 404);
  };
  return { org, calls, minted, faults, deleted, fetchFn, set: (f: typeof override) => (override = f) };
}

