import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, SignJWT, type JWTVerifyGetKey } from "jose";
import { agentOf } from "../src/agent.ts";
import { route } from "../src/routes.ts";
import { Desk, MemoryStore } from "../src/desk.ts";

// A stand-in Access team: its own signing key, issuer and app audience.
const TEAM = "team.example";
const AUD = "app-aud";
const CLIENT = "0123456789abcdef0123456789abcdef.access";
const cfg = { AGENT_CLIENT_ID: CLIENT, ACCESS_TEAM_DOMAIN: TEAM };
const access = (aud = AUD) => ({ aud, getIdentity: async () => undefined }) as ExecutionContext["access"];

const team = await generateKeyPair("RS256");
const stranger = await generateKeyPair("RS256");
const keys: JWTVerifyGetKey = async () => team.publicKey;

// A service-token ticket as Access issues it: common_name = Client ID, no email.
async function ticket(over: { claims?: Record<string, unknown>; iss?: string; aud?: string; exp?: string; key?: CryptoKey } = {}) {
  return new SignJWT({ common_name: CLIENT, sub: "", type: "app", ...over.claims })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(over.iss ?? `https://${TEAM}`)
    .setAudience(over.aud ?? AUD)
    .setIssuedAt()
    .setExpirationTime(over.exp ?? "5m")
    .sign(over.key ?? team.privateKey);
}
const req = (jwt?: string) =>
  new Request("https://desk.example/request", { method: "POST", headers: jwt ? { "cf-access-jwt-assertion": jwt } : {} });
const why = async (jwt: string | undefined, a = access(), c: Parameters<typeof agentOf>[2] = cfg) => {
  const r = await agentOf(req(jwt), a, c, keys);
  return r.ok ? `ok:${r.requester}` : r.why;
};

test("a genuine service-token ticket is the agent, named from its Client ID", async () => {
  assert.equal(await why(await ticket()), `ok:c-box agent ${CLIENT}`);
});

test("two Client IDs sharing a prefix stay two requesters", async () => {
  const twin = "01234567ffffffffffffffffffffffff.access";
  const a = await agentOf(req(await ticket()), access(), cfg, keys);
  const b = await agentOf(req(await ticket({ claims: { common_name: twin } })), access(), { ...cfg, AGENT_CLIENT_ID: twin }, keys);
  assert.ok(a.ok && b.ok);
  assert.notEqual(a.requester, b.requester);
});

test("forged, misdirected, expired or unsigned tickets are refused", async () => {
  assert.equal(await why(await ticket({ key: stranger.privateKey })), "bad_jwt", "signed by another key");
  assert.equal(await why(await ticket({ aud: "other-app" })), "bad_jwt", "meant for another app");
  assert.equal(await why(await ticket()), `ok:c-box agent ${CLIENT}`);
  assert.equal(await why(await ticket(), access("other-app")), "bad_jwt", "this app's aud differs");
  assert.equal(await why(await ticket({ iss: "https://evil.example" })), "bad_jwt", "another team");
  assert.equal(await why(await ticket({ exp: "-1m" })), "bad_jwt", "expired");
  const [h, p] = (await ticket()).split(".");
  const none = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
  assert.equal(await why(`${none}.${p}.`), "bad_jwt", "alg none");
  assert.equal(await why(`${h}.${p}.AAAA`), "bad_jwt", "bad signature");
  assert.equal(await why("garbage"), "bad_jwt");
});

test("only the configured service token counts, never a person's ticket", async () => {
  assert.equal(await why(await ticket({ claims: { common_name: "ffff.access" } })), "not_agent_token", "another service token");
  assert.equal(await why(await ticket({ claims: { common_name: undefined, email: "ben@example.com", sub: "u1" } })), "not_agent_token", "Ben's login");
  assert.equal(await why(await ticket({ claims: { email: "x@example.com" } })), "not_agent_token", "email plus the right Client ID");
});

test("missing pieces are refused with a reason", async () => {
  assert.equal(await why(undefined), "no_jwt");
  assert.deepEqual(await agentOf(req(await ticket()), undefined, cfg, keys), { ok: false, why: "no_access" });
  assert.equal(await why(await ticket(), access(), {}), "agent_unset");
  assert.equal(await why(await ticket(), access(), { ACCESS_TEAM_DOMAIN: TEAM }), "agent_unset");
  assert.equal(await why(await ticket(), access(), { AGENT_CLIENT_ID: " " , ACCESS_TEAM_DOMAIN: TEAM }), "agent_unset");
});

const base = "https://desk.example";
const post = (path: string, body?: unknown) => new Request(base + path, { method: "POST", body: body ? JSON.stringify(body) : undefined });

test("the grant records who asked from the verified identity, and only they can collect", async () => {
  const store = new MemoryStore();
  const res = await route(post("/request", { job: "test.echo", params: { word: "hi" }, reason: "x" }), store, { caller: "agent", requester: "c-box agent (aaaa)" });
  assert.equal(res.status, 201);
  const { id } = (await res.json()) as { id: string };
  const desk = new Desk(store, { origin: base, rpID: "desk.example" });
  assert.equal((await desk.grant(id)).requester, "c-box agent (aaaa)");
  const other = await route(post(`/collect/${id}`), store, { caller: "agent", requester: "c-box agent (bbbb)" });
  assert.equal(other.status, 403);
  assert.deepEqual(await other.json(), { error: "not_your_grant" });
});

test("a refused agent route logs why the agent check failed", async () => {
  const store = new MemoryStore();
  const res = await route(post("/request", {}), store, { caller: "unknown", why: "bad_jwt" });
  assert.equal(res.status, 403);
  const rows = await new Desk(store, { origin: base, rpID: "desk.example" }).readLog();
  assert.equal(rows.at(-1)?.detail, "POST /request by unknown, needs agent (bad_jwt)");
});
