// Is this request the c-box agent? The agent signs in to Cloudflare Access with a
// service token, which has no email, so ctx.access.getIdentity() cannot name it
// (routes.ts callerOf). Access instead forwards a signed login ticket (a JWT) in
// the Cf-Access-Jwt-Assertion header. We check that ticket ourselves before
// trusting it: signed by our Access team's key, issued by our team, meant for this
// app (ctx.access.aud), not expired, and carrying the agent's service-token Client
// ID. Anything missing or wrong = not the agent, with the reason kept for the log.

import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";

export type AgentCheck = { ok: true; requester: string } | { ok: false; why: string };

export interface AgentConfig {
  // Both set by Ben in the dashboard (kept by keep_vars), never in this public repo.
  AGENT_CLIENT_ID?: string; // the c-box service token's Client ID
  ACCESS_TEAM_DOMAIN?: string; // e.g. <team>.cloudflareaccess.com
}

// One key fetcher per team, reused across requests; jose caches the keys it fetches.
const keySets = new Map<string, JWTVerifyGetKey>();
function teamKeys(team: string): JWTVerifyGetKey {
  let keys = keySets.get(team);
  if (!keys) {
    keys = createRemoteJWKSet(new URL(`https://${team}/cdn-cgi/access/certs`));
    keySets.set(team, keys);
  }
  return keys;
}

export async function agentOf(
  request: Request,
  access: ExecutionContext["access"],
  cfg: AgentConfig,
  keys?: JWTVerifyGetKey, // tests pass their own key; the Worker uses the team's published keys
): Promise<AgentCheck> {
  const clientId = cfg.AGENT_CLIENT_ID?.trim();
  const team = cfg.ACCESS_TEAM_DOMAIN?.trim();
  if (!clientId || !team) return { ok: false, why: "agent_unset" };
  if (!access?.aud) return { ok: false, why: "no_access" };
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) return { ok: false, why: "no_jwt" };
  let claims: Record<string, unknown>;
  try {
    ({ payload: claims } = await jwtVerify(token, keys ?? teamKeys(team), {
      issuer: `https://${team}`,
      audience: access.aud,
      algorithms: ["RS256"],
    }));
  } catch {
    return { ok: false, why: "bad_jwt" };
  }
  // A person's ticket carries an email and no common_name; only a service token's names a Client ID.
  if (claims.common_name !== clientId || claims.email) return { ok: false, why: "not_agent_token" };
  return { ok: true, requester: `c-box agent (${clientId.slice(0, 8)})` };
}
