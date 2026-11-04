#!/usr/bin/env node
// The c-box side of the front desk: makes the c-box signing key and sends signed agent requests.
// No libraries (Node's own crypto and fetch). Signature format: src/cboxkey.ts.
//
//   node scripts/agent.mjs keygen                 makes the key (once), prints its public half + fingerprint
//   node scripts/agent.mjs post <url> [json]      POST with the Access login and the c-box signature
//   node scripts/agent.mjs wait <collect-url> [minutes]  collects as soon as Ben approves (default 15 min)
//   node scripts/agent.mjs menu <desk-url>         lists the jobs you may ask for (generated from src/jobs.ts)
//
// The private key file (default ~/.config/front-desk/cbox-key.pem, mode 0600) stays on the c-box and is
// never put in 1Password or a repo. The Access login comes from CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET
// in the environment (read from 1Password by the caller, per call).

import { createHash, createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname } from "node:path";


const KEY = process.env.CBOX_KEY_FILE ?? `${homedir()}/.config/front-desk/cbox-key.pem`;
const b64url = (b) => Buffer.from(b).toString("base64url");

function fingerprint(spki) {
  return createHash("sha256").update(spki).digest("hex").slice(0, 16).replace(/(.{4})(?!$)/g, "$1-");
}

/** Signs METHOD\nPATH\nTIME\nsha256-hex(body) with the c-box key: raw r||s, base64url. */
export function signRequest(keyPem, method, path, body, time = Date.now()) {
  const message = `${method}\n${path}\n${time}\n${createHash("sha256").update(body).digest("hex")}`;
  const sig = sign("sha256", Buffer.from(message), { key: createPrivateKey(keyPem), dsaEncoding: "ieee-p1363" });
  return { "x-cbox-time": String(time), "x-cbox-signature": b64url(sig) };
}

/** The agents' Access login headers, from the environment (read from 1Password by the caller). */
function access() {
  const id = process.env.CF_ACCESS_CLIENT_ID, secret = process.env.CF_ACCESS_CLIENT_SECRET;
  if (!id || !secret) throw new Error("CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET must be set");
  return { "cf-access-client-id": id, "cf-access-client-secret": secret };
}

/** POST with the Access login and a fresh c-box signature (a new one each call, so waits can re-send). */
async function post(url, body) {
  const u = new URL(url);
  const headers = { "content-type": "application/json", ...access(), ...signRequest(readFileSync(KEY), "POST", u.pathname, body) };
  return fetch(u, { method: "POST", headers, body });
}

async function main([cmd, url, body = ""]) {
  if (cmd === "keygen") {
    if (existsSync(KEY)) throw new Error(`${KEY} exists; remove it first to make a new key`);
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    mkdirSync(dirname(KEY), { recursive: true, mode: 0o700 });
    writeFileSync(KEY, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600, flag: "wx" });
    const spki = publicKey.export({ type: "spki", format: "der" });
    console.log(JSON.stringify({ key: b64url(spki), fingerprint: fingerprint(spki) }));
    return;
  }
  if (cmd === "wait" && url) {
    // Ben approves on his phone; the agent learns it here, no relay, inside the 5-minute collect window.
    const until = Date.now() + Number(body || 15) * 60_000;
    for (;;) {
      const res = await post(url, "");
      const text = await res.text();
      const waiting = (res.status === 403 && text.includes("not_approved")) || (res.status === 409 && text.includes("not_ready"));
      if (!waiting || Date.now() > until) {
        console.log(res.status, waiting ? `still waiting after ${body || 15} min` : text);
        if (!res.ok) process.exit(1);
        return;
      }
      await new Promise((r) => setTimeout(r, 5_000));
    }
  }
  if (cmd === "menu" && url) {
    const res = await fetch(new URL("/menu", url), { headers: access() });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    const m = await res.json();
    for (const j of m.jobs) console.log(`${j.job}  [${j.mode}${j.signed ? ", signed" : ""}]\n  ${j.does}\n  on: ${j.on}\n  params: ${j.params}`);
    console.log(`\nModes: ${Object.entries(m.modes).map(([k, v]) => `${k} = ${v}`).join(" ")}\n${m.new_job}\nAsk: ${m.ask}`);
    return;
  }
  if (cmd === "post" && url) {
    const res = await post(url, body);
    console.log(res.status, await res.text());
    return;
  }
  throw new Error("usage: agent.mjs keygen | agent.mjs post <url> [json] | agent.mjs wait <collect-url> [minutes] | agent.mjs menu <desk-url>");
}

if (import.meta.url === `file://${process.argv[1]}`) main(process.argv.slice(2)).catch((e) => { console.error(e.message); process.exit(1); });
