#!/usr/bin/env node
// The c-box side of the front desk: makes the c-box signing key and sends signed agent requests.
// No libraries (Node's own crypto and fetch). Signature format: src/cboxkey.ts.
//
//   node scripts/agent.mjs keygen                 makes the key (once), prints its public half + fingerprint
//   node scripts/agent.mjs post <url> [json]      POST with the Access login and the c-box signature
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
  if (cmd === "post" && url) {
    const id = process.env.CF_ACCESS_CLIENT_ID, secret = process.env.CF_ACCESS_CLIENT_SECRET;
    if (!id || !secret) throw new Error("CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET must be set");
    const u = new URL(url);
    const headers = { "content-type": "application/json", "cf-access-client-id": id, "cf-access-client-secret": secret,
      ...signRequest(readFileSync(KEY), "POST", u.pathname, body) };
    const res = await fetch(u, { method: "POST", headers, body });
    console.log(res.status, await res.text());
    return;
  }
  throw new Error("usage: agent.mjs keygen | agent.mjs post <url> [json]");
}

if (import.meta.url === `file://${process.argv[1]}`) main(process.argv.slice(2)).catch((e) => { console.error(e.message); process.exit(1); });
