// The c-box signing key: proof that a request comes from the c-box itself, not just from someone
// holding the agent's Access login (design: studio-os docs/specifications/face-id-access/
// C5C1-CBOX-ADDRESS-DESIGN.md, Codex architecture review r1). The private key lives only on the
// c-box (scripts/agent.mjs keygen), apart from the Access login and 1Password. Ben enrolls its
// public half by Face ID (job cbox.key.enroll) and can remove it from /cbox-key.
//
// A signed request carries x-cbox-time (ms) and x-cbox-signature: ECDSA P-256 / SHA-256, raw r||s,
// base64url, over "METHOD\nPATH\nTIME\nsha256-hex(body)". Accepted within 60 seconds, once.

import { DeskError, type Store } from "./desk.ts";

export const SIGNATURE_WINDOW_MS = 60_000;

export interface CboxKey {
  spki: string; // base64url SubjectPublicKeyInfo, P-256
  fingerprint: string;
  enrolled_at: number;
  grant_id: string;
}

const enc = new TextEncoder();
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const fromB64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

// The fixed 26-byte DER prefix of a P-256 SubjectPublicKeyInfo (65-byte uncompressed point follows).
const P256_SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

/** True for a base64url P-256 public key in SPKI form; nothing else is enrolled. */
export function isP256Spki(spki: unknown): spki is string {
  if (typeof spki !== "string" || !/^[A-Za-z0-9_-]{120,124}$/.test(spki)) return false;
  try {
    const b = fromB64url(spki);
    return b.length === 91 && hex(b.slice(0, 26).buffer) === P256_SPKI_PREFIX && b[26] === 4;
  } catch {
    return false;
  }
}

/** Short fingerprint Ben compares between chat and the approval screen: 16 hex in groups of 4. */
export async function fingerprint(spki: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", fromB64url(spki))).slice(0, 16).replace(/(.{4})(?!$)/g, "$1-");
}

export async function currentKey(store: Store): Promise<CboxKey | undefined> {
  return (await store.get<CboxKey | null>("cbox:key")) ?? undefined;
}

/**
 * Checks a request's c-box signature. Returns nothing, or throws a DeskError naming why it failed.
 * Each accepted signed message is remembered, so it cannot be used twice.
 */
export async function checkSignature(store: Store, method: string, path: string, headers: Headers, body: string, now: number): Promise<void> {
  const key = await currentKey(store);
  if (!key) throw new DeskError("no_cbox_key", 401);
  const time = headers.get("x-cbox-time") ?? "";
  const sig = headers.get("x-cbox-signature") ?? "";
  if (!/^\d{13}$/.test(time) || !/^[A-Za-z0-9_-]{86}$/.test(sig)) throw new DeskError("not_signed", 401);
  if (Math.abs(now - Number(time)) > SIGNATURE_WINDOW_MS) throw new DeskError("signature_expired", 401);
  const message = `${method}\n${path}\n${time}\n${hex(await crypto.subtle.digest("SHA-256", enc.encode(body)))}`;
  const pub = await crypto.subtle.importKey("spki", fromB64url(key.spki), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, fromB64url(sig), enc.encode(message));
  if (!ok) throw new DeskError("bad_signature", 401);
  // Remembered by the signed message, not the signature: an ECDSA signature can be altered into a
  // second valid one (malleability), but the message cannot. Storage calls only from here, so two
  // copies cannot both pass.
  const seen = `sig:${hex(await crypto.subtle.digest("SHA-256", enc.encode(message)))}`;
  // Re-read: Ben may have removed or replaced the key while the signature was being checked.
  if ((await currentKey(store))?.spki !== key.spki) throw new DeskError("no_cbox_key", 401);
  if (await store.get(seen)) throw new DeskError("signature_replayed", 401);
  await store.put(seen, Number(time) + SIGNATURE_WINDOW_MS);
}
