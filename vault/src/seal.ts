// Locks and unlocks the master key with the runtime's own WebCrypto -- no libraries.
// A 32-byte secret (Ben's passkey PRF output, or the printed recovery key)
// -> HKDF-SHA256 -> AES-256-GCM. The label is both the HKDF info and the
// GCM additional data, so a box sealed for one purpose never opens for another.

export class VaultError extends Error {}

export const MASTER_LABEL = "front-desk master-key v1";
export const RECOVERY_LABEL = "front-desk recovery-key v1";

export interface Sealed {
  iv: string;
  data: string;
}

const enc = new TextEncoder();

// Copied from src/desk.ts on purpose: the vault imports nothing outside vault/.
export function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(text: string): Uint8Array {
  const s = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

/** Turns a base64url string into exactly 32 secret bytes, or refuses. */
export function secretBytes(text: unknown): Uint8Array {
  let bytes: Uint8Array | null = null;
  try {
    if (typeof text === "string" && text) bytes = fromB64url(text);
  } catch {
    bytes = null;
  }
  if (!bytes || bytes.length !== 32) throw new VaultError("bad_secret");
  return bytes;
}

async function keyFrom(secret: Uint8Array, label: string): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: enc.encode(label) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Encrypts text under a 32-byte secret for one labelled purpose. */
export async function seal(secret: Uint8Array, label: string, text: string): Promise<Sealed> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await keyFrom(secret, label);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(label) }, key, enc.encode(text));
  return { iv: b64url(iv), data: b64url(new Uint8Array(data)) };
}

/** Decrypts, or throws wrong_secret: a wrong secret, wrong label or altered box never yields text. */
export async function open(secret: Uint8Array, label: string, box: Sealed): Promise<string> {
  try {
    const key = await keyFrom(secret, label);
    const iv = fromB64url(box.iv);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: enc.encode(label) }, key, fromB64url(box.data));
    return new TextDecoder().decode(plain);
  } catch {
    throw new VaultError("wrong_secret");
  }
}
