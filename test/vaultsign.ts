// Test helper (card bb86abf0): signs vault.run calls the way the desk sends them -- the grant fields, Ben's
// passkey answer over that grant's hash, and the passkey secret -- with a software passkey the test vault pins.
import { SoftKey } from "./softkey.ts";
import { b64url, grantHash } from "../src/desk.ts";
import { VaultLogic, type VaultStore } from "../vault/src/vault.ts";
import type { Fetch } from "../vault/src/cloudflare.ts";
import type { PasskeyPin } from "../vault/src/passkey.ts";
import type { SignedRun } from "../vault/src/approval.ts";

export const TEST_ORIGIN = "https://desk.example";
export const TEST_RP = "desk.example";
const enc = new TextEncoder();
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha = async (t: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(t)));

export async function pinOf(key: SoftKey): Promise<PasskeyPin> {
  return { id: key.id, key: b64url(await key.cose()), rp_hash: hex(await sha(TEST_RP)), origin_hash: hex(await sha(TEST_ORIGIN)) };
}

export const TEST_KEY = await SoftKey.create();
export const TEST_PIN = await pinOf(TEST_KEY);

let n = 0;
export type SignOpts = { id?: string; expires_at?: number; requester?: string; key?: SoftKey; origin?: string; rp?: string; userVerified?: boolean; signedFor?: SignedRun["grant"] };

/** A signed run for one grant. `signedFor`: sign that grant's hash instead (to test a swapped grant). */
export async function signed(job: string, params: Record<string, string>, prf: string, o: SignOpts = {}): Promise<SignedRun> {
  const grant = { id: o.id ?? `g-test-${++n}`, job, params, requester: o.requester ?? "c-box agent", expires_at: o.expires_at ?? Number.MAX_SAFE_INTEGER };
  const hash = await grantHash((o.signedFor ?? grant) as Parameters<typeof grantHash>[0]);
  const challenge = b64url(new Uint8Array([...crypto.getRandomValues(new Uint8Array(16)), ...hash.match(/../g)!.map((h) => parseInt(h, 16))]));
  const r = await (o.key ?? TEST_KEY).assert(challenge, o.rp ?? TEST_RP, o.origin ?? TEST_ORIGIN, { userVerified: o.userVerified ?? true });
  const assertion = { passkey_id: r.id, authenticator_data: r.response.authenticatorData, client_data_json: r.response.clientDataJSON, signature: r.response.signature };
  return { grant, assertion, prf };
}

/** vault.run as the desk calls it, signed by the test passkey. */
export async function signedRun(vault: VaultLogic, job: string, params: Record<string, string>, prf: string, o: SignOpts = {}) {
  return vault.run(await signed(job, params, prf, o));
}

/** A vault that pins the test passkey. */
export const testVault = (store: VaultStore, fetchFn: Fetch, now: () => number = Date.now) => new VaultLogic(store, fetchFn, now, TEST_PIN);
