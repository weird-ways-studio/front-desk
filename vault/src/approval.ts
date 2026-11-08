// The vault's own check of Ben's tap (card bb86abf0; REFINE-bb86abf0 v2.1 Outcome, R1, R2, R6). Before the
// master key is opened, the caller must hand over Ben's passkey answer for this exact grant, and the vault
// checks it itself with the recorder's verifier (passkey.ts, a verbatim copy) against the pinned passkey.
// Each grant runs at most once. The desk's checks stay; the vault no longer depends on them.
import { VaultError, secretBytes } from "./seal.ts";
import { approvalCheck, grantHashOf, PASSKEY_PIN, type PasskeyPin } from "./passkey.ts";

/** What the desk sends to vault.run: the grant as hashed, Ben's passkey answer, and the passkey secret. */
export interface SignedRun {
  grant: { id: string; job: string; params: Record<string, string>; requester: string; expires_at: number };
  assertion: { passkey_id: string; authenticator_data: string; client_data_json: string; signature: string };
  prf: string;
}

// Raised only BEFORE the admission step writes `used`, so nothing ran when the desk sees one of these (R6).
export const REFUSED_BEFORE_RUN = ["wrong_shape", "no_pin", "bad_grant", "bad_assertion", "expired"] as const;
// The grant is already in `used`: it may have run once.
export const ALREADY_USED = "already_used";
// A grant is good for this long after its own expiry (approve window + recording + the run), and its id is
// kept in `used` exactly that long: one boundary for both, so a forgotten id belongs to an expired grant (R1).
export const USED_GRACE_MS = 5 * 60_000;
// The desk checks this before calling run, so a desk and vault on different versions refuse as wrong_shape.
export const APPROVAL_API_VERSION = 1;

interface UsedStore {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
}

const isText = (v: unknown): v is string => typeof v === "string";

/**
 * Checks the shape, the pin and Ben's signature (crypto: awaits). Returns the grant, or throws a
 * REFUSED_BEFORE_RUN code. Old-shape calls (job, params, prf) arrive here as extra arguments.
 */
export async function checkSigned(req: unknown, extra: number, pin: PasskeyPin | undefined): Promise<SignedRun> {
  const r = req as Partial<SignedRun> | null;
  const keys = r && typeof r === "object" && !Array.isArray(r) ? Object.keys(r).sort().join(",") : "";
  if (extra !== 0 || keys !== "assertion,grant,prf") throw new VaultError("wrong_shape");
  // The passkey secret is checked here, so a bad one never reaches unlock() after admission.
  try {
    secretBytes(r!.prf);
  } catch {
    throw new VaultError("wrong_shape");
  }
  if (!pin) throw new VaultError("no_pin");
  const g = r!.grant as SignedRun["grant"] | null;
  const gkeys = g && typeof g === "object" && !Array.isArray(g) ? Object.keys(g).sort().join(",") : "";
  if (gkeys !== "expires_at,id,job,params,requester" || !isText(g!.id) || !g!.id || !isText(g!.job)) throw new VaultError("bad_grant");
  // The recorder's record shape, so its grantHashOf() input checks and hash apply unchanged (R2).
  const record = { v: 1 as const, grant: g!.id, stage: "approval", job: g!.job, params: g!.params, requester: g!.requester, expires_at: g!.expires_at, assertion: r!.assertion };
  const hash = await grantHashOf(record);
  if (!hash) throw new VaultError("bad_grant");
  if ((await approvalCheck(pin)(record, hash)) !== undefined) throw new VaultError("bad_assertion");
  return r as SignedRun;
}

/**
 * The one admission step, after all crypto: storage calls only, which the Durable Object does not
 * interleave. Re-reads the clock, refuses an expired or already-used grant, forgets ids past the same
 * boundary, and records this one before anything is opened.
 */
export async function admit(store: UsedStore, id: string, expiresAt: number, now: number): Promise<void> {
  if (now > expiresAt + USED_GRACE_MS) throw new VaultError("expired");
  const used = (await store.get<Map<string, number>>("used")) ?? new Map<string, number>();
  if (used.has(id)) throw new VaultError(ALREADY_USED);
  for (const [k, exp] of used) if (now > exp + USED_GRACE_MS) used.delete(k);
  used.set(id, expiresAt);
  await store.put("used", used);
}

export { PASSKEY_PIN };
