// COPIED VERBATIM from the Observatory (weird-ways-observatory/observatory) @76f2837 (card 85818ab1, REFINE-85818ab1
// "Copy rule"): the card format the recorder enforces (src/card.ts), the receipt it signs (src/contract.ts), and the
// recorder's public key (src/records.ts PIN.key). The vault loads no other project's files and the Observatory is a
// separate organization agents cannot reach, so the two cannot share code. Only the import lines differ: canonical,
// sha256 and unb64 come from ./passkey.ts, which holds verbatim copies of the same functions (@7ddcffe, unchanged at
// 76f2837). `Stage` is typed `string`, as in passkey.ts. Do not edit the copied parts here: change the Observatory
// first, then re-copy, and re-run test/cards-vectors.test.ts (verdicts made by the Observatory's own code).
// Used by the card book: vault/src/cards.ts.
import { canonical, sha256, unb64 } from "./passkey.ts";

/** The recorder's Ed25519 public key (base64, raw), as pinned in observatory src/records.ts PIN.key @76f2837. Public. */
export const RECORDER_KEY = "AeN3/Dl3QicxXBObHVyLdhMmWGoDpjVO44LoB0sRV+s=";

// ---- from observatory src/contract.ts @76f2837 ----
// A letter or digit first, so no grant id can be a built-in object name like __proto__.
export const GRANT = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
// `sig` (card 586da182): the recorder's Ed25519 signature over receiptSealed, added when it answers; never stored.
export interface Receipt { v: 1; seq: number; key: string; grant: string; stage: string; sha256: string; recorded_at: string; sig?: string }
/**
 * The bytes a receipt's `sig` covers: a fixed `receipt/v1` label first, then every receipt field but `sig` in
 * this order. An envelope's bytes start with `v`, so neither signature can pass as the other.
 */
export const receiptSealed = (r: Receipt) => new TextEncoder().encode(JSON.stringify({ kind: "receipt/v1", v: r.v, seq: r.seq, key: r.key, grant: r.grant, stage: r.stage, sha256: r.sha256, recorded_at: r.recorded_at }));

// ---- from observatory src/card.ts @76f2837 (import lines removed) ----
/**
 * Jobs a card may hold, the Observatory's own list (APPROACH §13): changed only by a PR Ben merges in an org
 * no agent can reach. Empty refuses every card (an off switch beside the vault's). gh.repo.create joins in
 * card build 4, with the job itself.
 */
export const CARD_ELIGIBLE: readonly string[] = Object.freeze(["test.echo", "cf.zone.read", "cf.dns.list", "cf.audit.read"]);
export const CARD_MAX = 5; // entries on one card
export const CARD_RUN_MS = 15 * 60_000; // a card's deadline is at most its grants' expiry + this

/** What Ben's tap covers, exactly these six keys. `deadline`: epoch ms, the latest any entry may start. */
export interface Manifest { kind: "card/v1"; card: string; requester: string; entries: string[]; deadline: number; jobs_version: number }

const SHA = /^[0-9a-f]{64}$/;
const KEYS = ["card", "deadline", "entries", "jobs_version", "kind", "requester"];
const int = (v: unknown): v is number => Number.isSafeInteger(v) && !Object.is(v, -0) && (v as number) > 0;

/** True if `v` is a valid card id. */
export const isCardId = (v: unknown): v is string => typeof v === "string" && GRANT.test(v);

/** The manifest, or why it is refused: exact keys and types, 1-5 distinct grant hashes. */
export function parseManifest(v: unknown): Manifest | string {
  if (!v || typeof v !== "object" || Array.isArray(v)) return "no manifest";
  const m = v as Record<string, unknown>;
  if (Object.keys(m).sort().join() !== KEYS.join()) return "the manifest has the wrong fields";
  if (m.kind !== "card/v1" || !isCardId(m.card) || typeof m.requester !== "string" || !m.requester || m.requester.length > 200) return "the manifest's kind, card id or requester is not valid";
  const e = m.entries;
  if (!Array.isArray(e) || e.length < 1 || e.length > CARD_MAX || !e.every((h) => typeof h === "string" && SHA.test(h)) || new Set(e).size !== e.length) return "the manifest's entries are not 1 to 5 distinct grant hashes";
  if (!int(m.deadline) || !int(m.jobs_version)) return "the manifest's deadline or jobs version is not valid";
  return m as unknown as Manifest;
}

/** The card hash Ben's phone signs: SHA-256 of the canonical manifest. A grant hash covers other keys, so the two never meet. */
export const cardHashOf = (m: Manifest) => sha256(canonical(m));

/** The card hash a passkey answer's challenge carries (16 random bytes + 32), or undefined if unreadable. */
export function challengeHash(assertion: unknown): string | undefined {
  try {
    const c = (assertion as { client_data_json: string }).client_data_json;
    const url = (s: string) => unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
    const ch = url(JSON.parse(new TextDecoder().decode(url(c))).challenge);
    return ch.length === 48 ? [...ch.slice(16)].map((b) => b.toString(16).padStart(2, "0")).join("") : undefined;
  } catch {
    return undefined;
  }
}
