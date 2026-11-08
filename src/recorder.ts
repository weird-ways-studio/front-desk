// Sends the desk's records to the Observatory's recorder before anything runs (card 97a2e83d,
// plan phase 3). The recorder lives in another Cloudflare account behind its own Access login, so
// it is reached by URL with the front desk's service token (observatory RECORDS.md). No receipt
// that matches the exact bytes sent means the record does not count, and the desk refuses to go on.

export type Stage = "request" | "verdict" | "approval" | "result";

export interface Receipt {
  seq: number;
  grant: string;
  stage: Stage;
  sha256: string;
  // The recorder's signed receipt in full (receipt/v1, observatory src/contract.ts), when it sent one: the vault
  // checks `sig` itself before a card entry starts (card 85818ab1 U6). Absent from an older recorder's answer.
  v?: 1;
  key?: string;
  recorded_at?: string;
  sig?: string;
  // The exact bytes sent, which `sha256` covers.
  body?: string;
}

/**
 * Records one stage; resolves to a receipt whose sha256 is that of the exact bytes sent (later
 * stages name the request by it), or throws RecorderError. `body`: send these exact bytes instead of
 * serializing `record` (a frozen card result, V1); they must name the same grant and stage.
 */
export type Recorder = (record: { grant: string; stage: Stage; job: string; [k: string]: unknown }, body?: string) => Promise<Receipt>;

/** The bytes a record is sent as, unless frozen bytes are given; refuses frozen bytes for another grant or stage. */
export function recordBody(record: { grant: string; stage: Stage }, body?: string): string {
  if (body === undefined) return JSON.stringify({ v: 1, ...record });
  let b: { grant?: unknown; stage?: unknown } | null = null;
  try {
    b = JSON.parse(body);
  } catch {
    b = null;
  }
  if (b?.grant !== record.grant || b?.stage !== record.stage) throw new RecorderError("frozen body names another record");
  return body;
}

/** The receipt's signed fields, only when every one has its exact type. */
function signedPart(r: Record<string, unknown>): Pick<Receipt, "v" | "key" | "recorded_at" | "sig"> {
  return r.v === 1 && [r.key, r.recorded_at, r.sig].every((x) => typeof x === "string") ? { v: 1, key: r.key as string, recorded_at: r.recorded_at as string, sig: r.sig as string } : {};
}

// Fixed words only: nothing the recorder or the network said is repeated, so no answer text can
// reach Ben's log or the agent.
export class RecorderError extends Error {}

export const RECORD_TIMEOUT_MS = 5_000;

/** Hex SHA-256 of text as UTF-8: the same hash the recorder puts in its receipt. */
async function sha256Hex(text: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// A plain timer, not a platform timeout helper, so nothing here rests on an unprobed Workers feature.
function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new RecorderError("recorder timed out")), ms);
  });
  return Promise.race([p, late]).finally(() => clearTimeout(timer));
}

/**
 * The recorder client, or undefined when any setting is missing -- the desk then refuses every
 * request (fail closed). The same bytes are sent at most twice: the recorder answers the same
 * receipt for the same bytes, so a lost answer is safe to retry.
 */
export function recorderFrom(url: string | undefined, clientId: string | undefined, clientSecret: string | undefined, fetchFn: typeof fetch = fetch, timeoutMs = RECORD_TIMEOUT_MS): Recorder | undefined {
  if (!url || !/^https:\/\/[a-z0-9.-]+\/v1\/records$/.test(url) || !clientId || !clientSecret) return undefined;
  return async (record, frozen) => {
    const body = recordBody(record, frozen);
    const sha = await sha256Hex(body);
    let why = "recorder unreachable";
    for (let attempt = 0; attempt < 2; attempt++) {
      // One deadline covers the answer and its body, so a stalled body cannot hold the desk.
      const got = await withTimeout(
        fetchFn(url, { method: "POST", headers: { "content-type": "application/json", "CF-Access-Client-Id": clientId, "CF-Access-Client-Secret": clientSecret }, body }).then(async (res) => ({ status: res.status, json: res.status === 200 || res.status === 201 ? await res.json() : undefined })),
        timeoutMs,
      ).catch(() => undefined);
      // Lost answer, unreadable body or timeout: the same bytes once more.
      if (!got) continue;
      if (got.status !== 200 && got.status !== 201) {
        why = `recorder answered ${got.status}`;
        // Only "pending" and lost answers are worth one more try; a refusal will not change.
        if (got.status !== 503) break;
        continue;
      }
      const r = (got.json as { receipt?: Partial<Receipt> } | null)?.receipt;
      if (!r || r.grant !== record.grant || r.stage !== record.stage || r.sha256 !== sha || !Number.isInteger(r.seq)) {
        throw new RecorderError("recorder receipt does not match the record");
      }
      return { seq: r.seq as number, grant: r.grant, stage: r.stage, sha256: sha, ...signedPart(r as Record<string, unknown>), body };
    }
    throw new RecorderError(why);
  };
}
