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
}

/**
 * Records one stage; resolves to a receipt whose sha256 is that of the exact bytes sent (later
 * stages name the request by it), or throws RecorderError.
 */
export type Recorder = (record: { grant: string; stage: Stage; job: string; [k: string]: unknown }) => Promise<Receipt>;

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
  return async (record) => {
    const body = JSON.stringify({ v: 1, ...record });
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
      return { seq: r.seq as number, grant: r.grant, stage: r.stage, sha256: sha };
    }
    throw new RecorderError(why);
  };
}
