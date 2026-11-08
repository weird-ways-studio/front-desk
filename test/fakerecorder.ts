// An in-memory stand-in for the Observatory's recorder (observatory src/contract.ts and
// src/recorder/ledger.ts at 4b7bedd). It refuses what the real one refuses that matters to the desk:
// secret-shaped field names, oversize bodies, a later stage with no recorded request or approval, a
// wrong request hash, and other bytes for an already-recorded stage. `down` makes every write fail.

import type { Receipt, Recorder, Stage } from "../src/recorder.ts";
import { RecorderError, recordBody } from "../src/recorder.ts";
import { repoIdRefusal } from "../vault/src/cardcopy.ts";

/** Signs receipts as the real recorder does (test/cardsign.ts TestRecorder), so the vault's receipt check can run. */
export interface Signer { receipt(grant: string, stage: string, body: string, over?: { seq?: number; recorded_at?: string }): Promise<object> }

const SECRETISH = /secret|password|token|private|credential/i;
const MAX_RECORD_BYTES = 8_192;

function secretish(v: unknown, depth = 0): boolean {
  if (!v || typeof v !== "object") return false;
  if (depth > 8) return true;
  return Object.entries(v).some(([k, x]) => SECRETISH.test(k) || secretish(x, depth + 1));
}

async function sha256Hex(text: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export class FakeRecorder {
  records: { stage: Stage; grant: string; body: string; record: Record<string, unknown> }[] = [];
  down = false;
  // Fail only this stage (e.g. "approval"), to put the desk in each failure state.
  failStage?: Stage;
  // Commits the record, then loses the answer (the desk sees an error), once per listed stage.
  loseAnswer = new Set<Stage>();
  // Refuse just the records this picks (e.g. one entry's approval), as the real recorder would with a 409.
  failIf?: (record: { grant: string; stage: Stage; [k: string]: unknown }) => boolean;
  signer?: Signer;
  sent: string[] = []; // every body that reached the recorder, in order (to count sends and compare bytes)

  readonly send: Recorder = async (record, frozen) => {
    if (this.down || this.failStage === record.stage) throw new RecorderError("recorder answered 503");
    if (this.failIf?.(record)) throw new RecorderError("recorder answered 409");
    const body = recordBody(record, frozen);
    this.sent.push(body);
    const out = await this.commit(record, body);
    if (this.loseAnswer.delete(record.stage)) throw new RecorderError("recorder unreachable");
    return out;
  };

  private async commit(record: { grant: string; stage: Stage; [k: string]: unknown }, body: string): Promise<Receipt> {
    if (new TextEncoder().encode(body).length > MAX_RECORD_BYTES) throw new RecorderError("recorder answered 413");
    if (secretish(record)) throw new RecorderError("recorder answered 400");
    // The Observatory's own rule (src/card.ts repoIdRefusal @4f96e85, copied in vault/src/cardcopy.ts): a done
    // gh.repo.create result needs repo_id digits; no other result may carry one (card 77ec1e64 T17).
    if (record.stage === "result" && repoIdRefusal(JSON.parse(body)) !== undefined) throw new RecorderError("recorder answered 400");
    const sha = await sha256Hex(body);
    const mine = this.records.filter((r) => r.grant === record.grant);
    const same = mine.find((r) => r.stage === record.stage);
    if (same) {
      if (same.body !== body) throw new RecorderError("recorder answered 409");
      return this.signed({ seq: this.records.indexOf(same) + 1, grant: record.grant, stage: record.stage, sha256: sha }, body);
    }
    if (record.stage !== "request") {
      const req = mine.find((r) => r.stage === "request");
      if (!req || record.request !== (await sha256Hex(req.body))) throw new RecorderError("recorder answered 409");
      if (record.stage === "result" && !mine.some((r) => r.stage === "approval")) throw new RecorderError("recorder answered 409");
    }
    // Re-checked after the awaits above, as the real recorder serializes writes: same bytes, same receipt.
    const raced = this.records.find((r) => r.grant === record.grant && r.stage === record.stage);
    if (raced) {
      if (raced.body !== body) throw new RecorderError("recorder answered 409");
      return this.signed({ seq: this.records.indexOf(raced) + 1, grant: record.grant, stage: record.stage, sha256: sha }, body);
    }
    this.records.push({ stage: record.stage, grant: record.grant, body, record: JSON.parse(body) });
    return this.signed({ seq: this.records.length, grant: record.grant, stage: record.stage, sha256: sha } satisfies Receipt, body);
  }

  // The same receipt for the same bytes (the real recorder's rule): signed over the stored seq, so a resend matches.
  private async signed(r: Receipt, body: string): Promise<Receipt> {
    if (!this.signer) return r;
    const s = await this.signer.receipt(r.grant, r.stage, body, { seq: r.seq, recorded_at: new Date(1_800_000_000_000 + r.seq).toISOString() });
    return { ...r, ...(s as Partial<Receipt>), body };
  }

  stages(grant: string): Stage[] {
    return this.records.filter((r) => r.grant === grant).map((r) => r.stage);
  }
}
