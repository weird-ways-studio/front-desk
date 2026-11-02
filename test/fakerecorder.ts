// An in-memory stand-in for the Observatory's recorder (observatory src/contract.ts and
// src/recorder/ledger.ts at 4b7bedd). It refuses what the real one refuses that matters to the desk:
// secret-shaped field names, oversize bodies, a later stage with no recorded request or approval, a
// wrong request hash, and other bytes for an already-recorded stage. `down` makes every write fail.

import type { Receipt, Recorder, Stage } from "../src/recorder.ts";
import { RecorderError } from "../src/recorder.ts";

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

  readonly send: Recorder = async (record) => {
    if (this.down || this.failStage === record.stage) throw new RecorderError("recorder answered 503");
    const body = JSON.stringify({ v: 1, ...record });
    if (new TextEncoder().encode(body).length > MAX_RECORD_BYTES) throw new RecorderError("recorder answered 413");
    if (secretish(record)) throw new RecorderError("recorder answered 400");
    const sha = await sha256Hex(body);
    const mine = this.records.filter((r) => r.grant === record.grant);
    const same = mine.find((r) => r.stage === record.stage);
    if (same) {
      if (same.body !== body) throw new RecorderError("recorder answered 409");
      return { seq: this.records.indexOf(same) + 1, grant: record.grant, stage: record.stage, sha256: sha };
    }
    if (record.stage !== "request") {
      const req = mine.find((r) => r.stage === "request");
      if (!req || record.request !== (await sha256Hex(req.body))) throw new RecorderError("recorder answered 409");
      if (record.stage === "result" && !mine.some((r) => r.stage === "approval")) throw new RecorderError("recorder answered 409");
    }
    this.records.push({ stage: record.stage, grant: record.grant, body, record: JSON.parse(body) });
    return { seq: this.records.length, grant: record.grant, stage: record.stage, sha256: sha } satisfies Receipt;
  };

  stages(grant: string): Stage[] {
    return this.records.filter((r) => r.grant === grant).map((r) => r.stage);
  }
}
