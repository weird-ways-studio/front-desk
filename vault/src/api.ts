// The vault's RPC surface as the front desk sees it (types only; nothing runs from here).

import type { OpRequest, OpResult, RunState } from "./runs.ts";
import type { CfAcceptResult, GhBaselineResult, Headcount, HeadcountSetupResult, ProbeResult, ReadResult } from "./vault.ts";

export type { OpRequest, OpResult, RunState };
export type { CfAcceptResult, GhBaselineResult, Headcount, HeadcountSetupResult, ProbeResult, ReadResult };

export interface VaultApi {
  status(): Promise<{ stored: boolean; pending: boolean; token_id?: string }>;
  run(job: string, params: Record<string, string>, prf: string): Promise<ProbeResult | ReadResult | HeadcountSetupResult | GhBaselineResult | CfAcceptResult>;
  headcount(): Promise<Headcount>;
  ghPreview(): Promise<{ changes: string[]; snapshot: string; base: string }>;
  cfPreview(): Promise<{ id: string; name: string }[]>;
}

// Runs (4a-2a; rules in runs.ts). Separate from VaultApi until the desk uses them (4a-2b).
export interface VaultRunApi {
  runApi(): Promise<{ version: number }>;
  runOp(req: OpRequest): Promise<OpResult>;
  runEnd(id: string, how: "stopped" | "finished"): Promise<{ state: RunState; generation: number }>;
  setKeyRev(rev: number): Promise<number>;
}
