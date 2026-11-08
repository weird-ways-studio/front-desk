// The vault's RPC surface as the front desk sees it (types only; nothing runs from here).

import type { SignedRun } from "./approval.ts";
import type { OpRequest, OpResult, RunBook, RunState } from "./runs.ts";
import type { CfAcceptResult, CfPreviewKey, GhBaselineResult, Headcount, HeadcountSetupResult, ReadResult } from "./vault.ts";

export type { OpRequest, OpResult, RunState, SignedRun };
export type { CfAcceptResult, CfPreviewKey, GhBaselineResult, Headcount, HeadcountSetupResult, ReadResult };

export interface VaultApi {
  status(): Promise<{ stored: boolean; pending: boolean; token_id?: string }>;
  run(req: SignedRun): Promise<ReadResult | HeadcountSetupResult | GhBaselineResult | CfAcceptResult>;
  headcount(): Promise<Headcount>;
  ghPreview(): Promise<{ changes: string[]; snapshot: string; base: string }>;
  cfPreview(): Promise<CfPreviewKey[]>;
  approvalApi(): Promise<{ version: number }>;
}

// Runs (4a-2a; rules in runs.ts). Separate from VaultApi until the desk uses them (4a-2b).
export interface VaultRunApi {
  runApi(): Promise<{ version: number }>;
  runOp(req: OpRequest): Promise<OpResult>;
  runEnd(id: string, how: "stopped" | "finished"): Promise<{ state: RunState; generation: number }>;
  runStatus(id: string): Promise<ReturnType<RunBook["status"]>>;
  setKeyRev(rev: number): Promise<number>;
}

// Cards (card 85818ab1; rules in cards.ts).
import type { CardOpen, CardRun, CardView, EntryState } from "./cards.ts";
export type { CardOpen, CardRun, CardView, EntryState };
export interface VaultCardApi {
  cardApi(): Promise<{ version: number; jobs_version: number; cap: number }>;
  cardOpen(req: CardOpen): Promise<CardView>;
  cardRun(req: CardRun): Promise<{ state: EntryState; answer?: unknown; card: CardView }>;
  cardStop(card: string): Promise<CardView>;
  cardStatus(card: string): Promise<CardView>;
  cardAck(card: string, index: number): Promise<boolean>;
}
