// The vault's RPC surface as the front desk sees it (types only; nothing runs from here).

import type { CfAcceptResult, GhBaselineResult, Headcount, HeadcountSetupResult, MintResult, ProbeResult } from "./vault.ts";

export type { CfAcceptResult, GhBaselineResult, Headcount, HeadcountSetupResult, MintResult, ProbeResult };

export interface VaultApi {
  status(): Promise<{ stored: boolean; pending: boolean; token_id?: string }>;
  run(job: string, params: Record<string, string>, prf: string): Promise<ProbeResult | MintResult | HeadcountSetupResult | GhBaselineResult | CfAcceptResult>;
  headcount(): Promise<Headcount>;
  ghPreview(): Promise<{ changes: string[]; snapshot: string; base: string }>;
  cfPreview(): Promise<{ id: string; name: string }[]>;
}
