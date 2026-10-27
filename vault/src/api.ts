// The vault's RPC surface as the front desk sees it (types only; nothing runs from here).

import type { Headcount, HeadcountSetupResult, MintResult, ProbeResult } from "./vault.ts";

export type { Headcount, HeadcountSetupResult, MintResult, ProbeResult };

export interface VaultApi {
  status(): Promise<{ stored: boolean; pending: boolean; token_id?: string }>;
  run(job: string, params: Record<string, string>, prf: string): Promise<ProbeResult | MintResult | HeadcountSetupResult>;
  headcount(): Promise<Headcount>;
}
