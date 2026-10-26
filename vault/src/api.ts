// The vault's RPC surface as the front desk sees it (types only; nothing runs from here).

import type { ProbeResult } from "./vault.ts";

export type { ProbeResult };

export interface VaultApi {
  status(): Promise<{ stored: boolean; token_id?: string }>;
  setup(prf: string, parent: string): Promise<{ token_id: string; recovery_key: string }>;
  run(job: string, params: Record<string, string>, prf: string): Promise<ProbeResult>;
}
