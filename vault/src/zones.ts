// The only Cloudflare zones a vault job may touch, by name (Codex PR3b-2b r1 #6).
// The front desk imports this list for its request check; the vault checks it again.
export const STUDIO_ZONES: readonly string[] = ["benculbert.com"];
