# front-desk

Off-box service that lets studio agents ask for narrow, short-lived access, approved by Ben's passkey on his phone. Card C5c-1 ebd61173, epic 46fc7b61. Design: `~/studio/studio-os/docs/specifications/face-id-access/C4-SPIKE.md`.

## Rules for agents working here

- This repo is PUBLIC (Ben, 2026-10-25). No secrets, hostnames of the live front desk, or account IDs in code or docs.
- `main` deploys to Cloudflare automatically and only through Ben's approved pull request (ruleset `protect-main`). Never ask for or use a bypass.
- Installs and the local runtime run through `~/studio/studio-os/scripts/sandbox-run` (third-party code).
- Every safeguard gets a test that fails when the safeguard is removed (instruction.control-must-refuse-unsafe-case).

## Where behavior lives

- `src/index.ts` -- Worker entry (named by `main` in `wrangler.jsonc`); forwards every request to the one Durable Object `FrontDesk`.
- `src/agent.ts` -- recognises the c-box agent from its verified Access service-token ticket.
- `src/routes.ts` -- HTTP routes. `src/desk.ts` -- grant, approval, collect and log rules. `src/jobs.ts` -- the fixed job list. `src/page.ts` -- phone pages.
- `vault/` -- the second Worker `front-desk-vault`: sealed master key and the jobs that use it. No libraries allowed (enforced by `test/vault.test.ts`). The front desk reaches it only through the service binding `VAULT` declared in `wrangler.jsonc`; the RPC methods live in `vault/src/index.ts`, the rules in `vault/src/vault.ts`, the sealing in `vault/src/seal.ts`.

## Release Checklist

1. [command] `npm test` passes
2. [command] `npx tsc --noEmit` passes
3. [command] `npx wrangler deploy --dry-run --outdir /tmp/fd-dist` succeeds (run inside sandbox-run)
3a. [command] `npx wrangler deploy --dry-run -c vault/wrangler.jsonc --outdir /tmp/fd-vault` succeeds (run inside sandbox-run)
4. [inspect] No secret, live hostname or account ID added to the repo.
5. [inspect] Every new refusal has a test shown failing with the safeguard removed.
