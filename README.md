# front-desk

A small service that lets studio agents ask for narrow, short-lived access, which Ben approves with his passkey (Face ID) on his phone.

- Design: `weird-ways-studio/studio-os` docs/specifications/face-id-access/C4-SPIKE.md
- No secrets live in this repo. Master keys are stored encrypted in the service and unlock only with Ben's passkey.
- Every change to `main` needs Ben's approving review; the service deploys only from `main`.
- Public on purpose: the protection rests on keys and review, not on hidden code (Ben, 2026-10-25).
- Hosting departs from studio ADR 017 (self-host on the c-box) because running off the c-box is the control.

## How it deploys (and what stops it)

- Cloudflare **Workers Builds** watches `main` of this repo and deploys it. Builds for any other branch are **off** -- a branch build runs code nobody reviewed with Cloudflare's deploy rights.
- `main` is protected by the `protect-main` ruleset: pull request plus Ben's approval of the latest push; no bypass, no force push, no deletion.
- `wrangler.jsonc` serves the Worker only on its workers.dev address (`workers_dev: true`), which a Cloudflare Access policy allowing only Ben guards; preview URLs stay off (`preview_urls: false`).
- Who is calling: Ben by his Access login email (`OWNER_EMAIL`); the c-box agent by its Access service token, whose signed ticket the Worker checks itself (`src/agent.ts`, settings `AGENT_CLIENT_ID` and `ACCESS_TEAM_DOMAIN`). All three are dashboard variables kept across deploys (`keep_vars`), never in this repo.
- Entry point: `src/index.ts` (`main` in `wrangler.jsonc`); Cloudflare calls its default export's `fetch`.

## The vault (`vault/`)

A second Worker, `front-desk-vault`, holds the master key: a Cloudflare token that can make other tokens. It is kept apart so the code that can open the master key loads **no libraries** (the front desk itself uses two: passkey checks and Access-ticket checks).

- No web address (`workers_dev: false`, no routes in `vault/wrangler.jsonc`). The only way in is the front desk's service binding `VAULT` (`services` in `wrangler.jsonc`), which calls the methods in `vault/src/index.ts` over RPC.
- The master key is stored sealed (AES-GCM) under the secret Ben's passkey releases at his tap (WebAuthn PRF), and again under a paper recovery key shown once at setup (`/setup-master`). It is opened only to run one job from the fixed list and is never returned.
- The vault deploys separately: a second Workers Builds connection on `main`, root directory the repo root, deploy command `npx wrangler deploy -c vault/wrangler.jsonc` (the repo's pinned wrangler). Deploy it before the front desk, whose binding needs it.
- `test/vault.test.ts` fails if any vault file imports anything but a file beside it or `cloudflare:workers`.
- Limits: the token pasted at setup and the passkey secret at each tap pass through the front desk (which runs the libraries) on their way to the vault. A tampered front desk could see them at that moment; the deploy lock is the control for that. A captured passkey secret alone opens nothing -- the sealed key never leaves the vault -- but it could ask the vault for a job from the fixed list.

## Run the tests

`npm test` (Node 22's built-in test runner; no test dependencies).
