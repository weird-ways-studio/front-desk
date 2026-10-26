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

A second Worker, `front-desk-vault`, holds the master key: a Cloudflare token that can make other tokens. It is kept apart so the code that can open the master key loads **no libraries** (the front desk itself uses two: passkey checks and Access-ticket checks). `test/vault.test.ts` fails if any vault file imports anything but a file beside it or `cloudflare:workers`.

- **How the front desk reaches it:** the service binding `VAULT` (`services` in `wrangler.jsonc`), calling the methods in `vault/src/index.ts` over RPC. The vault opens the key only to run one job from the fixed list, and never returns it.
- **Setup, once:** Ben opens the vault's own address at `/setup` (behind the same account-wide Access login; the vault accepts only a login with an email, i.e. Ben, never the agent's service token). A plain form, no script: the token goes from his phone straight to the vault, never through the front desk. The vault checks it with Cloudflare, holds it sealed under a one-time key, seals a copy under a new paper recovery key (shown once), and from then on its address answers 404.
- **Locking to the passkey:** Ben's next approval tap sends his passkey's secret (WebAuthn PRF) with the job; the vault re-seals the key under it and forgets the one-time key. If no tap comes within 30 minutes, the setup lapses and can be done again.
- **Deploy:** the existing Workers Builds connection deploys both Workers. Wrangler runs the front desk's custom build step (`build.command` in `wrangler.jsonc` -> `scripts/deploy-vault.sh`), which -- only inside Workers Builds on `main` -- deploys the vault first with the build's own token. Anywhere else it does nothing. If the vault deploy fails, the front desk is not deployed.
- **Limits:** (1) for up to 30 minutes after setup, the key is sealed under a key the vault itself holds, so vault code alone could open it; (2) the first tap's passkey secret passes through the front desk, so a tampered front desk at that moment could lock the key to a secret of its own (it still could not read the key); (3) each later tap's secret also passes through the front desk -- a captured secret opens nothing by itself, because the sealed key never leaves the vault, but it could ask for a job from the fixed list. The deploy lock is the control for a tampered front desk.

## Run the tests

`npm test` (Node 22's built-in test runner; no test dependencies).
