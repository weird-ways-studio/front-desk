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
- **Jobs (`src/jobs.ts`, and checked again in `vault/src/vault.ts`):** `cf.dns.txt.probe` -- the vault itself adds, checks and removes one TXT record; nothing is handed out. `cf.token.zone.read` -- a TEST key for the agent: Zone Read on one studio zone (the zone's basic details only, not DNS or settings), expiring after at most 15 minutes, and usable only from the c-box. The front desk makes one only for a request signed with the **c-box signing key** (below) and pins it to that request's address (`CF-Connecting-IP`), shown on the approval screen; the agent collects it with a signed request from the same address. Before handing it over, the vault tries the key from Cloudflare's own network and needs Cloudflare's location refusal (any other error counts as failure), and checks the account holds no unexpected token; if anything is off, the key is deleted instead. Its secret is shown neither to Ben nor in the log, reaches the agent once at collect, and is erased from storage then, or, if never collected, at the next job request or late collect after the 5-minute collect window (with no further requests it stays stored, though the key expires within 15 minutes). The vault remembers keys it handed out and deletes each at its first job after expiry (Cloudflare keeps expired keys listed).
- **Limits:** (1) until Ben's first tap (at most 30 minutes, then both are erased), the key is sealed under a key the vault itself holds, so vault code alone could open it; (2) the first tap's passkey secret passes through the front desk, so a tampered front desk at that moment could lock the key to a secret of its own (it still could not read the key); (3) each later tap's secret also passes through the front desk -- a captured secret opens nothing by itself, because the sealed key never leaves the vault, but it could ask for a job from the fixed list. The deploy lock is the control for a tampered front desk.

## The c-box signing key

Proof that a key request comes from the c-box, not just from someone holding the agent's Access login, without a fixed home IP (design and review: studio-os `docs/specifications/face-id-access/C5C1-CBOX-ADDRESS-DESIGN.md`).

- **Make it (on the c-box, once):** `node scripts/agent.mjs keygen` writes a P-256 private key to `~/.config/front-desk/cbox-key.pem` (mode 0600; never in 1Password or a repo) and prints its public half and fingerprint.
- **Enroll it:** the agent asks for job `cbox.key.enroll` with the public half and shows Ben the fingerprint in chat; Ben approves by Face ID on a screen showing the same fingerprint (and the key it replaces). Two enrollments approved out of order: the stale one is refused.
- **Use it:** `node scripts/agent.mjs post <url> <json>` signs `METHOD\nPATH\nTIME\nsha256(body)` (checks: `src/cboxkey.ts`). Accepted within 60 seconds and once per signed message (not per signature: ECDSA signatures can be altered into a second valid one).
- **Lost or stolen c-box:** Ben opens `/cbox-key` and taps Remove; every key request is refused until a new key is enrolled.
- **Limits:** anyone with full control of the c-box can use the key (as with any option, a TPM included -- the c-box's fTPM is not usable under Linux today). The c-box disk is not encrypted (task 6a25a486).

## Run the tests

`npm test` (Node 22's built-in test runner; no test dependencies).
