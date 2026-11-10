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
- **Jobs (`src/jobs.ts`, and checked again in `vault/src/vault.ts`):** the fixed list is printed by `GET /menu` (`node scripts/agent.mjs menu <desk-url>`), generated from `JOBS`, so this README does not repeat it. Today: `test.echo`; the read jobs `cf.zone.read`, `cf.dns.list`, `cf.audit.read` (the vault reads with short keys and hands the agent only the answer); `cbox.key.enroll`; `cf.token.headcount.setup`; `gh.app.baseline`; `cf.token.accept`. No job hands a key to the agent (`cf.token.zone.read` retired 2026-11-03) and none writes DNS (`cf.dns.txt.probe` cut 2026-11-08, card c653a0fd). A stored grant for a job no longer listed is refused (`Desk.grant()`).
- **Nightly count and accepting a known key:** the cron in `wrangler.jsonc` runs `Desk.headcount` (`src/desk.ts`), which asks the vault to list every Cloudflare key with its list-only key and compare with what it expects (`vault/src/vault.ts` `headcount`, rule in `unexpectedKeys`), plus GitHub against the list Ben accepted. A failed night pings healthchecks.io `/fail` and pushes the plain-words detail to Ben's phone through Pushover (`headcountAlarm`). When a flagged key is ours, job `cf.token.accept` names each flagged key on Ben's screen (read at request time, `cfPreview`); his tap adds exactly those ids to what the count and every job's audit expect, only if each is still in the account and still unexpected. It makes, changes or deletes nothing in Cloudflare.
- **Headcount runs agents can read (card build 5 6ab972c8):** each run of the count publishes a summary (counts, fixed error codes, the repo names added or removed; no key, member or App strings) and the last 14 are kept (`src/headcountrun.ts`). `GET /headcount` needs the agent login; Ben's login and unknown callers get 403. `node scripts/agent.mjs headcount <desk-url> [--after <iso> --repo <name>]` prints them and one verdict: PASS only for a clean run with nothing missing before it; FAIL when the run alarmed; UNPROVEN for anything missing, stale, errored, cut off or overlapping the change. Runs are named by when they started, never as "nights". Limit: a summary reports what the count found; it proves neither that the alarm was attempted (the summary is saved just before the alarm call) nor that Ben's phone got it. "Alarmed" in a verdict means the run's result was not clean (`ok` false).
- **Limits:** (1) until Ben's first tap (at most 30 minutes, then both are erased), the key is sealed under a key the vault itself holds, so vault code alone could open it; (2) the first tap's passkey secret passes through the front desk, so a tampered front desk at that moment could lock the key to a secret of its own (it still could not read the key); (3) each later tap's secret also passes through the front desk -- a captured secret opens nothing by itself, because the sealed key never leaves the vault, but it could ask for a job from the fixed list. The deploy lock is the control for a tampered front desk.

## Recorded before it runs (card 97a2e83d)

- **What:** every grant is recorded in the Observatory's recorder (another Cloudflare account; observatory `RECORDS.md`) at four points, each before the next step can happen: the `request` and then the `verdict` before the grant exists, Ben's `approval` (with the public parts of his passkey answer, never its secret) before anything runs or can be collected, and the `result` (`done` or `failed` only) after it ran. The `verdict` is `{overseer: "not_checked"}` for now: no overseer reviews requests yet, and Ben's approval page says so in one line ("Second check: none yet", `SECOND_CHECK` in `src/page.ts`; card 6da30339). A grant without a verdict receipt is never approved. Code: `src/recorder.ts` (the client: a receipt counts only if it names this grant, this stage and the SHA-256 of the exact bytes sent) and `Desk.record` / `recordResult` in `src/desk.ts`.
- **No receipt, no run:** no request receipt -> the agent gets `recorder_unavailable` and nothing waits for Ben; no approval receipt -> the grant is `stopped`, Ben's page says not approved, nothing runs. A result that cannot be recorded is logged `result_unrecorded` (the job already ran).
- **Settings (dashboard, kept by `keep_vars`):** `RECORDER_URL` (the recorder's `/v1/records` address, a plain variable: a live hostname stays out of this public repo), and the secrets `RECORDER_CLIENT_ID` and `RECORDER_CLIENT_SECRET`, the recorder's service token, which Ben pastes. Any one missing = every request refused. A job that ran but whose result could not be recorded is also pushed to Ben's phone.
- **Not recorded:** the nightly count (not a grant). **Limit:** a tampered front-desk deploy could skip recording; Ben's review of `main` is the control, and the Observatory's later auditor the cross-check.

## The c-box signing key

Proof that a key request comes from the c-box, not just from someone holding the agent's Access login, without a fixed home IP (design and review: studio-os `docs/specifications/face-id-access/C5C1-CBOX-ADDRESS-DESIGN.md`).

- **Make it (on the c-box, once):** `node scripts/agent.mjs keygen` writes a P-256 private key to `~/.config/front-desk/cbox-key.pem` (mode 0600; never in 1Password or a repo) and prints its public half and fingerprint.
- **Enroll it:** the agent asks for job `cbox.key.enroll` with the public half and shows Ben the fingerprint in chat; Ben approves by Face ID on a screen showing the same fingerprint (and the key it replaces). Two enrollments approved out of order: the stale one is refused.
- **Use it:** `node scripts/agent.mjs post <url> <json>` signs `METHOD\nPATH\nTIME\nsha256(body)` (checks: `src/cboxkey.ts`). Accepted within 60 seconds and once per signed message (not per signature: ECDSA signatures can be altered into a second valid one).
- **Wait for Ben:** `node scripts/agent.mjs wait <collect-url> [minutes]` collects as soon as Ben approves (each try freshly signed), so no one relays the approval and the 5-minute collect window is not missed. Every `/request` also pushes the approve link to Ben's phone (`pushed` in the answer says whether it went).
- **Lifecycle:** every enrollment and removal bumps a key generation; a key request, its approval and its collect must all fall in one generation, so removing the key stops anything in flight (a secret minted meanwhile is dropped). One enrollment may wait at a time, and at most 3 requests per requester wait for Ben. Collects re-read the grant after the signature check, so two at once cannot both get the secret.
- **Lost or stolen c-box:** Ben opens `/cbox-key` and taps Remove; every key request is refused until a new key is enrolled.
- **Limits:** anyone with full control of the c-box can use the key (as with any option, a TPM included -- the c-box's fTPM is not usable under Linux today). The c-box disk is not encrypted (task 6a25a486).

## Run the tests

`npm test` (Node 22's built-in test runner; no test dependencies).
