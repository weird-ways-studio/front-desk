# front-desk

Off-box service that lets studio agents ask for narrow, short-lived access, approved by Ben's passkey on his phone. Card C5c-1 ebd61173, epic 46fc7b61. Design: `~/studio/studio-os/docs/specifications/face-id-access/C4-SPIKE.md`.

## Rules for agents working here

- This repo is PUBLIC (Ben, 2026-10-25). No secrets, hostnames of the live front desk, or account IDs in code or docs. The pre-commit hook refuses the known ones (`~/studio/studio-os/scripts/public_repo_guard.py`, list in private studio-os `hooks/public-repo-deny/front-desk.txt`; add new IDs there, never here).
- `main` deploys to Cloudflare automatically and only through Ben's approved pull request (ruleset `protect-main`). Never ask for or use a bypass.
- Installs and the local runtime run through `~/studio/studio-os/scripts/sandbox-run` (third-party code).
- Every safeguard gets a test that fails when the safeguard is removed (instruction.control-must-refuse-unsafe-case).

## Where behavior lives

- `src/index.ts` -- Worker entry (named by `main` in `wrangler.jsonc`); forwards every request to the one Durable Object `FrontDesk`.
- `src/agent.ts` -- recognises the c-box agent from its verified Access service-token ticket.
- `src/routes.ts` -- HTTP routes. `src/desk.ts` -- grant, approval, collect and log rules. `src/jobs.ts` -- the fixed job list. `src/page.ts` -- phone pages.
- `src/cboxkey.ts` -- checks the c-box signature on key requests and collects; `scripts/agent.mjs` -- the c-box side (makes the key, signs requests). No libraries in either.
- `vault/` -- the second Worker `front-desk-vault`: sealed master key and the jobs that use it. No libraries allowed (enforced by `test/vault.test.ts`). The front desk reaches it only through the service binding `VAULT` declared in `wrangler.jsonc`; the RPC methods live in `vault/src/index.ts`, the rules in `vault/src/vault.ts`, the sealing in `vault/src/seal.ts`, its one-time setup page in `vault/src/setup.ts`.
- Nightly headcount (card C5c-2 3baea7cc): Cloudflare runs `scheduled()` in `src/index.ts` on the cron in `wrangler.jsonc` "triggers" -- nothing in the routes calls it. It asks the vault (`headcount()` in `vault/src/vault.ts`, using the list-only key made by job `cf.token.headcount.setup`), logs `headcount_ok` / `headcount_mismatch` (`src/desk.ts` `headcount`), and pings healthchecks.io (`headcountAlarm`): all-clear on a clean count, `/fail` otherwise -- and on a fail also pushes the detail to ntfy (dashboard secret `NTFY_TOPIC_URL`), because the healthchecks alert does not carry it. The ping URL is the dashboard secret `HC_HEADCOUNT_URL`; a night with no all-clear alerts Ben's phone.
- Approval pushes (card a830d543): `route()` in `src/routes.ts` sends one push per accepted `/request` (`approvalPush` in `src/desk.ts`): Pushover first (dashboard secrets `PUSHOVER_USER`, `PUSHOVER_TOKEN`), then ntfy (`NTFY_TOPIC_URL`), because ntfy.sh refuses Cloudflare Workers' shared addresses (429), with ntfy's `Click` set to the approve page, and returns `pushed` (with `push_error` naming why when it is false: no topic set, or what ntfy answered) so the agent sends Ben the link itself. The agent learns the result with `node scripts/agent.mjs wait <collect-url>`, which re-sends a signed collect every 5 s until Ben approves.
- GitHub (card C6a-1 8c48215f): `vault/src/github.ts` signs in as a GitHub App with WebCrypto, mints one-hour installation keys and lists what can reach the org. Two Apps, made by Ben on the vault's `/github` pages (`vault/src/ghsetup.ts`, GitHub's manifest flow; the key goes GitHub -> vault): the main App, whose key is sealed to Ben's passkey by job `gh.app.baseline`, and the read-only headcount App, whose key is kept unsealed for the nightly run. The same job records the org's expected list; the nightly headcount (`vault.ts` `ghHeadcount`) names every addition or removal. Rerun the job to accept changes Ben made: the front desk asks the vault (`ghPreview`, no tap) for the exact changes at /request, Ben's screen lists them, and the vault refuses if GitHub changed before his tap. Before each read the headcount App checks itself (still read-only, still on all repositories). Recovery: none built. If Ben's passkey is lost the main key cannot be opened; Ben deletes both Apps on GitHub (organization settings > GitHub Apps), which kills their keys, and reconnecting needs a vault reset that does not exist yet.
- What Ben reads (proposed rule instruction.orient-the-person, not yet in force): each job in `src/jobs.ts` has `explain()` (what approving does, anything to check, what happens on the tap, the exact text) and `done()` (the plain sentence after the tap, sent as `summary` by the approve route in `src/routes.ts`); `src/page.ts` `approvePage` shows them as Step 1 of 2 / Step 2 of 2 with the exact text folded under "Exact details". `src/ghplain.ts` turns the vault's GitHub lines into grouped words; `src/desk.ts` `headcountWords` writes the nightly alarm. `test/guide.test.ts` fails if technical text is in view or a result sentence is raw data. The vault's `/github` setup pages are five numbered steps (`vault/src/ghsetup.ts`).
- Deploys: Workers Builds runs `npx wrangler deploy`; wrangler first runs `build.command` from `wrangler.jsonc`, i.e. `scripts/deploy-vault.sh`, which deploys the vault (only in Workers Builds on main).

## Release Checklist

1. [command] `npm test` passes
2. [command] `npx tsc --noEmit` passes
3. [command] `npx wrangler deploy --dry-run --outdir /tmp/fd-dist` succeeds (run inside sandbox-run)
3a. [command] `npx wrangler deploy --dry-run -c vault/wrangler.jsonc --outdir /tmp/fd-vault` succeeds (run inside sandbox-run)
4. [command] `python3 ~/studio/studio-os/scripts/public_repo_guard.py front-desk --all` passes (no listed hostname or ID in files or history)
4a. [inspect] No secret, live hostname or account ID added to the repo that the list does not yet hold (add it there).
5. [inspect] Every new refusal has a test shown failing with the safeguard removed.
