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
- `wrangler.jsonc` keeps the Worker unreachable (`workers_dev: false`, `preview_urls: false`) until Cloudflare Access sits in front of it.
- Entry point: `src/index.ts` (`main` in `wrangler.jsonc`); Cloudflare calls its default export's `fetch`.

## Run the tests

`npm test` (Node 22's built-in test runner; no test dependencies).
