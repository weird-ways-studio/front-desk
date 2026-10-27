#!/bin/sh
# Deploys the vault Worker (vault/wrangler.jsonc) just before the front desk.
# Who runs this: wrangler itself, as the front desk's custom build step ("build.command" in
# ../wrangler.jsonc), on every `wrangler deploy`. It acts only inside Cloudflare Workers Builds
# (WORKERS_CI=1) on a real deploy of main, using the build's own token, so the one existing
# Builds connection ships both Workers. Anywhere else (tests, local dry-runs) it does nothing.
# If the vault deploy fails, this fails, and the front desk is not deployed either.
# Workers Builds sets WRANGLER_CI_OVERRIDE_NAME (the connected Worker, "front-desk") and
# WRANGLER_CI_MATCH_TAG (its id); wrangler obeys them over any config or --name. Left in place,
# the vault code would be uploaded as the front desk (seen live 2026-10-26, build for 91a710e).
# So they are removed for this one nested deploy, and the name comes from vault/wrangler.jsonc.
set -eu
if [ "${WORKERS_CI:-}" = "1" ] && [ "${WRANGLER_COMMAND:-}" = "deploy" ] && [ "${WORKERS_CI_BRANCH:-}" = "main" ]; then
  echo "deploy-vault: deploying front-desk-vault first"
  exec env -u WRANGLER_CI_OVERRIDE_NAME -u WRANGLER_CI_MATCH_TAG npx wrangler deploy -c vault/wrangler.jsonc
fi
echo "deploy-vault: not a Workers Builds deploy of main; skipping"
