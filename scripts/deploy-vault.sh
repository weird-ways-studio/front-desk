#!/bin/sh
# Deploys the vault Worker (vault/wrangler.jsonc) just before the front desk.
# Who runs this: wrangler itself, as the front desk's custom build step ("build.command" in
# ../wrangler.jsonc), on every `wrangler deploy`. It acts only inside Cloudflare Workers Builds
# (WORKERS_CI=1) on a real deploy of main, using the build's own token, so the one existing
# Builds connection ships both Workers. Anywhere else (tests, local dry-runs) it does nothing.
# If the vault deploy fails, this fails, and the front desk is not deployed either.
set -eu
if [ "${WORKERS_CI:-}" = "1" ] && [ "${WRANGLER_COMMAND:-}" = "deploy" ] && [ "${WORKERS_CI_BRANCH:-}" = "main" ]; then
  echo "deploy-vault: deploying front-desk-vault first"
  exec npx wrangler deploy -c vault/wrangler.jsonc
fi
echo "deploy-vault: not a Workers Builds deploy of main; skipping"
