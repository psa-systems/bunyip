#!/bin/sh
# Generate the runtime OIDC config the SPA fetches at boot, then start Caddy.
#
# The bunyip-web image is environment-agnostic: the OIDC values come from the
# container's environment at startup and are written to /config.json (which
# Caddy serves with Cache-Control: no-store). One image therefore serves any
# environment - change the env, restart the container, no rebuild.
#
# appuser owns /usr/share/caddy (set in the Dockerfile), so it can write here.
# jq emits the JSON so values containing quotes/backslashes can't corrupt it.
set -eu

jq -n \
    --arg issuer "${BUNYIP_OIDC_ISSUER:-}" \
    --arg client_id "${BUNYIP_OIDC_CLIENT_ID:-}" \
    --arg redirect_uri "${BUNYIP_OIDC_REDIRECT_URI:-}" \
    --arg scopes "${BUNYIP_OIDC_SCOPES:-openid email offline_access}" \
    '{issuer: $issuer, client_id: $client_id, redirect_uri: $redirect_uri, scopes: $scopes}' \
    > /usr/share/caddy/config.json

exec caddy run --config /etc/caddy/Caddyfile
