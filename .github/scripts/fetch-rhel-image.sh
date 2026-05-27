#!/usr/bin/env bash
# Download a RHEL 9 QCOW2 from Red Hat Image Builder using the SSO
# client-credentials flow. Polls the compose endpoint until success or failure.
#
# Required env:
#   RH_SSO_CLIENT_ID
#   RH_SSO_CLIENT_SECRET
#   RH_COMPOSE_ID
# Optional args:
#   $1 — output path (default: rhel-image.qcow2)

set -euo pipefail

: "${RH_SSO_CLIENT_ID:?RH_SSO_CLIENT_ID is required}"
: "${RH_SSO_CLIENT_SECRET:?RH_SSO_CLIENT_SECRET is required}"
: "${RH_COMPOSE_ID:?RH_COMPOSE_ID is required}"

OUTPUT_FILE="${1:-rhel-image.qcow2}"
TOKEN_URL="https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
API_URL="https://console.redhat.com/api/image-builder/v1/composes/${RH_COMPOSE_ID}"

ACCESS_TOKEN="$(curl -sS -X POST "$TOKEN_URL" \
  -d "grant_type=client_credentials" \
  -d "client_id=$RH_SSO_CLIENT_ID" \
  -d "client_secret=$RH_SSO_CLIENT_SECRET" | jq -r '.access_token')"
[[ -n "$ACCESS_TOKEN" && "$ACCESS_TOKEN" != "null" ]] || { echo "Failed to obtain access token"; exit 1; }

while true; do
  STATUS="$(curl -sS -H "Authorization: Bearer $ACCESS_TOKEN" "$API_URL" | jq -r '.image_status.status // empty')"
  echo "Compose status: ${STATUS:-unknown}"
  case "$STATUS" in
    success) break ;;
    failure) echo "Compose failed."; exit 1 ;;
    *) sleep 15 ;;
  esac
done

QCOW2_URL="$(curl -sS -H "Authorization: Bearer $ACCESS_TOKEN" "$API_URL" | jq -r '.image_status.upload_status.options.url // empty')"
[[ -n "$QCOW2_URL" ]] || { echo "Download URL not found."; exit 1; }
curl -L -o "$OUTPUT_FILE" "$QCOW2_URL"
