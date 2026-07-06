#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="${1:-}"
if [[ -z "${REPOSITORY}" ]]; then
  REPOSITORY="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
fi

required_secrets=(
  AWS_HOST
  AWS_SSH_PRIVATE_KEY
  AWS_SSH_USER
  GHCR_TOKEN
  GHCR_USERNAME
)

missing=()
for secret_name in "${required_secrets[@]}"; do
  if [[ -z "${!secret_name:-}" ]]; then
    missing+=("${secret_name}")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'Missing required environment variables for %s:\n' "${REPOSITORY}" >&2
  printf '  - %s\n' "${missing[@]}" >&2
  exit 1
fi

echo "Setting required AWS/GHCR GitHub Actions secrets for ${REPOSITORY}."
for secret_name in "${required_secrets[@]}"; do
  printf '%s' "${!secret_name}" | gh secret set "${secret_name}" --repo "${REPOSITORY}"
done

echo "Configured secret names:"
gh secret list --repo "${REPOSITORY}"
