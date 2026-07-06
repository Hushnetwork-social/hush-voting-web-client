#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "::error::$*"
  exit 1
}

notice() {
  echo "::notice::$*"
}

has_script() {
  local script_name="$1"
  node -e "const pkg = require('./package.json'); process.exit(pkg.scripts && pkg.scripts[process.argv[1]] ? 0 : 1)" "${script_name}"
}

run_script() {
  local script_name="$1"
  echo "::group::${script_name}"
  case "${PACKAGE_MANAGER_NAME}" in
    npm)
      npm run "${script_name}"
      ;;
    pnpm)
      pnpm run "${script_name}"
      ;;
    yarn)
      yarn run "${script_name}"
      ;;
    *)
      fail "Unsupported package manager: ${PACKAGE_MANAGER_NAME}"
      ;;
  esac
  echo "::endgroup::"
}

if [[ ! -f package.json ]]; then
  notice "No package.json found yet. Skipping frontend build/test until the app scaffold is added."
  exit 0
fi

if ! command -v node >/dev/null 2>&1; then
  fail "Node.js is required for frontend CI."
fi

PACKAGE_MANAGER="$(node -e "const pkg = require('./package.json'); process.stdout.write(pkg.packageManager || '')")"
if [[ -z "${PACKAGE_MANAGER}" ]]; then
  fail "package.json must define packageManager, for example pnpm@10.x."
fi

case "${PACKAGE_MANAGER}" in
  npm@*)
    PACKAGE_MANAGER_NAME="npm"
    [[ -f package-lock.json ]] || fail "npm projects must commit package-lock.json for reproducible CI installs."
    npm ci
    ;;
  pnpm@*)
    PACKAGE_MANAGER_NAME="pnpm"
    [[ -f pnpm-lock.yaml ]] || fail "pnpm projects must commit pnpm-lock.yaml for reproducible CI installs."
    corepack prepare "${PACKAGE_MANAGER}" --activate
    pnpm install --frozen-lockfile
    ;;
  yarn@*)
    PACKAGE_MANAGER_NAME="yarn"
    [[ -f yarn.lock ]] || fail "yarn projects must commit yarn.lock for reproducible CI installs."
    corepack prepare "${PACKAGE_MANAGER}" --activate
    yarn install --immutable
    ;;
  *)
    fail "Unsupported packageManager '${PACKAGE_MANAGER}'. Use npm@, pnpm@, or yarn@."
    ;;
esac

if has_script lint; then
  run_script lint
else
  notice "No lint script found. Skipping lint."
fi

if has_script typecheck; then
  run_script typecheck
else
  notice "No typecheck script found. Skipping typecheck."
fi

has_script build || fail "package.json must define a build script."
run_script build

if has_script test:unit; then
  run_script test:unit
elif has_script test; then
  run_script test
else
  fail "package.json must define test:unit or test for unit tests."
fi

has_script test:e2e:happy-path || fail "package.json must define test:e2e:happy-path for Gherkin happy-path E2E integration tests."
run_script test:e2e:happy-path
