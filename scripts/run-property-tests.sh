#!/usr/bin/env bash
set -euo pipefail

CHECKS="${1:-100}"

if ! command -v rg >/dev/null 2>&1; then
  echo "error: ripgrep (rg) is required to discover property test packages" >&2
  exit 1
fi

mapfile -t PKGS < <(
  rg -l --glob '*_test.go' 'rapid\.Check\(' . \
    | xargs -r -n1 dirname \
    | sed 's#^\./##' \
    | awk '{print "./"$0}' \
    | sort -u
)

if [ "${#PKGS[@]}" -eq 0 ]; then
  echo "No rapid property test packages discovered."
  exit 0
fi

echo "Running property tests with rapid.checks=${CHECKS} in ${#PKGS[@]} package(s)..."
for pkg in "${PKGS[@]}"; do
  echo "  -> ${pkg}"
  go test "${pkg}" -rapid.checks="${CHECKS}"
done

echo "Property tests passed."
