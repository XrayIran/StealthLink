#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TAG="v2.0.0"
REPO="${GITHUB_REPOSITORY:-XrayIran/StealthLink}"
ASSETS_DIR="${ROOT_DIR}/dist/release-assets"
DRY_RUN=1

die() { echo "[ERR] $*" >&2; exit 1; }
log() { echo "[INFO] $*"; }

usage() {
  cat <<EOF
Usage: publish-v2.0.0.sh [--repo owner/name] [--tag v2.0.0] [--yes]

Publishes ONLY v2.0.0 assets on GitHub:
  - stealthlink-<os>-<arch>-v2.0.0.zip
  - stealthlink-ctl
  - SHA256SUMS

Safety defaults:
  - dry-run by default
  - does not touch local git history
  - requires explicit --yes to execute remote deletion/publication
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="${2:-}"; shift 2 ;;
    --tag) TAG="${2:-}"; shift 2 ;;
    --yes) DRY_RUN=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

[[ "${TAG}" == "v2.0.0" ]] || die "This script is intentionally pinned to v2.0.0"
command -v gh >/dev/null 2>&1 || die "gh CLI required"

zip_asset="$(ls -1 "${ASSETS_DIR}"/stealthlink-*-v2.0.0.zip 2>/dev/null | head -1 || true)"
[[ -n "${zip_asset}" ]] || die "Missing zip asset in ${ASSETS_DIR}. Run: make release-assets VERSION=v2.0.0"
[[ -f "${ASSETS_DIR}/stealthlink-ctl" ]] || die "Missing ${ASSETS_DIR}/stealthlink-ctl"
[[ -f "${ASSETS_DIR}/SHA256SUMS" ]] || die "Missing ${ASSETS_DIR}/SHA256SUMS"

log "Repository: ${REPO}"
log "Tag: ${TAG}"
log "Assets:"
log "  - ${zip_asset}"
log "  - ${ASSETS_DIR}/stealthlink-ctl"
log "  - ${ASSETS_DIR}/SHA256SUMS"

log "Enumerating existing releases"
if ! release_lines="$(gh release list --repo "${REPO}" --limit 200 --json tagName --jq '.[].tagName' 2>/dev/null)"; then
  die "Unable to query releases for ${REPO}. Verify repo name and gh auth."
fi
mapfile -t release_tags <<<"${release_lines}"

to_delete=()
for t in "${release_tags[@]}"; do
  [[ "${t}" == "${TAG}" ]] && continue
  to_delete+=("${t}")
done

if (( ${#to_delete[@]} > 0 )); then
  log "Will delete existing releases/tags:"
  printf '  - %s\n' "${to_delete[@]}"
else
  log "No other releases/tags found"
fi

if (( DRY_RUN == 1 )); then
  log "Dry run complete. Re-run with --yes to execute."
  exit 0
fi

for t in "${to_delete[@]}"; do
  log "Deleting release+tag ${t}"
  gh release delete "${t}" --repo "${REPO}" --yes --cleanup-tag || die "failed deleting ${t}"
done

if gh release view "${TAG}" --repo "${REPO}" >/dev/null 2>&1; then
  log "Refreshing existing ${TAG} release assets"
  gh release delete-asset "${TAG}" "$(basename "${zip_asset}")" --repo "${REPO}" -y >/dev/null 2>&1 || true
  gh release delete-asset "${TAG}" "stealthlink-ctl" --repo "${REPO}" -y >/dev/null 2>&1 || true
  gh release delete-asset "${TAG}" "SHA256SUMS" --repo "${REPO}" -y >/dev/null 2>&1 || true
else
  log "Creating ${TAG} release"
  gh release create "${TAG}" --repo "${REPO}" --title "StealthLink ${TAG}" --notes-file docs/RELEASE_NOTES_v2.0.md
fi

log "Uploading v2.0.0-only assets"
gh release upload "${TAG}" \
  "${zip_asset}" \
  "${ASSETS_DIR}/stealthlink-ctl#stealthlink-ctl" \
  "${ASSETS_DIR}/SHA256SUMS#SHA256SUMS" \
  --repo "${REPO}" \
  --clobber

log "Done. Published only v2.0.0 assets to ${REPO}."
