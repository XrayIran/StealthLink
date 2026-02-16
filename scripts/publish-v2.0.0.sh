#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TAG="v2.0.0"
REPO="${GITHUB_REPOSITORY:-XrayIran/StealthLink}"
ASSETS_DIR="${ROOT_DIR}/dist/release-assets"
DRY_RUN=1
PRUNE_OLD_RELEASES=0
PRUNE_KEEP=3
SKIP_LIVE_GATE=0

die() { echo "[ERR] $*" >&2; exit 1; }
log() { echo "[INFO] $*"; }

usage() {
  cat <<EOF
Usage: publish-v2.0.0.sh [--repo owner/name] [--tag v2.0.0] [--yes] [--prune-old-releases] [--prune-keep N] [--skip-live-gate]

Publishes ONLY v2.0.0 assets on GitHub:
  - stealthlink-<os>-<arch>-v2.0.0.zip (all platform ZIPs)
  - stealthlink-ctl (the helper script)
  - SHA256SUMS

Safety defaults:
  - dry-run by default
  - does not touch local git history
  - does NOT delete other releases/tags unless --prune-old-releases is set
  - when pruning, keeps the newest N non-target releases (default: 3)
  - requires explicit --yes to execute remote deletion/publication
  - SHA256 checksums embedded in release notes and uploaded as SHA256SUMS
  - validates dist/live-validation/release-readiness.json passes (skip with --skip-live-gate)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="${2:-}"; shift 2 ;;
    --tag) TAG="${2:-}"; shift 2 ;;
    --yes) DRY_RUN=0; shift ;;
    --prune-old-releases) PRUNE_OLD_RELEASES=1; shift ;;
    --prune-keep) PRUNE_KEEP="${2:-}"; shift 2 ;;
    --skip-live-gate) SKIP_LIVE_GATE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

[[ "${TAG}" == "v2.0.0" ]] || die "This script is intentionally pinned to v2.0.0"
command -v gh >/dev/null 2>&1 || die "gh CLI required"
[[ "${PRUNE_KEEP}" =~ ^[0-9]+$ ]] || die "--prune-keep must be a non-negative integer"

mapfile -t zip_assets < <(ls -1 "${ASSETS_DIR}"/stealthlink-*-v2.0.0.zip 2>/dev/null || true)
((${#zip_assets[@]} > 0)) || die "Missing zip assets in ${ASSETS_DIR}. Run: make release-assets VERSION=v2.0.0"
[[ -f "${ASSETS_DIR}/stealthlink-ctl" ]] || die "Missing ${ASSETS_DIR}/stealthlink-ctl"
[[ -f "${ASSETS_DIR}/SHA256SUMS" ]] || die "Missing ${ASSETS_DIR}/SHA256SUMS"

"${ROOT_DIR}/scripts/release-assets-preflight.sh" --assets-dir "${ASSETS_DIR}" --require-live-validation >/dev/null

READINESS_FILE="${ROOT_DIR}/dist/live-validation/release-readiness.json"
if ((SKIP_LIVE_GATE == 0)); then
  [[ -f "${READINESS_FILE}" ]] || die "Live-gate failed: ${READINESS_FILE} not found. Re-run preflight or pass --skip-live-gate to bypass."
  gate=$(python3 - "${READINESS_FILE}" <<'PY'
import json, sys
path = sys.argv[1]
data = json.load(open(path, 'r', encoding='utf-8'))
if data.get('overall') == 'pass':
    print('pass')
    raise SystemExit(0)
if data.get('pass') is True:
    print('pass')
    raise SystemExit(0)
print('fail')
raise SystemExit(2)
PY
  ) || die "Live-gate failed: release-readiness.json does not indicate pass (expected overall=pass or pass=true). Fix validation errors or pass --skip-live-gate to bypass."
  [[ "${gate}" == "pass" ]] || die "Live-gate failed: release-readiness.json does not indicate pass (expected overall=pass or pass=true). Fix validation errors or pass --skip-live-gate to bypass."
  log "Live-gate passed (release-readiness.json indicates pass)"
else
  log "Live-gate skipped (--skip-live-gate)"
fi

log "Repository: ${REPO}"
log "Tag: ${TAG}"
log "ZIP assets:"
for z in "${zip_assets[@]}"; do
  log "  - ${z}"
done
log "Helper script: ${ASSETS_DIR}/stealthlink-ctl"
log "Checksums: ${ASSETS_DIR}/SHA256SUMS"

checksums=""
for z in "${zip_assets[@]}"; do
  sum=$(sha256sum "$z" | awk '{print $1}')
  name=$(basename "$z")
  checksums+="\`${sum}\`  ${name}\n"
done
ctl_sum=$(sha256sum "${ASSETS_DIR}/stealthlink-ctl" | awk '{print $1}')
checksums+="\`${ctl_sum}\`  stealthlink-ctl\n"

log "Enumerating existing releases"
if ! release_lines="$(gh release list --repo "${REPO}" --limit 200 --json tagName --jq '.[].tagName' 2>/dev/null)"; then
  die "Unable to query releases for ${REPO}. Verify repo name and gh auth."
fi
mapfile -t release_tags <<<"${release_lines}"

to_delete=()
if ((PRUNE_OLD_RELEASES == 1)); then
  keep_count=0
  for t in "${release_tags[@]}"; do
    [[ "${t}" == "${TAG}" ]] && continue
    if ((keep_count < PRUNE_KEEP)); then
      keep_count=$((keep_count + 1))
      continue
    fi
    to_delete+=("${t}")
  done
fi

if ((PRUNE_OLD_RELEASES == 1)); then
  if ((${#to_delete[@]} > 0)); then
    log "Will prune old releases/tags (keeping ${PRUNE_KEEP} non-target releases):"
    printf '  - %s\n' "${to_delete[@]}"
  else
    log "Prune enabled, but no old releases/tags need deletion"
  fi
else
  log "Prune disabled; existing releases/tags will not be deleted"
fi

if ((DRY_RUN == 1)); then
  log "Dry run complete. Re-run with --yes to execute."
  exit 0
fi

if ((PRUNE_OLD_RELEASES == 1)); then
  for t in "${to_delete[@]}"; do
    log "Deleting release+tag ${t}"
    gh release delete "${t}" --repo "${REPO}" --yes --cleanup-tag || die "failed deleting ${t}"
  done
fi

release_notes="## StealthLink ${TAG}

### One-Line Install

\`\`\`bash
curl -fsSL https://github.com/XrayIran/StealthLink/releases/latest/download/stealthlink-ctl -o /tmp/stealthlink-ctl && chmod +x /tmp/stealthlink-ctl && sudo /tmp/stealthlink-ctl setup --latest --role both
\`\`\`

### Assets

| File | Description |
|------|-------------|
| stealthlink-linux-amd64-v2.0.0.zip | Linux x86_64 bundle |
| stealthlink-linux-arm64-v2.0.0.zip | Linux ARM64 bundle |
| stealthlink-ctl | Helper control script |
| SHA256SUMS | Release checksums |

### SHA256 Checksums

${checksums}

### Usage

After downloading the bundle for your platform:

\`\`\`bash
unzip stealthlink-linux-\$(uname -m)-v2.0.0.zip
sudo ./stealthlink-ctl install --bundle ./stealthlink-linux-\$(uname -m)-v2.0.0.zip --role both
\`\`\`

Or install directly from GitHub:

\`\`\`bash
curl -fsSL https://github.com/XrayIran/StealthLink/releases/latest/download/stealthlink-ctl -o stealthlink-ctl
chmod +x stealthlink-ctl
sudo ./stealthlink-ctl setup --latest --role both
\`\`\`
"

notes_file=$(mktemp)
echo -e "$release_notes" > "$notes_file"

if gh release view "${TAG}" --repo "${REPO}" >/dev/null 2>&1; then
  log "Refreshing existing ${TAG} release assets"
  log "Updating ${TAG} release notes"
  gh release edit "${TAG}" --repo "${REPO}" --title "StealthLink ${TAG}" --notes-file "$notes_file"
  for z in "${zip_assets[@]}"; do
    gh release delete-asset "${TAG}" "$(basename "$z")" --repo "${REPO}" -y >/dev/null 2>&1 || true
  done
  gh release delete-asset "${TAG}" "stealthlink-ctl" --repo "${REPO}" -y >/dev/null 2>&1 || true
  gh release delete-asset "${TAG}" "SHA256SUMS" --repo "${REPO}" -y >/dev/null 2>&1 || true
else
  log "Creating ${TAG} release"
  gh release create "${TAG}" --repo "${REPO}" --title "StealthLink ${TAG}" --notes-file "$notes_file"
fi

rm -f "$notes_file"

log "Uploading v2.0.0-only assets"
upload_args=()
for z in "${zip_assets[@]}"; do
  upload_args+=("$z")
done
upload_args+=("${ASSETS_DIR}/stealthlink-ctl#stealthlink-ctl")
upload_args+=("${ASSETS_DIR}/SHA256SUMS#SHA256SUMS")

gh release upload "${TAG}" "${upload_args[@]}" --repo "${REPO}" --clobber

log "Done. Published only v2.0.0 assets to ${REPO}."
