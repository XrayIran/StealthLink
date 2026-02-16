#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

assets_dir="dist/release-assets"
live_validation_dir="dist/live-validation"
require_live_validation=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --assets-dir)
      assets_dir="${2:-}"
      shift 2
      ;;
    --live-validation-dir)
      live_validation_dir="${2:-}"
      shift 2
      ;;
    --require-live-validation)
      require_live_validation=1
      shift
      ;;
    -h|--help)
      cat <<USAGE
Usage: release-assets-preflight.sh [--assets-dir dist/release-assets] [--require-live-validation] [--live-validation-dir dist/live-validation]

Validate release asset policy:
  - stealthlink-<os>-<arch>-v<version>.zip (one or more)
  - stealthlink-ctl
  - SHA256SUMS

When --require-live-validation is set, also require evidence artifacts:
  - validate-live.json
  - stress-live.json
  - profile-live.json
  - release-readiness.json (with overall=pass or pass=true)
  - *-cpu.pb.gz
  - *-heap.pb.gz
USAGE
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

[[ -d "${assets_dir}" ]] || { echo "Missing assets directory: ${assets_dir}" >&2; exit 1; }

shopt -s nullglob
files=("${assets_dir}"/*)
shopt -u nullglob
((${#files[@]} > 0)) || { echo "No assets found in ${assets_dir}" >&2; exit 1; }

has_ctl=0
has_sums=0
zip_count=0

for f in "${files[@]}"; do
  bn="$(basename "${f}")"
  case "${bn}" in
    stealthlink-ctl)
      has_ctl=1
      ;;
    SHA256SUMS)
      has_sums=1
      ;;
    stealthlink-*-*-v*.zip)
      zip_count=$((zip_count + 1))
      ;;
    *)
      echo "Disallowed release asset: ${bn}" >&2
      echo "Allowed: stealthlink-<os>-<arch>-v<version>.zip, stealthlink-ctl, SHA256SUMS" >&2
      exit 1
      ;;
  esac
done

((zip_count > 0)) || { echo "Missing release ZIP asset in ${assets_dir}" >&2; exit 1; }
((has_ctl == 1)) || { echo "Missing stealthlink-ctl in ${assets_dir}" >&2; exit 1; }
((has_sums == 1)) || { echo "Missing SHA256SUMS in ${assets_dir}" >&2; exit 1; }

# Ensure checksum file only references allowed filenames.
while IFS= read -r line; do
  [[ -z "${line}" ]] && continue
  name="${line##*  }"
  case "${name}" in
    stealthlink-ctl|stealthlink-*-*-v*.zip)
      ;;
    *)
      echo "SHA256SUMS references disallowed file: ${name}" >&2
      exit 1
      ;;
  esac
done < "${assets_dir}/SHA256SUMS"

if ((require_live_validation == 1)); then
  [[ -d "${live_validation_dir}" ]] || { echo "Missing live validation directory: ${live_validation_dir}" >&2; exit 1; }

  required_json=(
    "validate-live.json"
    "stress-live.json"
    "profile-live.json"
    "release-readiness.json"
  )
  for f in "${required_json[@]}"; do
    [[ -s "${live_validation_dir}/${f}" ]] || { echo "Missing required live-validation artifact: ${live_validation_dir}/${f}" >&2; exit 1; }
  done

  shopt -s nullglob
  cpu_profiles=("${live_validation_dir}"/*-cpu.pb.gz)
  heap_profiles=("${live_validation_dir}"/*-heap.pb.gz)
  shopt -u nullglob
  ((${#cpu_profiles[@]} > 0)) || { echo "Missing CPU pprof artifact (*-cpu.pb.gz) in ${live_validation_dir}" >&2; exit 1; }
  ((${#heap_profiles[@]} > 0)) || { echo "Missing heap pprof artifact (*-heap.pb.gz) in ${live_validation_dir}" >&2; exit 1; }

  python3 - "${live_validation_dir}/release-readiness.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"Invalid release-readiness.json: {exc}", file=sys.stderr)
    raise SystemExit(1)
overall = data.get("overall")
passed = data.get("pass")
if overall == "pass":
    raise SystemExit(0)
if passed is True:
    raise SystemExit(0)
print("release-readiness.json does not indicate pass (expected overall=pass or pass=true)", file=sys.stderr)
raise SystemExit(1)
PY
fi

echo "Release asset preflight passed for ${assets_dir}" >&2
