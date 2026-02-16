#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

ZIP_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) ZIP_ARGS+=(--version "${2:-}"); shift 2 ;;
    --skip-dashboard|--skip-rust|--skip-python) ZIP_ARGS+=("$1"); shift ;;
    *) ZIP_ARGS+=("$1"); shift ;;
  esac
done

./scripts/build-release-zip.sh "${ZIP_ARGS[@]}"

latest_zip="$(ls -1t dist/stealthlink-*.zip 2>/dev/null | head -1 || true)"
[[ -n "${latest_zip}" ]] || { echo "No release ZIP found in dist/"; exit 1; }

assets_dir="dist/release-assets"
mkdir -p "${assets_dir}"
find "${assets_dir}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
cp -f "${latest_zip}" "${assets_dir}/"
cp -f "scripts/stealthlink-ctl" "${assets_dir}/stealthlink-ctl"
chmod 0755 "${assets_dir}/stealthlink-ctl"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "${assets_dir}" && sha256sum "$(basename "${latest_zip}")" "stealthlink-ctl" >SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  (cd "${assets_dir}" && shasum -a 256 "$(basename "${latest_zip}")" "stealthlink-ctl" >SHA256SUMS)
else
  python3 - "${assets_dir}" "$(basename "${latest_zip}")" <<'PY'
import hashlib, pathlib, sys
assets = pathlib.Path(sys.argv[1])
files = [sys.argv[2], "stealthlink-ctl"]
with (assets / "SHA256SUMS").open("w", encoding="utf-8") as out:
    for rel in files:
        h = hashlib.sha256()
        with (assets / rel).open("rb") as f:
            for c in iter(lambda: f.read(1024 * 1024), b""):
                h.update(c)
        out.write(f"{h.hexdigest()}  {rel}\n")
PY
fi

./scripts/release-assets-preflight.sh --assets-dir "${assets_dir}"

echo "Release assets ready in ${assets_dir}:"
echo "  - $(basename "${latest_zip}")"
echo "  - stealthlink-ctl"
echo "  - SHA256SUMS"
