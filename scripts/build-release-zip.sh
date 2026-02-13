#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
    VERSION="$(git describe --tags --always --dirty 2>/dev/null || date +%Y%m%d)"
fi

detect_arch() {
    if [[ -n "${GOARCH:-}" ]]; then
        echo "${GOARCH}"
        return 0
    fi
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l|armv7) echo "armv7" ;;
        *) echo "amd64" ;;
    esac
}

detect_os() {
    if [[ -n "${GOOS:-}" ]]; then
        echo "${GOOS}"
        return 0
    fi
    case "$(uname -s)" in
        Linux) echo "linux" ;;
        Darwin) echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT) echo "windows" ;;
        *) echo "linux" ;;
    esac
}

ARCH="$(detect_arch)"
OS="$(detect_os)"
HOST_ARCH="$(go env GOARCH)"
HOST_OS="$(go env GOOS)"

# Cross-compiling binaries that depend on cgo (for example pcap/libpcap) is
# often unavailable in release environments. Default to CGO off for cross
# targets unless explicitly overridden by the caller.
if [[ ("${ARCH}" != "${HOST_ARCH}" || "${OS}" != "${HOST_OS}") && -z "${CGO_ENABLED:-}" ]]; then
    export CGO_ENABLED=0
fi
BIN_EXT=""
if [[ "${OS}" == "windows" ]]; then
    BIN_EXT=".exe"
fi
VER_TAG="${VERSION}"
if [[ "${VER_TAG}" != v* ]]; then
    VER_TAG="v${VER_TAG}"
fi
PKG_NAME="stealthlink-${OS}-${ARCH}-${VER_TAG}"
DIST_DIR="${ROOT_DIR}/dist"
STAGE_DIR="${DIST_DIR}/${PKG_NAME}"
ZIP_PATH="${DIST_DIR}/${PKG_NAME}.zip"
MANIFEST_PATH="${DIST_DIR}/${PKG_NAME}.SHA256SUMS"

sha256_file() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${path}" | awk '{print $1}'
        return 0
    fi
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${path}" | awk '{print $1}'
        return 0
    fi
    python3 - "${path}" <<'PYEOF'
import hashlib
import pathlib
import sys

p = pathlib.Path(sys.argv[1])
h = hashlib.sha256()
with p.open("rb") as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
        h.update(chunk)
print(h.hexdigest())
PYEOF
}

mkdir -p "${DIST_DIR}"
rm -rf "${STAGE_DIR}" "${ZIP_PATH}" "${MANIFEST_PATH}"
mkdir -p "${STAGE_DIR}"

echo "[1/8] Validating Go sources"
go vet ./...

COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILDTIME="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
LDFLAGS="-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILDTIME}"

echo "[2/8] Building Go binaries (version=${VERSION} commit=${COMMIT})"
go build -ldflags "${LDFLAGS}" -o "${STAGE_DIR}/stealthlink-gateway${BIN_EXT}" ./cmd/gateway
go build -ldflags "${LDFLAGS}" -o "${STAGE_DIR}/stealthlink-agent${BIN_EXT}" ./cmd/agent
go build -ldflags "${LDFLAGS}" -o "${STAGE_DIR}/stealthlink-tools${BIN_EXT}" ./cmd/tools
go build -ldflags "${LDFLAGS}" -o "${STAGE_DIR}/stealthlink${BIN_EXT}" ./cmd/stealthlink
install -m 0755 scripts/stealthlink-ctl "${STAGE_DIR}/stealthlink-ctl"

echo "[3/8] Building Rust crypto"
if command -v cargo >/dev/null 2>&1; then
    ./scripts/build-rust-crypto.sh
else
    echo "cargo not found; skipping Rust build"
fi

mkdir -p "${STAGE_DIR}/rust/stealthlink-crypto/src"
cp rust/stealthlink-crypto/Cargo.toml "${STAGE_DIR}/rust/stealthlink-crypto/"
cp rust/stealthlink-crypto/Cargo.lock "${STAGE_DIR}/rust/stealthlink-crypto/" || true
cp -r rust/stealthlink-crypto/src/. "${STAGE_DIR}/rust/stealthlink-crypto/src/"
mkdir -p "${STAGE_DIR}/rust/stealthlink-crypto/target/release"
cp rust/stealthlink-crypto/target/release/libstealthlink_crypto.a "${STAGE_DIR}/rust/stealthlink-crypto/target/release/" 2>/dev/null || true
cp rust/stealthlink-crypto/target/release/libstealthlink_crypto.so "${STAGE_DIR}/rust/stealthlink-crypto/target/release/" 2>/dev/null || true
cp rust/stealthlink-crypto/target/release/libstealthlink_crypto.dylib "${STAGE_DIR}/rust/stealthlink-crypto/target/release/" 2>/dev/null || true

echo "[4/8] Building dashboard (TypeScript)"
if command -v npm >/dev/null 2>&1; then
    (
        cd dashboard
        npm install
        npm run build
    )
else
    echo "npm not found; skipping dashboard build"
fi

mkdir -p "${STAGE_DIR}/dashboard"
for f in package.json package-lock.json tsconfig.json tsconfig.node.json vite.config.ts index.html; do
    if [[ -f "dashboard/${f}" ]]; then
        cp "dashboard/${f}" "${STAGE_DIR}/dashboard/${f}"
    fi
done
if [[ -d dashboard/src ]]; then
    cp -r dashboard/src "${STAGE_DIR}/dashboard/src"
fi
if [[ -d dashboard/dist ]]; then
    cp -r dashboard/dist "${STAGE_DIR}/dashboard/dist"
fi

echo "[5/8] Validating Python tools"
python3 -m py_compile tools/*.py

echo "[6/8] Staging Python tools"
mkdir -p "${STAGE_DIR}/tools/tests"
cp tools/*.py "${STAGE_DIR}/tools/"
cp tools/requirements.txt "${STAGE_DIR}/tools/" 2>/dev/null || true
if [[ -d tools/tests ]]; then
    cp tools/tests/*.py "${STAGE_DIR}/tools/tests/" 2>/dev/null || true
fi

echo "[7/8] Staging docs, examples, and systemd files"
cp README.md "${STAGE_DIR}/README.md"
mkdir -p "${STAGE_DIR}/examples"
cp examples/*.yaml "${STAGE_DIR}/examples/" 2>/dev/null || true
mkdir -p "${STAGE_DIR}/docs"
cp docs/*.md "${STAGE_DIR}/docs/" 2>/dev/null || true
mkdir -p "${STAGE_DIR}/systemd"
cp systemd/*.service "${STAGE_DIR}/systemd/" 2>/dev/null || true
cp systemd/README.md "${STAGE_DIR}/systemd/" 2>/dev/null || true

required_stage_files=(
    "${STAGE_DIR}/stealthlink-gateway${BIN_EXT}"
    "${STAGE_DIR}/stealthlink-agent${BIN_EXT}"
    "${STAGE_DIR}/stealthlink-tools${BIN_EXT}"
    "${STAGE_DIR}/stealthlink${BIN_EXT}"
    "${STAGE_DIR}/stealthlink-ctl"
    "${STAGE_DIR}/README.md"
)
for f in "${required_stage_files[@]}"; do
    if [[ ! -f "${f}" ]]; then
        echo "Missing required staged file: ${f}" >&2
        exit 1
    fi
done

echo "[8/8] Creating ZIP bundle"
if command -v zip >/dev/null 2>&1; then
    (
        cd "${DIST_DIR}"
        zip -qr "${PKG_NAME}.zip" "${PKG_NAME}"
    )
else
    python3 - "${DIST_DIR}" "${PKG_NAME}" <<'PYEOF'
import pathlib
import sys
import zipfile

dist = pathlib.Path(sys.argv[1])
pkg_name = sys.argv[2]
root = dist / pkg_name
zip_path = dist / f"{pkg_name}.zip"

with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for p in root.rglob("*"):
        zf.write(p, p.relative_to(dist))
PYEOF
fi

{
    zip_hash="$(sha256_file "${ZIP_PATH}")"
    printf "%s  %s\n" "${zip_hash}" "$(basename "${ZIP_PATH}")"
    for staged in "stealthlink-gateway${BIN_EXT}" "stealthlink-agent${BIN_EXT}" "stealthlink-tools${BIN_EXT}" "stealthlink${BIN_EXT}" "stealthlink-ctl" "README.md"; do
        staged_hash="$(sha256_file "${STAGE_DIR}/${staged}")"
        printf "%s  %s/%s\n" "${staged_hash}" "${PKG_NAME}" "${staged}"
    done
} > "${MANIFEST_PATH}"

echo "Release bundle created:"
echo "  ${ZIP_PATH}"
echo "SHA256 manifest:"
echo "  ${MANIFEST_PATH}"
