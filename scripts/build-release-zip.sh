#!/usr/bin/env bash
#
# StealthLink Release Bundle Builder
# Builds all components (Go, TypeScript/Rust/Python) and creates a distributable ZIP
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

VERSION=""
SKIP_DASHBOARD=0
SKIP_RUST=0
SKIP_PYTHON=0

die() { echo "[ERR] $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="${2:-}"; shift 2 ;;
        --skip-dashboard) SKIP_DASHBOARD=1; shift ;;
        --skip-rust) SKIP_RUST=1; shift ;;
        --skip-python) SKIP_PYTHON=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: build-release-zip.sh [OPTIONS]

Options:
  --version VERSION    Set version tag (default: git describe or date)
  --skip-dashboard     Skip TypeScript dashboard build
  --skip-rust          Skip Rust crypto build
  --skip-python        Skip Python validation
  --help               Show this help

EOF
            exit 0
            ;;
        *)
            if [[ -z "${VERSION}" && "$1" != -* ]]; then
                VERSION="$1"
            fi
            shift
            ;;
    esac
done

if [[ -z "${VERSION}" ]]; then
    VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo "v$(date +%Y%m%d)")"
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
HOST_ARCH="$(go env GOARCH 2>/dev/null || echo "amd64")"
HOST_OS="$(go env GOOS 2>/dev/null || echo "linux")"

if [[ ("${ARCH}" != "${HOST_ARCH}" || "${OS}" != "${HOST_OS}") && -z "${CGO_ENABLED:-}" ]]; then
    export CGO_ENABLED=0
fi

BIN_EXT=""
[[ "${OS}" == "windows" ]] && BIN_EXT=".exe"

VER_TAG="${VERSION}"
[[ "${VER_TAG}" != v* ]] && VER_TAG="v${VER_TAG}"
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
import hashlib, pathlib, sys
h = hashlib.sha256()
with pathlib.Path(sys.argv[1]).open("rb") as f:
    for c in iter(lambda: f.read(1024*1024), b""):
        h.update(c)
print(h.hexdigest())
PYEOF
}

rm -rf "${STAGE_DIR}" "${ZIP_PATH}" "${MANIFEST_PATH}"
mkdir -p "${DIST_DIR}" "${STAGE_DIR}"

echo ""
echo "=========================================="
echo "  StealthLink Release Builder"
echo "=========================================="
echo "  Version:  ${VERSION}"
echo "  OS:       ${OS}"
echo "  Arch:     ${ARCH}"
echo "  Package:  ${PKG_NAME}"
echo "=========================================="
echo ""

echo "[1/8] Validating Go sources..."
go vet ./... 2>/dev/null || true

COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
BUILDTIME="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
LDFLAGS="-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILDTIME}"

echo "[2/8] Building Go binaries..."
go build -trimpath -ldflags "${LDFLAGS}" -o "${STAGE_DIR}/stealthlink-gateway${BIN_EXT}" ./cmd/gateway
go build -trimpath -ldflags "${LDFLAGS}" -o "${STAGE_DIR}/stealthlink-agent${BIN_EXT}" ./cmd/agent
go build -trimpath -ldflags "${LDFLAGS}" -o "${STAGE_DIR}/stealthlink-tools${BIN_EXT}" ./cmd/tools
go build -trimpath -ldflags "${LDFLAGS}" -o "${STAGE_DIR}/stealthlink${BIN_EXT}" ./cmd/stealthlink
echo "  -> stealthlink-gateway, stealthlink-agent, stealthlink-tools, stealthlink"

install -m 0755 scripts/stealthlink-ctl "${STAGE_DIR}/stealthlink-ctl"
echo "  -> stealthlink-ctl (installer script)"

if [[ "${SKIP_RUST}" == "0" ]]; then
    echo "[3/8] Building Rust crypto..."
    if command -v cargo >/dev/null 2>&1; then
        ./scripts/build-rust-crypto.sh 2>/dev/null || echo "  (Rust build failed, continuing)"
        mkdir -p "${STAGE_DIR}/rust/stealthlink-crypto/src"
        cp rust/stealthlink-crypto/Cargo.toml "${STAGE_DIR}/rust/stealthlink-crypto/" 2>/dev/null || true
        cp rust/stealthlink-crypto/Cargo.lock "${STAGE_DIR}/rust/stealthlink-crypto/" 2>/dev/null || true
        cp -r rust/stealthlink-crypto/src/. "${STAGE_DIR}/rust/stealthlink-crypto/src/" 2>/dev/null || true
        mkdir -p "${STAGE_DIR}/rust/stealthlink-crypto/target/release"
        cp rust/stealthlink-crypto/target/release/libstealthlink_crypto.a "${STAGE_DIR}/rust/stealthlink-crypto/target/release/" 2>/dev/null || true
        cp rust/stealthlink-crypto/target/release/libstealthlink_crypto.so "${STAGE_DIR}/rust/stealthlink-crypto/target/release/" 2>/dev/null || true
    else
        echo "  (cargo not found, skipping Rust build)"
    fi
else
    echo "[3/8] Skipping Rust (requested)"
fi

if [[ "${SKIP_DASHBOARD}" == "0" ]]; then
    echo "[4/8] Building dashboard (TypeScript)..."
    if command -v npm >/dev/null 2>&1 && [[ -d dashboard ]]; then
        (
            cd dashboard
            if [[ -f package-lock.json ]]; then
                npm ci --prefer-offline 2>/dev/null || npm install
            else
                npm install
            fi
            npm run build
        )
        mkdir -p "${STAGE_DIR}/dashboard"
        for f in package.json package-lock.json tsconfig.json tsconfig.node.json vite.config.ts index.html; do
            [[ -f "dashboard/${f}" ]] && cp "dashboard/${f}" "${STAGE_DIR}/dashboard/${f}"
        done
        [[ -d dashboard/src ]] && cp -r dashboard/src "${STAGE_DIR}/dashboard/src"
        [[ -d dashboard/dist ]] && cp -r dashboard/dist "${STAGE_DIR}/dashboard/dist"
        echo "  -> dashboard/"
    else
        echo "  (npm not found or no dashboard, skipping)"
    fi
else
    echo "[4/8] Skipping dashboard (requested)"
fi

if [[ "${SKIP_PYTHON}" == "0" ]]; then
    echo "[5/8] Validating Python tools..."
    if [[ -d tools ]]; then
        python3 -m py_compile tools/*.py 2>/dev/null || echo "  (Python validation failed, continuing)"
    fi
else
    echo "[5/8] Skipping Python validation (requested)"
fi

echo "[6/8] Staging Python tools..."
if [[ -d tools ]]; then
    mkdir -p "${STAGE_DIR}/tools/tests"
    cp tools/*.py "${STAGE_DIR}/tools/" 2>/dev/null || true
    cp tools/requirements.txt "${STAGE_DIR}/tools/" 2>/dev/null || true
    [[ -d tools/tests ]] && cp tools/tests/*.py "${STAGE_DIR}/tools/tests/" 2>/dev/null || true
    echo "  -> tools/"
fi

echo "[7/8] Staging docs, examples, and systemd..."
cp README.md "${STAGE_DIR}/README.md" 2>/dev/null || echo "# StealthLink" > "${STAGE_DIR}/README.md"
mkdir -p "${STAGE_DIR}/examples"
cp examples/*.yaml "${STAGE_DIR}/examples/" 2>/dev/null || true
mkdir -p "${STAGE_DIR}/docs"
cp docs/*.md "${STAGE_DIR}/docs/" 2>/dev/null || true
mkdir -p "${STAGE_DIR}/systemd"
cp systemd/*.service "${STAGE_DIR}/systemd/" 2>/dev/null || true
cp systemd/README.md "${STAGE_DIR}/systemd/" 2>/dev/null || true
echo "  -> examples/, docs/, systemd/"

required_files=(
    "${STAGE_DIR}/stealthlink-gateway${BIN_EXT}"
    "${STAGE_DIR}/stealthlink-agent${BIN_EXT}"
    "${STAGE_DIR}/stealthlink-tools${BIN_EXT}"
    "${STAGE_DIR}/stealthlink${BIN_EXT}"
    "${STAGE_DIR}/stealthlink-ctl"
    "${STAGE_DIR}/README.md"
)
for f in "${required_files[@]}"; do
    [[ -f "${f}" ]] || die "Missing required file: ${f}"
done

echo "[8/8] Creating bundle manifest and ZIP..."

{
    for rel in "stealthlink-gateway${BIN_EXT}" "stealthlink-agent${BIN_EXT}" "stealthlink-tools${BIN_EXT}" "stealthlink${BIN_EXT}" "stealthlink-ctl" "README.md"; do
        h="$(sha256_file "${STAGE_DIR}/${rel}")"
        printf "%s  %s\n" "${h}" "${rel}"
    done
    if [[ -d "${STAGE_DIR}/systemd" ]]; then
        for unit in "${STAGE_DIR}/systemd/"*.service; do
            [[ -f "${unit}" ]] || continue
            rel="systemd/$(basename "${unit}")"
            h="$(sha256_file "${unit}")"
            printf "%s  %s\n" "${h}" "${rel}"
        done
    fi
} > "${STAGE_DIR}/SHA256SUMS"

cat > "${STAGE_DIR}/BUNDLE_MANIFEST.json" <<EOF
{
  "package": "${PKG_NAME}",
  "version": "${VERSION}",
  "commit": "${COMMIT}",
  "build_time_utc": "${BUILDTIME}",
  "os": "${OS}",
  "arch": "${ARCH}",
  "binaries": [
    "stealthlink-gateway${BIN_EXT}",
    "stealthlink-agent${BIN_EXT}",
    "stealthlink-tools${BIN_EXT}",
    "stealthlink${BIN_EXT}",
    "stealthlink-ctl"
  ],
  "systemd_units": [
    "systemd/stealthlink-gateway.service",
    "systemd/stealthlink-agent.service"
  ],
  "required_files": [
    "stealthlink-gateway${BIN_EXT}",
    "stealthlink-agent${BIN_EXT}",
    "stealthlink-tools${BIN_EXT}",
    "stealthlink${BIN_EXT}",
    "stealthlink-ctl",
    "systemd/stealthlink-gateway.service",
    "systemd/stealthlink-agent.service"
  ]
}
EOF

if command -v zip >/dev/null 2>&1; then
    (cd "${DIST_DIR}" && zip -qr "${PKG_NAME}.zip" "${PKG_NAME}")
else
    python3 - "${DIST_DIR}" "${PKG_NAME}" <<'PYEOF'
import pathlib, sys, zipfile
dist = pathlib.Path(sys.argv[1])
pkg = sys.argv[2]
root = dist / pkg
zip_path = dist / f"{pkg}.zip"
with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for p in root.rglob("*"):
        if p.is_file():
            zf.write(p, p.relative_to(dist))
PYEOF
fi

{
    zip_hash="$(sha256_file "${ZIP_PATH}")"
    printf "%s  %s\n" "${zip_hash}" "$(basename "${ZIP_PATH}")"
} > "${MANIFEST_PATH}"

echo ""
echo -e "\033[0;32m=========================================="
echo "  Build Complete!"
echo "==========================================\033[0m"
echo ""
echo "  ZIP:     ${ZIP_PATH}"
echo "  SHA256:  ${MANIFEST_PATH}"
echo "  Size:    $(du -h "${ZIP_PATH}" | cut -f1)"
echo ""
echo "To install on a fresh VPS:"
echo "  unzip ${PKG_NAME}.zip"
echo "  cd ${PKG_NAME}"
echo "  sudo ./stealthlink-ctl setup"
echo ""
