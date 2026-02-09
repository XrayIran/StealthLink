#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_DIR="${ROOT_DIR}/rust/stealthlink-crypto"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found" >&2
  exit 1
fi

cd "${RUST_DIR}"
cargo build --release

echo "Rust crypto library built at: ${RUST_DIR}/target/release"
