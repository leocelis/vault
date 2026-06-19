#!/usr/bin/env bash
# Build vault-cli from this repo and install the binary to ~/.local/bin (or $INSTALL_DIR).
# Usage (from repo root):  ./scripts/install.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f scripts/dev-env.sh ]]; then
  # shellcheck source=/dev/null
  . scripts/dev-env.sh
fi

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"

echo "install: building vault-cli (release)…"
cargo build --release -p vault-cli

BIN="$ROOT/target/release/vault"
install -m 755 "$BIN" "$INSTALL_DIR/vault"

echo "install: installed to $INSTALL_DIR/vault"
echo "install: ensure $INSTALL_DIR is on your PATH"
"$INSTALL_DIR/vault" --version 2>/dev/null || true
