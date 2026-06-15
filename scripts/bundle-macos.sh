#!/usr/bin/env bash
# Build vault-gui (release) and wrap it in a double-clickable macOS .app bundle.
#
# Output: target/Vault.app  — double-click it in Finder, or `open target/Vault.app`.
# This is an unsigned local bundle for personal use; it is NOT notarized for distribution.
#
# Usage:  ./scripts/bundle-macos.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname)" != "Darwin" ]]; then
  echo "bundle-macos.sh: this packages a macOS .app; on other platforms just run \`cargo run -p vault-gui\`." >&2
  exit 1
fi

echo "Building vault-gui (release)…"
cargo build --release -p vault-gui

APP="target/Vault.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp target/release/vault-gui "$APP/Contents/MacOS/vault-gui"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>            <string>Vault</string>
    <key>CFBundleDisplayName</key>     <string>Vault</string>
    <key>CFBundleIdentifier</key>      <string>dev.vault.desktop</string>
    <key>CFBundleVersion</key>         <string>0.0.0</string>
    <key>CFBundleShortVersionString</key> <string>0.0.0</string>
    <key>CFBundleExecutable</key>      <string>vault-gui</string>
    <key>CFBundlePackageType</key>     <string>APPL</string>
    <key>LSMinimumSystemVersion</key>  <string>10.15</string>
    <key>NSHighResolutionCapable</key> <true/>
</dict>
</plist>
PLIST

echo "Built $APP"
echo "Launch it with:  open $APP    (or double-click it in Finder)"
