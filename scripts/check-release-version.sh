#!/usr/bin/env bash
# Assert git tag vX.Y.Z matches [workspace.package] version in Cargo.toml (UC-13).
set -euo pipefail
cd "$(dirname "$0")/.."

tag="${1:?usage: check-release-version.sh vX.Y.Z}"
ver="${tag#v}"
if [[ "$ver" == "$tag" || -z "$ver" ]]; then
  echo "FAIL: tag must look like vX.Y.Z (got $tag)"
  exit 1
fi

cargo_ver=$(grep -A20 '^\[workspace\.package\]' Cargo.toml | grep '^version' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
if [[ "$cargo_ver" != "$ver" ]]; then
  echo "FAIL: tag $tag (version $ver) != workspace version $cargo_ver in Cargo.toml"
  exit 1
fi
echo "OK: tag matches workspace version $ver"
