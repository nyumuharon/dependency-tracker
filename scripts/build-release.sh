#!/usr/bin/env bash
# Builds standalone dep-tracker binaries for Linux, Windows, and macOS.
# Usage: ./scripts/build-release.sh [output-dir]   (default: dist/)
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="${1:-dist}"
VERSION="$(grep -oP 'appVersion = "\K[^"]+' cmd/dep-tracker/main.go)"
mkdir -p "$OUT"

targets=(
  "linux   amd64 dep-tracker-linux-amd64"
  "linux   arm64 dep-tracker-linux-arm64"
  "windows amd64 dep-tracker-windows-amd64.exe"
  "darwin  amd64 dep-tracker-macos-amd64"
  "darwin  arm64 dep-tracker-macos-arm64"
)

for t in "${targets[@]}"; do
  read -r goos goarch name <<<"$t"
  echo "Building $name (v$VERSION)"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o "$OUT/$name" ./cmd/dep-tracker
done

# Provide darwin-* aliases for macOS binaries to match README paths
cp "$OUT/dep-tracker-macos-amd64" "$OUT/dep-tracker-darwin-amd64"
cp "$OUT/dep-tracker-macos-arm64" "$OUT/dep-tracker-darwin-arm64"

(cd "$OUT" && sha256sum dep-tracker-* > SHA256SUMS.txt)
echo "Done. Binaries written to $OUT/"
