#!/usr/bin/env bash
# Shell one-line installer for dep-tracker on Linux & macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/nyumuharon/dependency-tracker/main/scripts/install.sh | bash

set -euo pipefail

REPO="nyumuharon/dependency-tracker"

# 1. Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  linux*)  GOOS="linux" ;;
  darwin*) GOOS="darwin" ;;
  *) echo "Unsupported operating system: $OS" >&2; exit 1 ;;
esac

# 2. Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GOARCH="amd64" ;;
  arm64|aarch64) GOARCH="arm64" ;;
  *) echo "Unsupported CPU architecture: $ARCH" >&2; exit 1 ;;
esac

# 3. Determine target binary name
BINARY_NAME="dep-tracker-${GOOS}-${GOARCH}"

# 4. Fetch latest tag
RELEASE_JSON=$(curl -fsSL --retry 3 "https://api.github.com/repos/${REPO}/releases/latest")
TAG=$(printf '%s' "$RELEASE_JSON" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
if [ -z "$TAG" ]; then
  echo "Could not determine the latest release." >&2
  exit 1
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${BINARY_NAME}"
echo "Downloading dep-tracker (${TAG}) for ${GOOS}/${GOARCH}..."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -fSL --retry 3 --progress-bar -o "${TMP_DIR}/dep-tracker" "$DOWNLOAD_URL"
curl -fsSL --retry 3 -o "${TMP_DIR}/SHA256SUMS.txt" "https://github.com/${REPO}/releases/download/${TAG}/SHA256SUMS.txt"
EXPECTED=$(awk -v name="$BINARY_NAME" '$2 == name {print $1}' "${TMP_DIR}/SHA256SUMS.txt")
if ! printf '%s\n' "$EXPECTED" | LC_ALL=C grep -Eq '^[0-9a-fA-F]{64}$'; then
  echo "Missing or invalid release checksum for $BINARY_NAME." >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "${TMP_DIR}/dep-tracker" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "${TMP_DIR}/dep-tracker" | awk '{print $1}')
else
  echo "Install sha256sum or shasum to verify the release." >&2
  exit 1
fi
EXPECTED=$(printf '%s' "$EXPECTED" | tr '[:upper:]' '[:lower:]')
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "Checksum mismatch; installation cancelled." >&2
  exit 1
fi
chmod +x "${TMP_DIR}/dep-tracker"

# 5. Install to /usr/local/bin or ~/.local/bin
INSTALL_DIR="${DEP_TRACKER_INSTALL_DIR:-/usr/local/bin}"
if [ -n "${DEP_TRACKER_INSTALL_DIR:-}" ]; then
  mkdir -p "$INSTALL_DIR"
fi
if [ ! -w "$INSTALL_DIR" ]; then
  if command -v sudo >/dev/null 2>&1; then
    echo "Installing to $INSTALL_DIR (requires sudo)..."
    sudo cp "${TMP_DIR}/dep-tracker" "${INSTALL_DIR}/dep-tracker"
    sudo chmod +x "${INSTALL_DIR}/dep-tracker"
  else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
    cp "${TMP_DIR}/dep-tracker" "${INSTALL_DIR}/dep-tracker"
    chmod +x "${INSTALL_DIR}/dep-tracker"
    echo "Installed to $INSTALL_DIR (ensure this directory is in your PATH)."
  fi
else
  cp "${TMP_DIR}/dep-tracker" "${INSTALL_DIR}/dep-tracker"
  chmod +x "${INSTALL_DIR}/dep-tracker"
fi

echo ""
echo "============================================================"
echo " dep-tracker ($TAG) installed successfully to $INSTALL_DIR/dep-tracker"
echo "============================================================"
echo ""
echo "Run 'dep-tracker --help' to get started!"
