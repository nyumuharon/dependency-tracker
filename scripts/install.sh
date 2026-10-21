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
TAG=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep -oP '"tag_name":\s*"\K[^"]+' || echo "v1.0.2")

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${BINARY_NAME}"
echo "Downloading dep-tracker (${TAG}) for ${GOOS}/${GOARCH}..."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -sSL --progress-bar -o "${TMP_DIR}/dep-tracker" "$DOWNLOAD_URL"
chmod +x "${TMP_DIR}/dep-tracker"

# 5. Install to /usr/local/bin or ~/.local/bin
INSTALL_DIR="/usr/local/bin"
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
