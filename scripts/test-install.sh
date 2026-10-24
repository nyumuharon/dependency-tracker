#!/usr/bin/env bash
# Offline installer regression tests. Never writes outside a temporary directory.
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/mock-bin" "$TEST_DIR/install" "$TEST_DIR/fixtures"
export MOCK_FIXTURES="$TEST_DIR/fixtures"
printf '%s' 'verified binary' > "$MOCK_FIXTURES/binary"
if command -v sha256sum >/dev/null 2>&1; then
  HASH=$(sha256sum "$MOCK_FIXTURES/binary" | awk '{print $1}')
else
  HASH=$(shasum -a 256 "$MOCK_FIXTURES/binary" | awk '{print $1}')
fi
printf '%s  dep-tracker-linux-amd64\n' "$HASH" > "$MOCK_FIXTURES/SHA256SUMS.txt"
cat > "$TEST_DIR/mock-bin/uname" <<'MOCK'
#!/usr/bin/env bash
case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) exit 1 ;; esac
MOCK
cat > "$TEST_DIR/mock-bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
OUT=""
URL=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) OUT="$2"; shift 2 ;;
    --retry) shift 2 ;;
    http*) URL="$1"; shift ;;
    *) shift ;;
  esac
done
case "$URL" in
  */releases/latest)
    if [ "$MOCK_MODE" = "api-failed" ]; then exit 22; fi
    printf '%s' '{"tag_name":"v1.0.5"}' ;;
  */SHA256SUMS.txt)
    if [ "$MOCK_MODE" = "missing-checksum" ]; then exit 22; fi
    cp "$MOCK_FIXTURES/SHA256SUMS.txt" "$OUT" ;;
  */dep-tracker-linux-amd64)
    if [ "$MOCK_MODE" = "download-failed" ]; then exit 22; fi
    if [ "$MOCK_MODE" = "tampered" ]; then printf '%s' tampered > "$OUT"; else cp "$MOCK_FIXTURES/binary" "$OUT"; fi ;;
  *) exit 22 ;;
esac
MOCK
chmod +x "$TEST_DIR/mock-bin/"*
export PATH="$TEST_DIR/mock-bin:$PATH"
export DEP_TRACKER_INSTALL_DIR="$TEST_DIR/install"
for MOCK_MODE in valid tampered missing-checksum download-failed api-failed; do
  export MOCK_MODE
  printf '%s' 'existing binary' > "$DEP_TRACKER_INSTALL_DIR/dep-tracker"
  if bash "$PROJECT_DIR/scripts/install.sh" > "$TEST_DIR/log" 2>&1; then
    if [ "$MOCK_MODE" != valid ]; then cat "$TEST_DIR/log"; echo "Unexpected install success: $MOCK_MODE" >&2; exit 1; fi
    cmp "$MOCK_FIXTURES/binary" "$DEP_TRACKER_INSTALL_DIR/dep-tracker"
  else
    if [ "$MOCK_MODE" = valid ]; then cat "$TEST_DIR/log"; exit 1; fi
    if [ "$(cat "$DEP_TRACKER_INSTALL_DIR/dep-tracker")" != 'existing binary' ]; then echo "Existing binary changed: $MOCK_MODE" >&2; exit 1; fi
  fi
done
echo "Installer regression tests passed (verified, tampered, missing checksum, download/API failure)."
