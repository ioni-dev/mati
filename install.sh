#!/usr/bin/env bash
# mati installer
# Usage: curl -fsSL https://github.com/ioni-dev/mati/releases/latest/download/install.sh | bash

set -euo pipefail

REPO="ioni-dev/mati"
BINARY="mati"
INSTALL_DIR="/usr/local/bin"
BASE_URL="https://github.com/${REPO}/releases/latest/download"

# ── helpers ────────────────────────────────────────────────────────────────────

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[0;34m%s\033[0m\n' "$*"; }
die()   { red "error: $*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found. Please install it and retry."
}

# ── dependency checks ──────────────────────────────────────────────────────────

need curl
need tar

# sha256sum is coreutils on Linux; shasum ships on macOS
if command -v sha256sum >/dev/null 2>&1; then
  SHA_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA_CMD="shasum -a 256"
else
  die "No SHA-256 utility found (sha256sum or shasum). Please install one and retry."
fi

# ── platform detection ─────────────────────────────────────────────────────────

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      x86_64)            TARGET="x86_64-apple-darwin"   ;;
      arm64 | aarch64)   TARGET="aarch64-apple-darwin"  ;;
      *)                 die "Unsupported macOS architecture: $ARCH" ;;
    esac
    ;;
  Linux)
    case "$ARCH" in
      x86_64)            TARGET="x86_64-unknown-linux-musl"   ;;
      arm64 | aarch64)   TARGET="aarch64-unknown-linux-musl"  ;;
      *)                 die "Unsupported Linux architecture: $ARCH" ;;
    esac
    ;;
  *)
    die "Unsupported operating system: $OS. Only Linux and macOS are supported."
    ;;
esac

ARTIFACT="mati-${TARGET}.tar.gz"
ARTIFACT_URL="${BASE_URL}/${ARTIFACT}"
CHECKSUMS_URL="${BASE_URL}/checksums.txt"

blue "Detected platform: ${TARGET}"

# ── download ───────────────────────────────────────────────────────────────────

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

blue "Downloading ${ARTIFACT}..."
curl -fsSL --progress-bar -o "${TMP}/${ARTIFACT}" "${ARTIFACT_URL}" \
  || die "Download failed. Check your network connection or visit ${ARTIFACT_URL} manually."

blue "Downloading checksums.txt..."
curl -fsSL -o "${TMP}/checksums.txt" "${CHECKSUMS_URL}" \
  || die "Failed to download checksums from ${CHECKSUMS_URL}."

# ── checksum verification ──────────────────────────────────────────────────────

blue "Verifying checksum..."

# Extract the expected hash for this artifact from checksums.txt
EXPECTED_LINE="$(grep "${ARTIFACT}" "${TMP}/checksums.txt" || true)"
[ -n "$EXPECTED_LINE" ] || die "Checksum entry for '${ARTIFACT}' not found in checksums.txt."

# Rewrite the path in the checksum line to point at the local file
EXPECTED_HASH="$(echo "$EXPECTED_LINE" | awk '{print $1}')"
ACTUAL_HASH="$($SHA_CMD "${TMP}/${ARTIFACT}" | awk '{print $1}')"

if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
  die "Checksum mismatch for ${ARTIFACT}.
  expected: ${EXPECTED_HASH}
  actual:   ${ACTUAL_HASH}
Download may be corrupted. Please retry."
fi

green "Checksum verified."

# ── extract ────────────────────────────────────────────────────────────────────

tar -xzf "${TMP}/${ARTIFACT}" -C "${TMP}" \
  || die "Failed to extract ${ARTIFACT}."

[ -f "${TMP}/${BINARY}" ] || die "Binary '${BINARY}' not found in archive."
chmod +x "${TMP}/${BINARY}"

# ── install ────────────────────────────────────────────────────────────────────

if [ -w "${INSTALL_DIR}" ]; then
  mv "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  blue "Installing to ${INSTALL_DIR} (sudo required)..."
  sudo mv "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

# ── verify ─────────────────────────────────────────────────────────────────────

INSTALLED_PATH="$(command -v "${BINARY}" || true)"
if [ -z "$INSTALLED_PATH" ]; then
  die "Installation succeeded but '${BINARY}' is not on PATH. Add '${INSTALL_DIR}' to your PATH."
fi

green ""
green "mati installed. Run: mati init"
