#!/bin/bash
set -euo pipefail

SPARKLE_VERSION="2.8.1"
SPARKLE_SHA256="5cddb7695674ef7704268f38eccaee80e3accbf19e61c1689efff5b6116d85be"
SPARKLE_SIZE="13660640"
SPARKLE_URL="https://github.com/sparkle-project/Sparkle/releases/download/2.8.1/Sparkle-2.8.1.tar.xz"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEFAULT_DEST="${PROJECT_ROOT}/build/sparkle/${SPARKLE_VERSION}"
DEST_DIR="$DEFAULT_DEST"
PRINT_DIR=0

usage() {
    cat <<EOF
Usage: scripts/fetch-sparkle.sh [options]

Options:
  --print-dir     Print the resolved Sparkle directory and exit
  -h, --help      Show this help

EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --print-dir)
            PRINT_DIR=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ "$PRINT_DIR" -eq 1 ]]; then
    echo "$DEST_DIR"
    exit 0
fi

mkdir -p "$(dirname "$DEST_DIR")"

TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

ARCHIVE_PATH="$TMP_DIR/Sparkle-${SPARKLE_VERSION}.tar.xz"
EXTRACT_DIR="$TMP_DIR/extracted"

echo "Downloading exact Sparkle ${SPARKLE_VERSION} archive..."
curl \
    --disable \
    --fail \
    --silent \
    --show-error \
    --location \
    --max-redirs 1 \
    --max-filesize "$SPARKLE_SIZE" \
    --proto '=https' \
    --proto-redir '=https' \
    --tlsv1.2 \
    --connect-timeout 10 \
    --max-time 180 \
    --output "$ARCHIVE_PATH" \
    "$SPARKLE_URL"

ACTUAL_SIZE="$(wc -c < "$ARCHIVE_PATH" | tr -d ' ')"
if [[ "$ACTUAL_SIZE" != "$SPARKLE_SIZE" ]]; then
    echo "Sparkle archive size mismatch: expected $SPARKLE_SIZE, got $ACTUAL_SIZE." >&2
    exit 1
fi

ACTUAL_SHA256="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
if [[ "$ACTUAL_SHA256" != "$SPARKLE_SHA256" ]]; then
    echo "Sparkle checksum mismatch." >&2
    echo "Expected: $SPARKLE_SHA256" >&2
    echo "Actual:   $ACTUAL_SHA256" >&2
    exit 1
fi

mkdir -p "$EXTRACT_DIR"
python3 - "$ARCHIVE_PATH" <<'PY'
import pathlib
import sys
import tarfile

with tarfile.open(sys.argv[1], "r:xz") as archive:
    names = [member.name for member in archive.getmembers()]
if len(names) != len(set(names)):
    raise SystemExit("Sparkle archive contains duplicate paths")
for name in names:
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise SystemExit(f"Sparkle archive contains an unsafe path: {name}")
PY
tar -xf "$ARCHIVE_PATH" -C "$EXTRACT_DIR"

STAGING_DIR="${DEST_DIR}.tmp"
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

cp -R "$EXTRACT_DIR/." "$STAGING_DIR/"

[[ -d "$STAGING_DIR/Sparkle.framework" ]] \
    || { echo "Sparkle archive lacks Sparkle.framework." >&2; exit 1; }
for tool in generate_appcast generate_keys sign_update; do
    [[ -x "$STAGING_DIR/bin/$tool" ]] \
        || { echo "Sparkle archive lacks executable bin/$tool." >&2; exit 1; }
done

rm -rf "$DEST_DIR"
mv "$STAGING_DIR" "$DEST_DIR"

echo "Sparkle ${SPARKLE_VERSION} installed at $DEST_DIR"
