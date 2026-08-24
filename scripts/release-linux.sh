#!/usr/bin/env bash
# Assemble and Ed25519-sign the Linux appcast manifest (the "appcast-linux.json" + .sig the
# in-app updater fetches). The Linux analog of scripts/generate-appcast-win.ps1.
#
# It computes the per-artifact SHA-256, writes the manifest JSON, then calls the cc-sign-manifest
# tool to produce the detached signature over the SAME domain-separated message the client verifies
# (src/ui/appcast_sig.rs). Hosting/publishing is the workflow's job (.github/workflows/linux-release.yml);
# this script only produces dist/appcast-linux.json[.sig].
#
# Artifact names are kept consistent with packaging/linux/install.sh:
#   crowd-cast-agent-x86_64                      (the binary)
#   obs-bundle-<abi>-x86_64.tar.zst              (the libobs bundle)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VERSION=""
BUILD="0"
ABI=""
BINARY=""
BUNDLE=""
DOWNLOAD_BASE=""           # binary host, e.g. https://github.com/<owner>/<repo>/releases/download/<tag>
BUNDLE_URL_OVERRIDE=""     # full bundle URL; defaults to <download-base>/<bundle-name>. The bundle
                           # normally lives in its own per-ABI Release, so its URL differs from the
                           # binary's app-release URL.
KEY_FILE="${CROWD_CAST_ED_PRIVATE_KEY_FILE:-}"
PUBLIC_KEY=""
BUNDLE_MANIFEST_URL=""
BUNDLE_MANIFEST_SHA256=""
BUNDLE_IMPLEMENTATION_ID=""
OUT_DIR="$PROJECT_ROOT/dist"
NOTES=""
CRITICAL="false"
MIN_VERSION=""
SIGNER=""

usage() {
    cat <<EOF
Usage: scripts/release-linux.sh --version <semver> --build <n> --abi <ver> \\
         --binary <path> --bundle <path> --download-base <url> [options]

Required:
  --version <semver>     Marketing version (must equal Cargo.toml version for this release)
  --build <n>            Monotonic build number (the workflow passes github.run_number)
  --abi <ver>            libobs/OBS ABI the bundle targets (e.g. 32.0.2)
  --binary <path>        Path to the built crowd-cast-agent binary
  --bundle <path>        Path to the obs-bundle-<abi>-x86_64.tar.zst
  --download-base <url>  Base URL the BINARY is hosted at (no trailing slash; the app Release)

Options:
  --bundle-url <url>     Full URL the bundle is served from (default: <download-base>/<bundle-name>).
                         Point this at the per-ABI bundle Release so the bundle isn't re-uploaded.
  --key-file <path>      Ed25519 private key (base64; 32-byte seed or 64-byte seed||pub).
                         Defaults to \$CROWD_CAST_ED_PRIVATE_KEY_FILE.
  --public-key <base64>  Exact public key embedded in the application
  --bundle-manifest-url <url>
                         Exact native bundle manifest URL bound into the application
  --bundle-manifest-sha256 <hex>
                         SHA-256 of the exact native bundle manifest bytes
  --bundle-implementation-id <id>
                         Compiled native implementation identity
  --out-dir <dir>        Output dir for the manifest + sig (default: dist/)
  --notes <text>         Release notes string
  --critical             Mark this release critical (forward-compat flag)
  --minimum-version <v>  Minimum version allowed to skip this update (forward-compat)
  --signer <path>        Path to cc-sign-manifest (default: build it with --features release-tools)
  -h, --help             Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --build) BUILD="$2"; shift 2 ;;
        --abi) ABI="$2"; shift 2 ;;
        --binary) BINARY="$2"; shift 2 ;;
        --bundle) BUNDLE="$2"; shift 2 ;;
        --download-base) DOWNLOAD_BASE="${2%/}"; shift 2 ;;
        --bundle-url) BUNDLE_URL_OVERRIDE="$2"; shift 2 ;;
        --key-file) KEY_FILE="$2"; shift 2 ;;
        --public-key) PUBLIC_KEY="$2"; shift 2 ;;
        --bundle-manifest-url) BUNDLE_MANIFEST_URL="$2"; shift 2 ;;
        --bundle-manifest-sha256) BUNDLE_MANIFEST_SHA256="$2"; shift 2 ;;
        --bundle-implementation-id) BUNDLE_IMPLEMENTATION_ID="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --notes) NOTES="$2"; shift 2 ;;
        --critical) CRITICAL="true"; shift ;;
        --minimum-version) MIN_VERSION="$2"; shift 2 ;;
        --signer) SIGNER="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

err() { echo "error: $*" >&2; exit 1; }

[[ -n "$VERSION" ]]       || err "missing --version"
[[ -n "$ABI" ]]           || err "missing --abi"
[[ -n "$DOWNLOAD_BASE" ]] || err "missing --download-base"
[[ "$BUILD" =~ ^[1-9][0-9]*$ ]] || err "--build must be a positive integer"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || err "--version must be release SemVer"
[[ -f "$BINARY" ]]        || err "binary not found: $BINARY"
[[ -f "$BUNDLE" ]]        || err "bundle not found: $BUNDLE"
[[ -n "$KEY_FILE" && -f "$KEY_FILE" ]] || err "signing key file not found (set --key-file or \$CROWD_CAST_ED_PRIVATE_KEY_FILE)"
[[ -n "$PUBLIC_KEY" ]] || err "missing --public-key"
[[ "$BUNDLE_MANIFEST_URL" == https://* ]] || err "--bundle-manifest-url must be HTTPS"
[[ "$BUNDLE_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] || err "--bundle-manifest-sha256 must be canonical lowercase SHA-256"
[[ "$BUNDLE_IMPLEMENTATION_ID" =~ ^[A-Za-z0-9._-]+$ ]] || err "invalid --bundle-implementation-id"
command -v sha256sum >/dev/null 2>&1 || err "'sha256sum' is required"
command -v python3   >/dev/null 2>&1 || err "'python3' is required (manifest JSON assembly)"
python3 - "$DOWNLOAD_BASE" "$BUNDLE_MANIFEST_URL" "${BUNDLE_URL_OVERRIDE:-$DOWNLOAD_BASE/placeholder}" <<'PY'
import sys
import urllib.parse

for value in sys.argv[1:]:
    url = urllib.parse.urlsplit(value)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise SystemExit("release URLs must be exact HTTPS without credentials, query, or fragment")
PY

# Build the signer on demand if not provided. It needs the release-tools feature.
if [[ -z "$SIGNER" ]]; then
    echo ">> building cc-sign-manifest..." >&2
    ( cd "$PROJECT_ROOT" && cargo build --release --features release-tools --bin cc-sign-manifest >&2 )
    SIGNER="$PROJECT_ROOT/target/release/cc-sign-manifest"
fi
[[ -x "$SIGNER" ]] || err "signer not executable: $SIGNER"

BIN_NAME="crowd-cast-agent-x86_64"
BUNDLE_NAME="obs-bundle-${ABI}-x86_64.tar.zst"

BIN_URL="$DOWNLOAD_BASE/$BIN_NAME"
# Bundle is normally served from its own per-ABI Release (so it isn't re-uploaded per release); fall
# back to the binary's download-base if no override is given (e.g. the local smoke test).
BUNDLE_URL="${BUNDLE_URL_OVERRIDE:-$DOWNLOAD_BASE/$BUNDLE_NAME}"

BIN_SHA="$(sha256sum "$BINARY"  | awk '{print $1}')"
BUNDLE_SHA="$(sha256sum "$BUNDLE" | awk '{print $1}')"
BIN_SIZE="$(wc -c < "$BINARY" | tr -d ' ')"
BUNDLE_SIZE="$(wc -c < "$BUNDLE" | tr -d ' ')"

mkdir -p "$OUT_DIR"
MANIFEST="$OUT_DIR/appcast-linux.json"

# Assemble the manifest with python3 so notes/strings are JSON-escaped correctly. The byte content
# written here is EXACTLY what gets signed and uploaded — do not reformat it afterwards.
BIN_URL="$BIN_URL" \
BUNDLE_URL="$BUNDLE_URL" \
VERSION="$VERSION" BUILD="$BUILD" ABI="$ABI" NOTES="$NOTES" \
CRITICAL="$CRITICAL" MIN_VERSION="$MIN_VERSION" \
BIN_SHA="$BIN_SHA" BIN_SIZE="$BIN_SIZE" BUNDLE_SHA="$BUNDLE_SHA" BUNDLE_SIZE="$BUNDLE_SIZE" \
BUNDLE_MANIFEST_URL="$BUNDLE_MANIFEST_URL" BUNDLE_MANIFEST_SHA256="$BUNDLE_MANIFEST_SHA256" \
BUNDLE_IMPLEMENTATION_ID="$BUNDLE_IMPLEMENTATION_ID" \
python3 - "$MANIFEST" <<'PY'
import json, os, sys
manifest = {
    "version": os.environ["VERSION"],
    "build": int(os.environ["BUILD"]),
    "notes": os.environ.get("NOTES", ""),
    "critical": os.environ["CRITICAL"] == "true",
    "minimum_version": os.environ.get("MIN_VERSION", ""),
    "binary": {"url": os.environ["BIN_URL"], "sha256": os.environ["BIN_SHA"], "size": int(os.environ["BIN_SIZE"])},
    "bundle_manifest": {"url": os.environ["BUNDLE_MANIFEST_URL"], "sha256": os.environ["BUNDLE_MANIFEST_SHA256"]},
    "bundle": {
        "abi": os.environ["ABI"],
        "implementation_id": os.environ["BUNDLE_IMPLEMENTATION_ID"],
        "url": os.environ["BUNDLE_URL"],
        "sha256": os.environ["BUNDLE_SHA"],
        "size": int(os.environ["BUNDLE_SIZE"]),
    },
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
PY

# Sign the exact manifest bytes (domain-separated inside the signer).
"$SIGNER" \
    --manifest "$MANIFEST" \
    --key-file "$KEY_FILE" \
    --expected-public-key "$PUBLIC_KEY" \
    --out "$MANIFEST.sig"

echo ">> wrote $MANIFEST + $MANIFEST.sig"
echo "   version=$VERSION build=$BUILD abi=$ABI"
echo "   binary sha256=$BIN_SHA"
echo "   bundle sha256=$BUNDLE_SHA"
echo "   binary url=$BIN_URL"
echo "   bundle url=$BUNDLE_URL"
