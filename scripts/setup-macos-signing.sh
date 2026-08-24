#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P12_PATH=""
SIGN_IDENTITY="${CROWD_CAST_MACOS_SIGN_IDENTITY:-}"
KEYCHAIN_PATH="${CROWD_CAST_KEYCHAIN_PATH:-$HOME/Library/Keychains/login.keychain-db}"
NOTARY_PROFILE="${CROWD_CAST_NOTARY_PROFILE:-crowdcast-notary}"
APPLE_ID="${CROWD_CAST_APPLE_ID:-}"
TEAM_ID="${CROWD_CAST_TEAM_ID:-}"
SETUP_NOTARY=1

usage() {
    cat <<EOF
Usage: scripts/setup-macos-signing.sh --p12 <path> [options]

Interactive operator provisioning only. The security and notarytool processes own
all password prompts; this script never accepts passwords through arguments or the
environment.

Options:
  --p12 <path>              Developer ID PKCS#12 certificate
  --identity <identity>     Exact Developer ID Application identity
  --keychain <path>         Existing keychain (default: login.keychain-db)
  --notary-profile <name>   notarytool profile name (default: crowdcast-notary)
  --apple-id <id>           Apple ID email for notarization
  --team-id <id>            Apple Team ID
  --skip-notary             Import and verify only the signing identity
  -h, --help                Show this help

Environment fallbacks contain identifiers only:
  CROWD_CAST_KEYCHAIN_PATH
  CROWD_CAST_NOTARY_PROFILE
  CROWD_CAST_APPLE_ID
  CROWD_CAST_TEAM_ID
EOF
}

err() { echo "error: $*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || err "missing required command: $1"; }

for forbidden in \
    CROWD_CAST_P12_PASSWORD \
    CROWD_CAST_KEYCHAIN_PASSWORD \
    CROWD_CAST_APPLE_APP_SPECIFIC_PASSWORD
do
    [[ -z "${!forbidden+x}" ]] || err "$forbidden must not be set; Apple tools must own the prompt"
done

while [[ $# -gt 0 ]]; do
    case "$1" in
        --p12) P12_PATH="$2"; shift 2 ;;
        --identity) SIGN_IDENTITY="$2"; shift 2 ;;
        --keychain) KEYCHAIN_PATH="$2"; shift 2 ;;
        --notary-profile) NOTARY_PROFILE="$2"; shift 2 ;;
        --apple-id) APPLE_ID="$2"; shift 2 ;;
        --team-id) TEAM_ID="$2"; shift 2 ;;
        --skip-notary) SETUP_NOTARY=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) err "unknown option: $1" ;;
    esac
done

[[ -t 0 && -t 1 ]] || err "interactive TTY required for Apple-owned credential prompts"
[[ -n "$P12_PATH" && -f "$P12_PATH" ]] || err "--p12 must name an existing PKCS#12 file"
[[ -n "$SIGN_IDENTITY" ]] || err "--identity is required"
[[ -f "$KEYCHAIN_PATH" ]] || err "keychain not found: $KEYCHAIN_PATH"
require_cmd security
require_cmd codesign

security import "$P12_PATH" \
    -k "$KEYCHAIN_PATH" \
    -T /usr/bin/codesign \
    -T /usr/bin/security \
    -T /usr/bin/xcrun
security set-key-partition-list \
    -S apple-tool:,apple: \
    -s \
    "$KEYCHAIN_PATH"

verify_args=(--identity "$SIGN_IDENTITY" --keychain "$KEYCHAIN_PATH")
if [[ "$SETUP_NOTARY" -eq 1 ]]; then
    require_cmd xcrun
    [[ -n "$APPLE_ID" ]] || read -r -p "Apple ID email for notarization: " APPLE_ID
    [[ -n "$TEAM_ID" ]] || read -r -p "Apple Team ID: " TEAM_ID
    xcrun notarytool store-credentials "$NOTARY_PROFILE" \
        --apple-id "$APPLE_ID" \
        --team-id "$TEAM_ID"
    verify_args+=(--notary-profile "$NOTARY_PROFILE")
else
    verify_args+=(--skip-notary)
fi

"$SCRIPT_DIR/verify-macos-release-authority.sh" "${verify_args[@]}"
