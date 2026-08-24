#!/bin/bash
set -euo pipefail

IDENTITY=""
KEYCHAIN_PATH="${CROWD_CAST_KEYCHAIN_PATH:-$HOME/Library/Keychains/login.keychain-db}"
NOTARY_PROFILE=""
VERIFY_NOTARY=1
SPARKLE_DIR=""
SPARKLE_PUBLIC_ED_KEY=""

err() { echo "error: $*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || err "missing required command: $1"; }

for forbidden in \
    CROWD_CAST_P12_PASSWORD \
    CROWD_CAST_KEYCHAIN_PASSWORD \
    CROWD_CAST_APPLE_APP_SPECIFIC_PASSWORD
do
    [[ -z "${!forbidden+x}" ]] || err "$forbidden must not be present in a release process"
done

run_bounded() {
    "$@" &
    local command_pid=$!
    (
        sleep 30
        kill -TERM "$command_pid" 2>/dev/null || true
    ) &
    local timer_pid=$!
    local status
    set +e
    wait "$command_pid"
    status=$?
    set -e
    kill -TERM "$timer_pid" 2>/dev/null || true
    wait "$timer_pid" 2>/dev/null || true
    return "$status"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --identity) IDENTITY="$2"; shift 2 ;;
        --keychain) KEYCHAIN_PATH="$2"; shift 2 ;;
        --notary-profile) NOTARY_PROFILE="$2"; shift 2 ;;
        --sparkle-dir) SPARKLE_DIR="$2"; shift 2 ;;
        --sparkle-public-ed-key) SPARKLE_PUBLIC_ED_KEY="$2"; shift 2 ;;
        --skip-notary) VERIFY_NOTARY=0; shift ;;
        *) err "unknown option: $1" ;;
    esac
done

[[ -n "$IDENTITY" ]] || err "--identity is required"
[[ -f "$KEYCHAIN_PATH" ]] || err "keychain not found: $KEYCHAIN_PATH"
if [[ "$VERIFY_NOTARY" -eq 1 ]]; then
    [[ -n "$NOTARY_PROFILE" ]] || err "--notary-profile is required"
fi
if [[ -n "$SPARKLE_DIR" || -n "$SPARKLE_PUBLIC_ED_KEY" ]]; then
    [[ -x "$SPARKLE_DIR/bin/generate_keys" ]] || err "--sparkle-dir must contain executable bin/generate_keys"
    [[ "$SPARKLE_PUBLIC_ED_KEY" =~ ^[A-Za-z0-9+/]{43}=$ ]] \
        || err "--sparkle-public-ed-key must be canonical base64 for 32 bytes"
fi
require_cmd security
require_cmd codesign

identity_output="$(security find-identity -v -p codesigning "$KEYCHAIN_PATH")" \
    || err "unable to enumerate signing identities"
identity_count="$(printf '%s\n' "$identity_output" | grep -F -c \""$IDENTITY"\" || true)"
[[ "$identity_count" -eq 1 ]] || err "expected one valid signing identity named '$IDENTITY', found $identity_count"

probe_root="$(mktemp -d "${TMPDIR:-/tmp}/crowd-cast-signing-probe.XXXXXX")"
trap 'rm -rf "$probe_root"' EXIT
probe_app="$probe_root/Probe.app"
mkdir -p "$probe_app/Contents/MacOS"
printf '#!/bin/sh\nexit 0\n' > "$probe_app/Contents/MacOS/probe"
chmod 0755 "$probe_app/Contents/MacOS/probe"
cat > "$probe_app/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>probe</string>
<key>CFBundleIdentifier</key><string>dev.crowd-cast.signing-probe</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
EOF

run_bounded codesign --force --timestamp=none --sign "$IDENTITY" "$probe_app" \
    || err "signing identity is present but unusable"
run_bounded codesign --verify --strict --verbose=2 "$probe_app" \
    || err "signing identity produced an unverifiable probe"

if [[ "$VERIFY_NOTARY" -eq 1 ]]; then
    require_cmd xcrun
    run_bounded xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" --output-format json >/dev/null \
        || err "notary profile is missing or unusable: $NOTARY_PROFILE"
fi

if [[ -n "$SPARKLE_DIR" ]]; then
    run_bounded "$SPARKLE_DIR/bin/generate_keys" -p > "$probe_root/sparkle-public-key" \
        || err "pre-provisioned Sparkle signing key is unavailable"
    sparkle_key="$(grep -Eo '[A-Za-z0-9+/]{43}=' "$probe_root/sparkle-public-key" | sort -u)"
    [[ "$sparkle_key" == "$SPARKLE_PUBLIC_ED_KEY" ]] \
        || err "pre-provisioned Sparkle signing key does not match the expected public key"
fi

echo "macOS release authority verified"
