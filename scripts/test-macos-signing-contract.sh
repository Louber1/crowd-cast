#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/crowd-cast-macos-signing-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT
FAKE_BIN="$TEST_ROOT/bin"
FAKE_LOG="$TEST_ROOT/invocations.log"
SPARKLE_DIR="$TEST_ROOT/sparkle"
SPARKLE_PUBLIC_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
KEYCHAIN="$TEST_ROOT/release.keychain-db"
P12="$TEST_ROOT/release.p12"
mkdir -p "$FAKE_BIN" "$SPARKLE_DIR/bin"
: > "$FAKE_LOG"
: > "$KEYCHAIN"
: > "$P12"

cat > "$FAKE_BIN/security" <<'EOF'
#!/bin/bash
printf 'security' >> "$FAKE_LOG"
printf '\t%s' "$@" >> "$FAKE_LOG"
printf '\n' >> "$FAKE_LOG"
if [[ "${FAKE_IDENTITY_MODE:-ok}" == "missing" ]]; then
    echo "0 valid identities found"
else
    echo '  1) 0123456789ABCDEF0123456789ABCDEF01234567 "Developer ID Application: Crowd Cast (TEAMID)"'
    echo "     1 valid identities found"
fi
EOF

cat > "$FAKE_BIN/codesign" <<'EOF'
#!/bin/bash
printf 'codesign' >> "$FAKE_LOG"
printf '\t%s' "$@" >> "$FAKE_LOG"
printf '\n' >> "$FAKE_LOG"
[[ "${FAKE_CODESIGN_MODE:-ok}" != "fail" ]]
EOF

cat > "$FAKE_BIN/xcrun" <<'EOF'
#!/bin/bash
printf 'xcrun' >> "$FAKE_LOG"
printf '\t%s' "$@" >> "$FAKE_LOG"
printf '\n' >> "$FAKE_LOG"
[[ "${FAKE_NOTARY_MODE:-ok}" != "fail" ]]
EOF
chmod 0755 "$FAKE_BIN/security" "$FAKE_BIN/codesign" "$FAKE_BIN/xcrun"

cat > "$SPARKLE_DIR/bin/generate_keys" <<'EOF'
#!/bin/bash
printf 'generate_keys' >> "$FAKE_LOG"
printf '\t%s' "$@" >> "$FAKE_LOG"
printf '\n' >> "$FAKE_LOG"
if [[ "${FAKE_SPARKLE_MODE:-ok}" == "missing" ]]; then
    echo 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='
else
    echo 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
fi
EOF
chmod 0755 "$SPARKLE_DIR/bin/generate_keys"

run_verify() {
    PATH="$FAKE_BIN:$PATH" FAKE_LOG="$FAKE_LOG" \
        "$SCRIPT_DIR/verify-macos-release-authority.sh" \
        --identity "Developer ID Application: Crowd Cast (TEAMID)" \
        --keychain "$KEYCHAIN" \
        --notary-profile crowdcast-notary \
        --sparkle-dir "$SPARKLE_DIR" \
        --sparkle-public-ed-key "$SPARKLE_PUBLIC_KEY"
}

assert_fails() {
    local expected="$1"
    shift
    local output="$TEST_ROOT/failure.log"
    if "$@" >"$output" 2>&1; then
        echo "expected failure: $expected" >&2
        exit 1
    fi
    grep -F "$expected" "$output" >/dev/null
}

assert_fails "interactive TTY required" \
    env PATH="$FAKE_BIN:$PATH" FAKE_LOG="$FAKE_LOG" \
    "$SCRIPT_DIR/setup-macos-signing.sh" \
    --p12 "$P12" \
    --identity "Developer ID Application: Crowd Cast (TEAMID)" \
    --keychain "$KEYCHAIN"
[[ ! -s "$FAKE_LOG" ]] || { echo "non-TTY provisioning invoked a credential tool" >&2; exit 1; }

: > "$FAKE_LOG"
provision_command=(
    "$SCRIPT_DIR/setup-macos-signing.sh"
    --p12 "$P12"
    --identity "Developer ID Application: Crowd Cast (TEAMID)"
    --keychain "$KEYCHAIN"
    --notary-profile crowdcast-notary
    --apple-id operator@example.invalid
    --team-id TEAMID
)
printf -v provision_shell '%q ' "${provision_command[@]}"
env PATH="$FAKE_BIN:$PATH" FAKE_LOG="$FAKE_LOG" \
    script -qfec "$provision_shell" /dev/null > "$TEST_ROOT/provision.log"
grep -F $'security\timport' "$FAKE_LOG" >/dev/null
grep -F $'security\tset-key-partition-list\t-S\tapple-tool:,apple:\t-s' "$FAKE_LOG" >/dev/null
grep -F $'xcrun\tnotarytool\tstore-credentials\tcrowdcast-notary\t--apple-id\toperator@example.invalid\t--team-id\tTEAMID' "$FAKE_LOG" >/dev/null
! grep -Ei -- '-P|-k\t.*password|--password|secret' "$FAKE_LOG" >/dev/null

: > "$FAKE_LOG"
assert_fails "CROWD_CAST_P12_PASSWORD must not be present" \
    env CROWD_CAST_P12_PASSWORD=do-not-log-this PATH="$FAKE_BIN:$PATH" FAKE_LOG="$FAKE_LOG" \
    "$SCRIPT_DIR/verify-macos-release-authority.sh" \
    --identity "Developer ID Application: Crowd Cast (TEAMID)" \
    --keychain "$KEYCHAIN" \
    --notary-profile crowdcast-notary
! grep -F "do-not-log-this" "$TEST_ROOT/failure.log" >/dev/null
[[ ! -s "$FAKE_LOG" ]] || { echo "forbidden environment reached a credential tool" >&2; exit 1; }

assert_fails "expected one valid signing identity" \
    env FAKE_IDENTITY_MODE=missing PATH="$FAKE_BIN:$PATH" FAKE_LOG="$FAKE_LOG" \
    "$SCRIPT_DIR/verify-macos-release-authority.sh" \
    --identity "Developer ID Application: Crowd Cast (TEAMID)" \
    --keychain "$KEYCHAIN" \
    --notary-profile crowdcast-notary

assert_fails "signing identity is present but unusable" \
    env FAKE_CODESIGN_MODE=fail PATH="$FAKE_BIN:$PATH" FAKE_LOG="$FAKE_LOG" \
    "$SCRIPT_DIR/verify-macos-release-authority.sh" \
    --identity "Developer ID Application: Crowd Cast (TEAMID)" \
    --keychain "$KEYCHAIN" \
    --notary-profile crowdcast-notary

assert_fails "notary profile is missing or unusable" \
    env FAKE_NOTARY_MODE=fail PATH="$FAKE_BIN:$PATH" FAKE_LOG="$FAKE_LOG" \
    "$SCRIPT_DIR/verify-macos-release-authority.sh" \
    --identity "Developer ID Application: Crowd Cast (TEAMID)" \
    --keychain "$KEYCHAIN" \
    --notary-profile crowdcast-notary

assert_fails "pre-provisioned Sparkle signing key does not match the expected public key" \
    env FAKE_SPARKLE_MODE=missing PATH="$FAKE_BIN:$PATH" FAKE_LOG="$FAKE_LOG" \
    "$SCRIPT_DIR/verify-macos-release-authority.sh" \
    --identity "Developer ID Application: Crowd Cast (TEAMID)" \
    --keychain "$KEYCHAIN" \
    --notary-profile crowdcast-notary \
    --sparkle-dir "$SPARKLE_DIR" \
    --sparkle-public-ed-key "$SPARKLE_PUBLIC_KEY"

: > "$FAKE_LOG"
run_verify > "$TEST_ROOT/success.log"
grep -F "macOS release authority verified" "$TEST_ROOT/success.log" >/dev/null
grep -F $'security\tfind-identity\t-v\t-p\tcodesigning' "$FAKE_LOG" >/dev/null
grep -F $'codesign\t--force\t--timestamp=none\t--sign\tDeveloper ID Application: Crowd Cast (TEAMID)' "$FAKE_LOG" >/dev/null
grep -F $'codesign\t--verify\t--strict\t--verbose=2' "$FAKE_LOG" >/dev/null
grep -F $'xcrun\tnotarytool\thistory\t--keychain-profile\tcrowdcast-notary\t--output-format\tjson' "$FAKE_LOG" >/dev/null
grep -F $'generate_keys\t-p' "$FAKE_LOG" >/dev/null
! grep -Ei 'password|do-not-log-this' "$FAKE_LOG" >/dev/null

echo "macOS signing contract tests passed"
