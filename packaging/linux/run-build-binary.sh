#!/usr/bin/env bash
# Host driver: build the crowd-cast-agent binary on the glibc-2.34 floor, in the SAME AlmaLinux 9
# image as the libobs bundle. The caller supplies the exact builder image digest; this script never
# builds or resolves a mutable image. The exact image must contain the locked Cargo dependency
# sources needed for an offline build. The repo is mounted read-only and build output goes to out/.
# Output -> packaging/linux/out/crowd-cast-agent-x86_64.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ENGINE="${ENGINE:?ENGINE must name the container engine}"
IMG="${CROWD_CAST_BUILDER_IMAGE:?CROWD_CAST_BUILDER_IMAGE must name the exact builder image digest}"
[[ "$IMG" =~ ^[a-z0-9./:_-]+@sha256:[0-9a-f]{64}$ ]] \
  || { echo "error: CROWD_CAST_BUILDER_IMAGE must be an immutable lowercase sha256 digest reference" >&2; exit 1; }
command -v "$ENGINE" >/dev/null 2>&1 \
  || { echo "error: container engine not found: $ENGINE" >&2; exit 1; }

for required in \
  CROWD_CAST_OBS_ABI \
  CROWD_CAST_BUILD_NUMBER \
  CROWD_CAST_API_GATEWAY_URL \
  CROWD_CAST_UPDATE_FEED_URL \
  CROWD_CAST_UPDATE_PUBKEY \
  CROWD_CAST_GOOGLE_CLIENT_ID \
  CROWD_CAST_RELEASE_CHANNEL \
  CROWD_CAST_OBS_BUNDLE_MANIFEST_PATH \
  CROWD_CAST_OBS_BUNDLE_MANIFEST_SHA256
do
  [[ -n "${!required:-}" ]] || { echo "error: $required is required" >&2; exit 1; }
done
[[ -f "$CROWD_CAST_OBS_BUNDLE_MANIFEST_PATH" ]] \
  || { echo "error: CROWD_CAST_OBS_BUNDLE_MANIFEST_PATH must name an existing file" >&2; exit 1; }
[[ "$CROWD_CAST_OBS_BUNDLE_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || { echo "error: CROWD_CAST_OBS_BUNDLE_MANIFEST_SHA256 must be canonical lowercase SHA-256" >&2; exit 1; }
[[ "$(sha256sum "$CROWD_CAST_OBS_BUNDLE_MANIFEST_PATH" | cut -d' ' -f1)" == "$CROWD_CAST_OBS_BUNDLE_MANIFEST_SHA256" ]] \
  || { echo "error: OBS bundle manifest SHA-256 mismatch" >&2; exit 1; }
[[ "$CROWD_CAST_BUILD_NUMBER" =~ ^[1-9][0-9]*$ ]] \
  || { echo "error: CROWD_CAST_BUILD_NUMBER must be a positive integer" >&2; exit 1; }
case "$CROWD_CAST_RELEASE_CHANNEL" in
  prod) [[ -z "${CROWD_CAST_UPLOAD_TEST:-}" ]] || { echo "error: prod build must not set CROWD_CAST_UPLOAD_TEST" >&2; exit 1; } ;;
  dev) [[ "${CROWD_CAST_UPLOAD_TEST:-}" == "1" ]] || { echo "error: dev build requires CROWD_CAST_UPLOAD_TEST=1" >&2; exit 1; } ;;
  *) echo "error: CROWD_CAST_RELEASE_CHANNEL must be dev or prod" >&2; exit 1 ;;
esac
OUT="$HERE/out"; mkdir -p "$OUT"

# Repo mounted :ro (no :z relabel — it would recursively relabel a multi-GB target/; this box has no
# enforcing SELinux). The small mounts use :z to match run-build.sh.
MOUNTS=(
  -v "$REPO:/src:ro"
  -v "$HERE/build-binary.sh:/build-binary.sh:ro,z"
  -v "$OUT:/out:z"
  -v "$CROWD_CAST_OBS_BUNDLE_MANIFEST_PATH:/native/obs-bundle-manifest.json:ro"
)

"$ENGINE" run --rm \
  "${MOUNTS[@]}" \
  -e CARGO_TARGET_DIR=/out/cargo-target \
  -e CROWD_CAST_OBS_ABI="$CROWD_CAST_OBS_ABI" \
  -e CROWD_CAST_BUILD_NUMBER="$CROWD_CAST_BUILD_NUMBER" \
  -e CROWD_CAST_API_GATEWAY_URL="$CROWD_CAST_API_GATEWAY_URL" \
  -e CROWD_CAST_UPDATE_FEED_URL="$CROWD_CAST_UPDATE_FEED_URL" \
  -e CROWD_CAST_UPDATE_PUBKEY="$CROWD_CAST_UPDATE_PUBKEY" \
  -e CROWD_CAST_GOOGLE_CLIENT_ID="$CROWD_CAST_GOOGLE_CLIENT_ID" \
  -e CROWD_CAST_OBS_BUNDLE_MANIFEST_PATH=/native/obs-bundle-manifest.json \
  -e CROWD_CAST_OBS_BUNDLE_MANIFEST_SHA256="$CROWD_CAST_OBS_BUNDLE_MANIFEST_SHA256" \
  -e CROWD_CAST_UPLOAD_TEST="${CROWD_CAST_UPLOAD_TEST:-}" \
  "$IMG" /build-binary.sh
echo "=== out ==="; ls -lh "$OUT/crowd-cast-agent-x86_64"
