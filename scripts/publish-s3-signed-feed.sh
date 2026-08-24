#!/usr/bin/env bash
set -euo pipefail

BUCKET=""
POINTER_KEY=""
ARCHIVE_PREFIX=""
MANIFEST=""
SIGNATURE=""

err() { echo "error: $*" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bucket) BUCKET="$2"; shift 2 ;;
    --pointer-key) POINTER_KEY="$2"; shift 2 ;;
    --archive-prefix) ARCHIVE_PREFIX="$2"; shift 2 ;;
    --manifest) MANIFEST="$2"; shift 2 ;;
    --signature) SIGNATURE="$2"; shift 2 ;;
    *) err "unknown option: $1" ;;
  esac
done

[[ -n "$BUCKET" ]] || err "--bucket is required"
[[ -n "$POINTER_KEY" ]] || err "--pointer-key is required"
[[ -n "$ARCHIVE_PREFIX" ]] || err "--archive-prefix is required"
[[ -f "$MANIFEST" ]] || err "--manifest must name an existing file"
[[ -f "$SIGNATURE" ]] || err "--signature must name an existing file"
for key in "$POINTER_KEY" "$ARCHIVE_PREFIX"; do
  [[ "$key" != /* && "$key" != *\\* && "$key" != *../* && "$key" != */..* ]] \
    || err "invalid S3 key: $key"
done
command -v aws >/dev/null 2>&1 || err "aws CLI is required"
command -v sha256sum >/dev/null 2>&1 || err "sha256sum is required"

versioning="$(aws s3api get-bucket-versioning --bucket "$BUCKET" --query Status --output text)"
[[ "$versioning" == "Enabled" ]] || err "S3 bucket versioning must be Enabled"

work="$(mktemp -d "${TMPDIR:-/tmp}/crowd-cast-s3-feed.XXXXXX")"
trap 'rm -rf "$work"' EXIT

verify_file() {
  local actual="$1" expected="$2" label="$3"
  [[ "$(wc -c < "$actual" | tr -d ' ')" == "$(wc -c < "$expected" | tr -d ' ')" ]] \
    || { echo "error: $label readback size mismatch" >&2; return 1; }
  [[ "$(sha256sum "$actual" | awk '{print $1}')" == "$(sha256sum "$expected" | awk '{print $1}')" ]] \
    || { echo "error: $label readback SHA-256 mismatch" >&2; return 1; }
}

put_immutable() {
  local key="$1" file="$2" content_type="$3" readback="$4"
  local sha size
  sha="$(sha256sum "$file" | awk '{print $1}')"
  size="$(wc -c < "$file" | tr -d ' ')"
  aws s3api put-object \
    --bucket "$BUCKET" --key "$key" --body "$file" \
    --content-type "$content_type" --metadata "sha256=$sha,size=$size" \
    --if-none-match '*' >/dev/null
  aws s3api get-object --bucket "$BUCKET" --key "$key" "$readback" >/dev/null
  verify_file "$readback" "$file" "immutable $key"
}

manifest_archive="$ARCHIVE_PREFIX/appcast-linux.json"
signature_archive="$ARCHIVE_PREFIX/appcast-linux.json.sig"
put_immutable "$manifest_archive" "$MANIFEST" application/json "$work/archive-manifest"
put_immutable "$signature_archive" "$SIGNATURE" text/plain "$work/archive-signature"

manifest_key="$POINTER_KEY"
signature_key="$POINTER_KEY.sig"

snapshot_pointer() {
  local key="$1" prefix="$2"
  local identity etag version
  if identity="$(aws s3api head-object --bucket "$BUCKET" --key "$key" --query '[ETag,VersionId]' --output text 2>/dev/null)"; then
    read -r etag version <<< "$identity"
    [[ -n "$etag" && -n "$version" && "$version" != "None" ]] || return 1
    printf -v "${prefix}_old_exists" '%s' 1
    printf -v "${prefix}_old_etag" '%s' "$etag"
    printf -v "${prefix}_old_version" '%s' "$version"
  else
    printf -v "${prefix}_old_exists" '%s' 0
    printf -v "${prefix}_old_etag" '%s' ''
    printf -v "${prefix}_old_version" '%s' ''
  fi
}

publish_pointer() {
  local key="$1" file="$2" content_type="$3" prefix="$4" archive_key="$5"
  local -a args=(
    s3api put-object --bucket "$BUCKET" --key "$key" --body "$file"
    --content-type "$content_type" --cache-control no-cache
    --metadata "archive-key=$archive_key"
  )
  local old_exists_var="${prefix}_old_exists" old_etag_var="${prefix}_old_etag"
  if [[ "${!old_exists_var}" -eq 1 ]]; then
    args+=(--if-match "${!old_etag_var}")
  else
    args+=(--if-none-match '*')
  fi
  local identity etag version status recovered_archive
  set +e
  identity="$(aws "${args[@]}" --query '[ETag,VersionId]' --output text)"
  status=$?
  set -e
  read -r etag version <<< "$identity"
  if [[ "$status" -ne 0 || -z "$etag" || -z "$version" || "$version" == "None" ]]; then
    identity="$(aws s3api head-object \
      --bucket "$BUCKET" --key "$key" \
      --query '[ETag,VersionId,Metadata."archive-key"]' --output text 2>/dev/null)" \
      || return 1
    read -r etag version recovered_archive <<< "$identity"
    [[ -n "$etag" && -n "$version" && "$version" != "None" && "$recovered_archive" == "$archive_key" ]] \
      || return 1
    local old_version_var="${prefix}_old_version"
    if [[ "${!old_exists_var}" -eq 1 && "$version" == "${!old_version_var}" ]]; then
      return 1
    fi
  fi
  printf -v "${prefix}_new_etag" '%s' "$etag"
  printf -v "${prefix}_new_version" '%s' "$version"
}

rollback_pointer() {
  local key="$1" prefix="$2"
  local old_exists_var="${prefix}_old_exists" old_etag_var="${prefix}_old_etag" old_version_var="${prefix}_old_version"
  local new_version_var="${prefix}_new_version"
  local identity etag version
  aws s3api delete-object \
    --bucket "$BUCKET" --key "$key" --version-id "${!new_version_var}" >/dev/null
  if [[ "${!old_exists_var}" -eq 1 ]]; then
    identity="$(aws s3api head-object --bucket "$BUCKET" --key "$key" --query '[ETag,VersionId]' --output text)" \
      || return 1
    read -r etag version <<< "$identity"
    [[ "$etag" == "${!old_etag_var}" && "$version" == "${!old_version_var}" ]] || return 1
  elif aws s3api head-object --bucket "$BUCKET" --key "$key" >/dev/null 2>&1; then
    return 1
  fi
}

verify_pointer() {
  local key="$1" version="$2" file="$3" label="$4"
  aws s3api get-object --bucket "$BUCKET" --key "$key" --version-id "$version" "$work/$label-current" >/dev/null \
    && verify_file "$work/$label-current" "$file" "$label pointer"
}

snapshot_pointer "$signature_key" signature || err "existing signature pointer lacks an exact identity"
snapshot_pointer "$manifest_key" manifest || err "existing manifest pointer lacks an exact identity"

if ! publish_pointer "$signature_key" "$SIGNATURE" text/plain signature "$signature_archive"; then
  err "signature pointer publication failed"
fi
if ! verify_pointer "$signature_key" "$signature_new_version" "$SIGNATURE" signature; then
  rollback_pointer "$signature_key" signature || err "signature pointer readback failed and rollback was not exact"
  err "signature pointer readback failed"
fi

if ! publish_pointer "$manifest_key" "$MANIFEST" application/json manifest "$manifest_archive"; then
  rollback_pointer "$signature_key" signature || err "manifest publication failed and signature rollback was not exact"
  err "manifest pointer publication failed; signature pointer restored"
fi
if ! verify_pointer "$manifest_key" "$manifest_new_version" "$MANIFEST" manifest; then
  rollback_pointer "$manifest_key" manifest || err "manifest readback failed and manifest rollback was not exact"
  rollback_pointer "$signature_key" signature || err "manifest readback failed and signature rollback was not exact"
  err "manifest pointer readback failed; prior feed restored"
fi

printf 'published signed feed s3://%s/%s manifest_version=%s signature_version=%s\n' \
  "$BUCKET" "$manifest_key" "$manifest_new_version" "$signature_new_version"
