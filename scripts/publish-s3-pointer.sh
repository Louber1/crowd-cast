#!/usr/bin/env bash
set -euo pipefail

BUCKET=""
POINTER_KEY=""
ARCHIVE_KEY=""
FILE=""
CONTENT_TYPE="application/octet-stream"

err() { echo "error: $*" >&2; exit 1; }
usage() {
  echo "usage: scripts/publish-s3-pointer.sh --bucket <bucket> --pointer-key <key> --archive-key <key> --file <path> [--content-type <type>]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bucket) BUCKET="$2"; shift 2 ;;
    --pointer-key) POINTER_KEY="$2"; shift 2 ;;
    --archive-key) ARCHIVE_KEY="$2"; shift 2 ;;
    --file) FILE="$2"; shift 2 ;;
    --content-type) CONTENT_TYPE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; err "unknown option: $1" ;;
  esac
done

[[ -n "$BUCKET" ]] || err "--bucket is required"
[[ -n "$POINTER_KEY" ]] || err "--pointer-key is required"
[[ -n "$ARCHIVE_KEY" ]] || err "--archive-key is required"
[[ -f "$FILE" ]] || err "--file must name an existing regular file"
[[ "$POINTER_KEY" != "$ARCHIVE_KEY" ]] || err "pointer and archive keys must differ"
for key in "$POINTER_KEY" "$ARCHIVE_KEY"; do
  [[ "$key" != /* && "$key" != *\\* && "$key" != *../* && "$key" != */..* ]] \
    || err "invalid S3 key: $key"
done
command -v aws >/dev/null 2>&1 || err "aws CLI is required"
command -v sha256sum >/dev/null 2>&1 || err "sha256sum is required"

versioning="$(aws s3api get-bucket-versioning --bucket "$BUCKET" --query Status --output text)"
[[ "$versioning" == "Enabled" ]] || err "S3 bucket versioning must be Enabled"

work="$(mktemp -d "${TMPDIR:-/tmp}/crowd-cast-s3-pointer.XXXXXX")"
trap 'rm -rf "$work"' EXIT
expected_sha="$(sha256sum "$FILE" | awk '{print $1}')"
expected_size="$(wc -c < "$FILE" | tr -d ' ')"

aws s3api put-object \
  --bucket "$BUCKET" \
  --key "$ARCHIVE_KEY" \
  --body "$FILE" \
  --content-type "$CONTENT_TYPE" \
  --metadata "sha256=$expected_sha,size=$expected_size" \
  --if-none-match '*' >/dev/null
aws s3api get-object --bucket "$BUCKET" --key "$ARCHIVE_KEY" "$work/archive" >/dev/null
[[ "$(wc -c < "$work/archive" | tr -d ' ')" == "$expected_size" ]] \
  || err "immutable archive readback size mismatch"
[[ "$(sha256sum "$work/archive" | awk '{print $1}')" == "$expected_sha" ]] \
  || err "immutable archive readback SHA-256 mismatch"

old_exists=0
old_etag=""
old_version=""
if old_identity="$(aws s3api head-object \
    --bucket "$BUCKET" \
    --key "$POINTER_KEY" \
    --query '[ETag,VersionId]' \
    --output text 2>/dev/null)"; then
  read -r old_etag old_version <<< "$old_identity"
  [[ -n "$old_etag" && -n "$old_version" && "$old_version" != "None" ]] \
    || err "existing pointer lacks an exact version identity"
  old_exists=1
fi

put_args=(
  s3api put-object
  --bucket "$BUCKET"
  --key "$POINTER_KEY"
  --body "$FILE"
  --content-type "$CONTENT_TYPE"
  --cache-control no-cache
  --metadata "sha256=$expected_sha,size=$expected_size,archive-key=$ARCHIVE_KEY"
)
if [[ "$old_exists" -eq 1 ]]; then
  put_args+=(--if-match "$old_etag")
else
  put_args+=(--if-none-match '*')
fi
set +e
new_identity="$(aws "${put_args[@]}" --query '[ETag,VersionId]' --output text)"
put_status=$?
set -e
read -r new_etag new_version <<< "$new_identity"
if [[ "$put_status" -ne 0 || -z "$new_etag" || -z "$new_version" || "$new_version" == "None" ]]; then
  recovered_identity="$(aws s3api head-object \
    --bucket "$BUCKET" \
    --key "$POINTER_KEY" \
    --query '[ETag,VersionId,Metadata."archive-key"]' \
    --output text 2>/dev/null)" \
    || err "pointer publication failed without a recoverable exact identity"
  read -r new_etag new_version recovered_archive <<< "$recovered_identity"
  [[ -n "$new_etag" && -n "$new_version" && "$new_version" != "None" ]] \
    || err "recovered pointer lacks an exact version identity"
  [[ "$recovered_archive" == "$ARCHIVE_KEY" ]] \
    || err "pointer publication outcome is ambiguous"
  if [[ "$old_exists" -eq 1 && "$new_version" == "$old_version" ]]; then
    err "pointer publication did not create a new version"
  fi
fi

readback_ok=0
if aws s3api get-object \
    --bucket "$BUCKET" \
    --key "$POINTER_KEY" \
    --version-id "$new_version" \
    "$work/current" >/dev/null; then
  if [[ "$(wc -c < "$work/current" | tr -d ' ')" == "$expected_size" \
      && "$(sha256sum "$work/current" | awk '{print $1}')" == "$expected_sha" ]]; then
    readback_ok=1
  fi
fi

if [[ "$readback_ok" -ne 1 ]]; then
  echo "error: pointer readback mismatch; deleting the exact new version" >&2
  aws s3api delete-object \
    --bucket "$BUCKET" \
    --key "$POINTER_KEY" \
    --version-id "$new_version" >/dev/null
  if [[ "$old_exists" -eq 1 ]]; then
    restored_identity="$(aws s3api head-object \
      --bucket "$BUCKET" --key "$POINTER_KEY" \
      --query '[ETag,VersionId]' --output text)"
    read -r restored_etag restored_version <<< "$restored_identity"
    [[ "$restored_etag" == "$old_etag" && "$restored_version" == "$old_version" ]] \
      || err "pointer rollback did not restore the prior exact version"
  elif aws s3api head-object --bucket "$BUCKET" --key "$POINTER_KEY" >/dev/null 2>&1; then
    err "pointer rollback did not restore absence"
  fi
  exit 1
fi

printf 'published s3://%s/%s version=%s sha256=%s size=%s\n' \
  "$BUCKET" "$POINTER_KEY" "$new_version" "$expected_sha" "$expected_size"
