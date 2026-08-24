#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/crowd-cast-publisher-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT
FAKE_BIN="$TEST_ROOT/bin"
export FAKE_AWS_STATE="$TEST_ROOT/state.json"
mkdir -p "$FAKE_BIN"
printf '{"next":1,"objects":{},"lost":[]}' > "$FAKE_AWS_STATE"

cat > "$FAKE_BIN/aws" <<'PY'
#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import shutil
import sys

state_path = pathlib.Path(os.environ["FAKE_AWS_STATE"])
state = json.loads(state_path.read_text(encoding="utf-8"))
args = sys.argv[1:]


def value(flag, default=None):
    try:
        return args[args.index(flag) + 1]
    except ValueError:
        return default


def save():
    state_path.write_text(json.dumps(state, separators=(",", ":"), sort_keys=True), encoding="utf-8")


def current(key):
    versions = state["objects"].get(key, [])
    return versions[-1] if versions else None


if args[:2] == ["s3api", "get-bucket-versioning"]:
    print("Enabled")
elif args[:2] == ["s3api", "put-object"]:
    key = value("--key")
    previous = current(key)
    if "--if-none-match" in args and previous is not None:
        raise SystemExit(1)
    if "--if-match" in args and (previous is None or previous["etag"] != value("--if-match")):
        raise SystemExit(1)
    data = pathlib.Path(value("--body")).read_bytes()
    version = str(state["next"])
    state["next"] += 1
    metadata = {}
    for entry in (value("--metadata", "") or "").split(","):
        if "=" in entry:
            name, item = entry.split("=", 1)
            metadata[name] = item
    record = {
        "version": version,
        "etag": f'"{hashlib.sha256(data).hexdigest()[:32]}-{version}"',
        "body": data.hex(),
        "metadata": metadata,
    }
    state["objects"].setdefault(key, []).append(record)
    lose_key = os.environ.get("FAKE_AWS_LOSE_PUT_RESPONSE_KEY")
    lose_marker = f"{key}:{version}"
    if key == lose_key and lose_marker not in state["lost"]:
        state["lost"].append(lose_marker)
        save()
        raise SystemExit(1)
    save()
    print(f'{record["etag"]}\t{version}')
elif args[:2] == ["s3api", "head-object"]:
    key = value("--key")
    record = current(key)
    if record is None:
        raise SystemExit(254)
    query = value("--query", "")
    if "archive-key" in query:
        print(f'{record["etag"]}\t{record["version"]}\t{record["metadata"].get("archive-key", "None")}')
    elif "VersionId" in query:
        print(f'{record["etag"]}\t{record["version"]}')
    else:
        print("{}")
elif args[:2] == ["s3api", "get-object"]:
    key = value("--key")
    version = value("--version-id")
    records = state["objects"].get(key, [])
    record = next((item for item in records if item["version"] == version), None) if version else current(key)
    if record is None:
        raise SystemExit(254)
    output_path = pathlib.Path(args[-1])
    if os.environ.get("FAKE_AWS_CORRUPT_GET_KEY") == key and version:
        output_path.write_bytes(b"corrupt")
    else:
        output_path.write_bytes(bytes.fromhex(record["body"]))
    print("{}")
elif args[:2] == ["s3api", "delete-object"]:
    key = value("--key")
    version = value("--version-id")
    records = state["objects"].get(key, [])
    state["objects"][key] = [item for item in records if item["version"] != version]
    save()
    print("{}")
else:
    raise SystemExit(f"unsupported fake aws invocation: {args!r}")
PY
chmod 0755 "$FAKE_BIN/aws"

export PATH="$FAKE_BIN:$PATH"
printf 'pointer one\n' > "$TEST_ROOT/pointer-one"
printf 'pointer two\n' > "$TEST_ROOT/pointer-two"
printf 'pointer three\n' > "$TEST_ROOT/pointer-three"

"$SCRIPT_DIR/publish-s3-pointer.sh" \
    --bucket test \
    --pointer-key feed.xml \
    --archive-key archive/one.xml \
    --file "$TEST_ROOT/pointer-one" >/dev/null

FAKE_AWS_LOSE_PUT_RESPONSE_KEY=feed.xml \
"$SCRIPT_DIR/publish-s3-pointer.sh" \
    --bucket test \
    --pointer-key feed.xml \
    --archive-key archive/two.xml \
    --file "$TEST_ROOT/pointer-two" >/dev/null

if FAKE_AWS_CORRUPT_GET_KEY=feed.xml \
    "$SCRIPT_DIR/publish-s3-pointer.sh" \
        --bucket test \
        --pointer-key feed.xml \
        --archive-key archive/three.xml \
        --file "$TEST_ROOT/pointer-three" >/dev/null 2>&1; then
    echo "pointer publisher accepted a corrupt readback" >&2
    exit 1
fi
aws s3api get-object --bucket test --key feed.xml "$TEST_ROOT/pointer-current" >/dev/null
cmp "$TEST_ROOT/pointer-two" "$TEST_ROOT/pointer-current"

printf '{"build":1}\n' > "$TEST_ROOT/manifest-one"
printf 'signature-one\n' > "$TEST_ROOT/signature-one"
printf '{"build":2}\n' > "$TEST_ROOT/manifest-two"
printf 'signature-two\n' > "$TEST_ROOT/signature-two"

"$SCRIPT_DIR/publish-s3-signed-feed.sh" \
    --bucket test \
    --pointer-key signed.json \
    --archive-prefix signed-archive/one \
    --manifest "$TEST_ROOT/manifest-one" \
    --signature "$TEST_ROOT/signature-one" >/dev/null

if FAKE_AWS_CORRUPT_GET_KEY=signed.json \
    "$SCRIPT_DIR/publish-s3-signed-feed.sh" \
        --bucket test \
        --pointer-key signed.json \
        --archive-prefix signed-archive/two \
        --manifest "$TEST_ROOT/manifest-two" \
        --signature "$TEST_ROOT/signature-two" >/dev/null 2>&1; then
    echo "signed feed publisher accepted a corrupt manifest readback" >&2
    exit 1
fi
aws s3api get-object --bucket test --key signed.json "$TEST_ROOT/manifest-current" >/dev/null
aws s3api get-object --bucket test --key signed.json.sig "$TEST_ROOT/signature-current" >/dev/null
cmp "$TEST_ROOT/manifest-one" "$TEST_ROOT/manifest-current"
cmp "$TEST_ROOT/signature-one" "$TEST_ROOT/signature-current"

echo "release publisher tests passed"
