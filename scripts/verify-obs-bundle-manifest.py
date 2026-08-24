#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import urllib.parse

SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_ID = re.compile(r"[0-9a-f]{40}")
IDENTIFIER = re.compile(r"[A-Za-z0-9._+-]+")
SCHEMA = "libobs-native-bundle-manifest-v1"
IMPLEMENTATION_ID = "crowdcast_hybrid_mp4_v1"
MAX_MANIFEST_BYTES = 1024 * 1024
FILE_MODES = {420, 493}


def fail(message):
    raise ValueError(message)


def object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def exact_keys(value, expected, label):
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    actual = set(value)
    if actual != set(expected):
        fail(f"{label} fields differ: expected {sorted(expected)}, got {sorted(actual)}")


def exact_or_optional_keys(value, required, optional, label):
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    actual = set(value)
    if not set(required).issubset(actual) or not actual.issubset(set(required) | set(optional)):
        fail(f"{label} has missing or unknown fields")


def positive_integer(value, label):
    if type(value) is not int or value < 1:
        fail(f"{label} must be positive integer")


def sha256(value, label):
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        fail(f"{label} must be canonical lowercase SHA-256")


def git_id(value, label):
    if not isinstance(value, str) or GIT_ID.fullmatch(value) is None:
        fail(f"{label} must be a canonical 40-character Git identity")


def safe_path(value, label):
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a non-empty path")
    path = pathlib.PurePosixPath(value)
    if (
        not value.isascii()
        or any(ord(character) <= 32 or ord(character) == 127 for character in value)
        or path.is_absolute()
        or str(path) != value
        or "." in path.parts
        or ".." in path.parts
        or "\\" in value
    ):
        fail(f"{label} is not a normalized relative POSIX path")


def safe_link_target(value, label):
    safe_path(value, label)
    if value.startswith("/"):
        fail(f"{label} must be relative")


def exact_https_url(value, label):
    if (
        not isinstance(value, str)
        or not value.isascii()
        or any(ord(character) <= 32 or ord(character) == 127 for character in value)
    ):
        fail(f"{label} must be a URL string")
    url = urllib.parse.urlsplit(value)
    try:
        url.port
    except ValueError as error:
        fail(f"{label} has an invalid port: {error}")
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.geturl() != value
    ):
        fail(f"{label} must be exact HTTPS without credentials, query, or fragment")


def file_record(value, label):
    exact_keys(value, {"path", "size", "sha256"}, label)
    safe_path(value["path"], f"{label}.path")
    positive_integer(value["size"], f"{label}.size")
    sha256(value["sha256"], f"{label}.sha256")


def shipped_entry(value, label):
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    entry_type = value.get("type")
    if entry_type == "file":
        exact_keys(value, {"path", "type", "size", "sha256", "mode"}, label)
        safe_path(value["path"], f"{label}.path")
        positive_integer(value["size"], f"{label}.size")
        sha256(value["sha256"], f"{label}.sha256")
        if type(value["mode"]) is not int or value["mode"] not in FILE_MODES:
            fail(f"{label}.mode must be integer 420 (0644) or 493 (0755)")
    elif entry_type == "symlink":
        exact_keys(value, {"path", "type", "target"}, label)
        safe_path(value["path"], f"{label}.path")
        safe_link_target(value["target"], f"{label}.target")
    else:
        fail(f"{label}.type must be file or symlink")


def material(value, label):
    exact_keys(value, {"url", "size", "sha256"}, label)
    exact_https_url(value["url"], f"{label}.url")
    positive_integer(value["size"], f"{label}.size")
    sha256(value["sha256"], f"{label}.sha256")


def validate(manifest, args):
    exact_keys(
        manifest,
        {"schema", "platform", "arch", "obs_abi", "implementation_id", "provenance", "entries", "bundle"},
        "manifest",
    )
    if manifest["schema"] != SCHEMA:
        fail(f"manifest.schema must equal {SCHEMA}")
    if manifest["platform"] != args.platform or manifest["arch"] != args.arch:
        fail("manifest target does not equal the expected platform and architecture")
    if not isinstance(manifest["obs_abi"], str) or IDENTIFIER.fullmatch(manifest["obs_abi"]) is None:
        fail("manifest.obs_abi is invalid")
    if manifest["implementation_id"] != IMPLEMENTATION_ID:
        fail(f"manifest.implementation_id must equal {IMPLEMENTATION_ID}")

    provenance = manifest["provenance"]
    exact_keys(provenance, {"obs", "libobs_rs", "build"}, "provenance")
    obs = provenance["obs"]
    exact_keys(obs, {"upstream_commit", "upstream_tree", "patch_commit", "patched_tree"}, "provenance.obs")
    for name in ("upstream_commit", "upstream_tree", "patch_commit", "patched_tree"):
        git_id(obs[name], f"provenance.obs.{name}")

    libobs_rs = provenance["libobs_rs"]
    exact_keys(libobs_rs, {"commit", "tree", "generated_bindings"}, "provenance.libobs_rs")
    git_id(libobs_rs["commit"], "provenance.libobs_rs.commit")
    git_id(libobs_rs["tree"], "provenance.libobs_rs.tree")
    if libobs_rs["commit"] != args.approved_libobs_revision:
        fail("manifest libobs-rs commit is not the independently approved revision")
    bindings = libobs_rs["generated_bindings"]
    if not isinstance(bindings, list) or not bindings:
        fail("provenance.libobs_rs.generated_bindings must be a non-empty array")
    for index, record in enumerate(bindings):
        file_record(record, f"provenance.libobs_rs.generated_bindings[{index}]")
    binding_paths = [record["path"] for record in bindings]
    if len(binding_paths) != len(set(binding_paths)) or binding_paths != sorted(binding_paths):
        fail("generated binding paths must be unique and sorted")

    build = provenance["build"]
    exact_keys(build, {"recipe", "builder_image", "dependencies"}, "provenance.build")
    file_record(build["recipe"], "provenance.build.recipe")
    builder_image = build["builder_image"]
    exact_keys(builder_image, {"reference", "digest"}, "provenance.build.builder_image")
    digest = builder_image["digest"]
    if not isinstance(digest, str) or not digest.startswith("sha256:") or SHA256.fullmatch(digest[7:]) is None:
        fail("builder image digest must be canonical sha256")
    if not isinstance(builder_image["reference"], str) or not builder_image["reference"].endswith("@" + digest):
        fail("builder image reference must end with its exact digest")

    dependencies = build["dependencies"]
    if not isinstance(dependencies, list) or not dependencies:
        fail("provenance.build.dependencies must be a non-empty array")
    dependency_names = []
    for index, dependency in enumerate(dependencies):
        label = f"provenance.build.dependencies[{index}]"
        exact_or_optional_keys(dependency, {"name", "material"}, {"vcs"}, label)
        if not isinstance(dependency["name"], str) or IDENTIFIER.fullmatch(dependency["name"]) is None:
            fail(f"{label}.name is invalid")
        dependency_names.append(dependency["name"])
        material(dependency["material"], f"{label}.material")
        if "vcs" in dependency:
            vcs = dependency["vcs"]
            exact_keys(vcs, {"repository", "commit", "tree"}, f"{label}.vcs")
            exact_https_url(vcs["repository"], f"{label}.vcs.repository")
            git_id(vcs["commit"], f"{label}.vcs.commit")
            git_id(vcs["tree"], f"{label}.vcs.tree")
    if len(dependency_names) != len(set(dependency_names)) or dependency_names != sorted(dependency_names):
        fail("dependency names must be unique and sorted")

    entries = manifest["entries"]
    if not isinstance(entries, list) or not entries:
        fail("manifest.entries must be a non-empty array")
    for index, entry in enumerate(entries):
        shipped_entry(entry, f"manifest.entries[{index}]")
    entry_paths = [entry["path"] for entry in entries]
    if len(entry_paths) != len(set(entry_paths)) or entry_paths != sorted(entry_paths):
        fail("manifest entry paths must be unique and sorted")

    bundle = manifest["bundle"]
    exact_keys(bundle, {"url", "size", "sha256"}, "manifest.bundle")
    exact_https_url(bundle["url"], "manifest.bundle.url")
    positive_integer(bundle["size"], "manifest.bundle.size")
    sha256(bundle["sha256"], "manifest.bundle.sha256")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--platform", required=True, choices=("linux", "macos", "windows"))
    parser.add_argument("--arch", required=True)
    parser.add_argument("--approved-libobs-revision", required=True)
    parser.add_argument("--bundle", type=pathlib.Path)
    parser.add_argument("--summary-out", required=True, type=pathlib.Path)
    args = parser.parse_args()

    sha256(args.manifest_sha256, "--manifest-sha256")
    git_id(args.approved_libobs_revision, "--approved-libobs-revision")
    with args.manifest.open("rb") as manifest_file:
        manifest_stat = os.fstat(manifest_file.fileno())
        if not stat.S_ISREG(manifest_stat.st_mode):
            fail("manifest must be a regular file")
        if manifest_stat.st_size < 1 or manifest_stat.st_size > MAX_MANIFEST_BYTES:
            fail(f"manifest size must be between 1 and {MAX_MANIFEST_BYTES} bytes")
        manifest_bytes = manifest_file.read(MAX_MANIFEST_BYTES + 1)
    if len(manifest_bytes) != manifest_stat.st_size:
        fail("manifest changed while it was read")
    actual_manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    if actual_manifest_sha != args.manifest_sha256:
        fail("exact manifest byte SHA-256 mismatch")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"), object_pairs_hook=object_without_duplicates)
    except UnicodeDecodeError as error:
        fail(f"manifest is not UTF-8: {error}")
    validate(manifest, args)

    bundle = manifest["bundle"]
    if args.bundle is not None:
        bundle_hash = hashlib.sha256()
        observed_size = 0
        with args.bundle.open("rb") as bundle_file:
            bundle_stat = os.fstat(bundle_file.fileno())
            if not stat.S_ISREG(bundle_stat.st_mode):
                fail("bundle must be a regular file")
            if bundle_stat.st_size != bundle["size"]:
                fail("bundle size does not equal manifest")
            while chunk := bundle_file.read(1024 * 1024):
                observed_size += len(chunk)
                bundle_hash.update(chunk)
        if observed_size != bundle["size"]:
            fail("bundle size does not equal manifest")
        if bundle_hash.hexdigest() != bundle["sha256"]:
            fail("bundle SHA-256 does not equal manifest")

    summary = {
        "arch": manifest["arch"],
        "bundle_sha256": bundle["sha256"],
        "bundle_size": bundle["size"],
        "bundle_url": bundle["url"],
        "implementation_id": manifest["implementation_id"],
        "manifest_sha256": actual_manifest_sha,
        "obs_abi": manifest["obs_abi"],
        "platform": manifest["platform"],
    }
    args.summary_out.write_text(json.dumps(summary, separators=(",", ":"), sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
