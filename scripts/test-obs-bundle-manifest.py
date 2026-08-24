#!/usr/bin/env python3
import copy
import hashlib
import json
import pathlib
import subprocess
import tempfile

SCRIPT = pathlib.Path(__file__).with_name("verify-obs-bundle-manifest.py")
GIT_COMMIT = "1" * 40
GIT_TREE = "2" * 40
BUNDLE = b"exact native archive"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def manifest():
    return {
        "schema": "libobs-native-bundle-manifest-v1",
        "platform": "linux",
        "arch": "x86_64",
        "obs_abi": "32.0.2",
        "implementation_id": "crowdcast_hybrid_mp4_v1",
        "provenance": {
            "obs": {
                "upstream_commit": "3" * 40,
                "upstream_tree": "4" * 40,
                "patch_commit": "5" * 40,
                "patched_tree": "6" * 40,
            },
            "libobs_rs": {
                "commit": GIT_COMMIT,
                "tree": GIT_TREE,
                "generated_bindings": [
                    {"path": "bindings/bindings_linux.rs", "size": 7, "sha256": digest(b"binding")}
                ],
            },
            "build": {
                "recipe": {"path": "build/recipe.sh", "size": 6, "sha256": digest(b"recipe")},
                "builder_image": {
                    "reference": f"registry.example/crowdcast/obs@sha256:{'7' * 64}",
                    "digest": f"sha256:{'7' * 64}",
                },
                "dependencies": [
                    {
                        "name": "ffmpeg",
                        "material": {
                            "url": "https://sources.example/ffmpeg.tar.xz",
                            "size": 8,
                            "sha256": digest(b"ffmpeg!!"),
                        },
                        "vcs": {
                            "repository": "https://github.com/FFmpeg/FFmpeg.git",
                            "commit": "8" * 40,
                            "tree": "9" * 40,
                        },
                    }
                ],
            },
        },
        "entries": [
            {"path": "lib/libobs.so", "type": "file", "size": 3, "sha256": digest(b"obs"), "mode": 493},
            {"path": "lib/libobs.so.32", "type": "symlink", "target": "libobs.so"},
        ],
        "bundle": {
            "url": "https://artifacts.example/obs-bundle.tar.zst",
            "size": len(BUNDLE),
            "sha256": digest(BUNDLE),
        },
    }


def run_case(root, value, bundle=BUNDLE, expect_success=False, raw=None):
    manifest_path = root / "manifest.json"
    bundle_path = root / "bundle"
    summary_path = root / "summary.json"
    data = raw if raw is not None else json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    manifest_path.write_bytes(data)
    bundle_path.write_bytes(bundle)
    result = subprocess.run(
        [
            str(SCRIPT),
            "--manifest",
            str(manifest_path),
            "--manifest-sha256",
            digest(data),
            "--platform",
            "linux",
            "--arch",
            "x86_64",
            "--approved-libobs-revision",
            GIT_COMMIT,
            "--bundle",
            str(bundle_path),
            "--summary-out",
            str(summary_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if (result.returncode == 0) != expect_success:
        raise AssertionError(f"unexpected validator result: {result.stderr}")
    return summary_path


with tempfile.TemporaryDirectory(prefix="crowd-cast-manifest-test-") as temporary:
    root = pathlib.Path(temporary)
    valid = manifest()
    summary_path = run_case(root, valid, expect_success=True)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["implementation_id"] == "crowdcast_hybrid_mp4_v1"
    assert summary["bundle_sha256"] == digest(BUNDLE)

    unknown = copy.deepcopy(valid)
    unknown["fallback"] = True
    run_case(root, unknown)

    unsafe = copy.deepcopy(valid)
    unsafe["entries"][0]["path"] = "../obs.dll"
    run_case(root, unsafe)

    non_normalized = copy.deepcopy(valid)
    non_normalized["entries"][0]["path"] = "lib//libobs.so"
    run_case(root, non_normalized)

    zero_byte_file = copy.deepcopy(valid)
    zero_byte_file["entries"][0]["size"] = 0
    zero_byte_file["entries"][0]["sha256"] = digest(b"")
    run_case(root, zero_byte_file)

    invalid_mode = copy.deepcopy(valid)
    invalid_mode["entries"][0]["mode"] = 2541
    run_case(root, invalid_mode)

    upward_link = copy.deepcopy(valid)
    upward_link["entries"][1]["target"] = "../libobs.so"
    run_case(root, upward_link)

    mutable_image = copy.deepcopy(valid)
    mutable_image["provenance"]["build"]["builder_image"]["reference"] = "registry.example/obs:latest"
    run_case(root, mutable_image)

    control_url = copy.deepcopy(valid)
    control_url["bundle"]["url"] = "https://artifacts.example/obs\n-bundle.tar.zst"
    run_case(root, control_url)

    duplicate = json.dumps(valid, separators=(",", ":")).encode()
    duplicate = duplicate[:-1] + b',"schema":"libobs-native-bundle-manifest-v1"}'
    run_case(root, valid, raw=duplicate)

    run_case(root, valid, bundle=BUNDLE + b"tampered")

    run_case(root, valid, raw=b" " * (1024 * 1024 + 1))

print("OBS bundle manifest tests passed")
