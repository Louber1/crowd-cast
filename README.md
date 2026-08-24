<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://huggingface.co/datasets/p-doom/AGI-CAST-0.6k/resolve/main/pdoom_logo_white_transparent.png">
    <img src="https://huggingface.co/datasets/p-doom/AGI-CAST-0.6k/resolve/main/pdoom_logo_black_transparent.png" width="60%" alt="p(doom)" />
  </picture>
</div>
<hr>
<div align="center" style="line-height: 1;">
  <a href="https://www.pdoom.org/"><img alt="Homepage"
    src="https://img.shields.io/badge/Homepage-p%28doom%29-white?logo=home&logoColor=black"/></a>
  <a href="https://huggingface.co/p-doom"><img alt="Hugging Face"
    src="https://img.shields.io/badge/%F0%9F%A4%97%20Hugging%20Face-p--doom-ffc107?color=ffc107&logoColor=white"/></a>
  <br>
  <a href="https://discord.gg/G4JNuPX2VR"><img alt="Discord"
    src="https://img.shields.io/badge/Discord-p%28doom%29-7289da?logo=discord&logoColor=white&color=7289da"/></a>
  <a href="https://github.com/p-doom"><img alt="GitHub"
    src="https://img.shields.io/badge/GitHub-p--doom-24292e?logo=github&logoColor=white"/></a>
  <a href="https://twitter.com/prob_doom"><img alt="Twitter Follow"
    src="https://img.shields.io/badge/Twitter-prob__doom-white?logo=x&logoColor=white"/></a>
  <br>
  <a href="LICENSE.md" style="margin: 2px;">
    <img alt="License" src="https://img.shields.io/badge/License-MIT-f5de53?&color=f5de53" style="display: inline-block; vertical-align: middle;"/>
  </a>
  <br>
</div>

# `crowd-cast`:  Crowd-Sourcing Months-Long Trajectories of Human Computer Work

Infrastructure for capturing paired screencast and keyboard/mouse input data.

## Quick Start

> [![Download for macOS](https://img.shields.io/badge/Download%20for%20macOS-111111?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/p-doom/crowd-cast/releases)
> [![Download for Windows](https://img.shields.io/badge/Download%20for%20Windows-0078D6?style=for-the-badge&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZD0iTTAgMy40NDkgOS43NSAyLjF2OS40NTFIMFptMTAuOTQ5LTEuNTAxTDI0IDB2MTEuNEgxMC45NDlaTTAgMTIuNmg5Ljc1djkuNDUxTDAgMjAuNjk5Wm0xMC45NDkgMEgyNFYyNGwtMTMuMDUxLTEuODAxWiIvPjwvc3ZnPg%3D%3D&logoColor=white)](https://github.com/p-doom/crowd-cast/releases)
> [![Download for Linux](https://img.shields.io/badge/Download%20for%20Linux-E95420?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/p-doom/crowd-cast/releases)

Download the installer for your platform and follow the instructions in the setup wizard.

- **macOS**: open `CrowdCast.dmg` and grant permissions by following the setup wizard.
- **Windows**: download `crowd-cast-setup.exe` from the newest `windows-v...` production release.
- **Linux**: production packaging is fail-closed while the exact OBS runtime is moved into a pre-execution trusted package. Supported sessions are GNOME on Wayland and sway.

GitHub exposes one repository-wide “latest” release, not one per platform. Direct
download buttons therefore lead to the Releases page; platform assets are never
copied into an unrelated release.

## Features

- **Self-contained installation**: No separate OBS Studio installation required
- **Privacy-aware capture**: Only records when selected applications are in the foreground
- **Full control**: Start or stop recording at any time, and delete the last 10 minutes of recording
- **Automatic updates**: Sparkle framework keeps the app up to date in the background
- **Idle detection**: Automatically pauses recording when you step away, resumes on return
- **Hardware acceleration**: Uses native encoding (VideoToolbox on macOS)
- **Efficient uploads**: Streaming uploads via pre-signed S3 URLs with retry/backoff
- **Easy setup**: Wizard handles permissions and application selection

## How It Works

crowd-cast ships an exact, release-bound [libobs](https://github.com/obsproject/obs-studio) runtime for screen capture and recording, eliminating the need to install OBS Studio separately.

**Key components:**

- **Release-bound libobs** - Screen/window capture with hardware encoding (via [libobs-rs](https://github.com/joshprk/libobs-rs))
- **Sync Engine** - Coordinates recording with input capture, filters by frontmost app
- **Input Capture** - Cross-platform keyboard/mouse capture (rdev/evdev)
- **System Tray** - Control recording from the menu bar

```
┌─────────────────────────────────────────────────────────────────┐
│                     crowd-cast Agent (Rust)                     │
│  ┌──────────┐  ┌────────────────┐  ┌─────────────────────────┐  │
│  │ Tray UI  │  │ Embedded libobs│  │      Sync Engine        │  │
│  │          │  │ (libobs-rs)    │  │  - Frontmost app detect │  │
│  └──────────┘  │                │  │  - Input filtering      │  │
│                │  ┌───────────┐ │  │  - Event buffering      │  │
│                │  │mac-capture│ │  └───────────┬─────────────┘  │
│                │  │obs-x264   │ │              │                │
│                │  │obs-ffmpeg │ │        ┌─────┴─────┐          │
│                │  └───────────┘ │        │ rdev/evdev│          │
│                └────────────────┘        └───────────┘          │
│                        │                       │                │
│                   Video Output            Input Events          │
│                        │                       │                │
│                        └───────────┬───────────┘                │
│                                    │                            │
│                              ┌─────┴─────┐                      │
│                              │ Uploader  │                      │
│                              └─────┬─────┘                      │
└────────────────────────────────────┼────────────────────────────┘
                                     │
                                     ▼
                              ┌─────────────┐
                              │ Lambda + S3 │
                              └─────────────┘
```

## Features

- **Self-contained installation**: No separate OBS Studio installation required
- **Privacy-aware capture**: Only records when selected applications are in the foreground
- **Automatic updates**: signed background updates on macOS, Windows, and Linux
- **Idle detection**: Automatically pauses recording when you step away, resumes on return
- **Hardware acceleration**: Uses native encoding (VideoToolbox on macOS)
- **Efficient uploads**: Streaming uploads via pre-signed S3 URLs with retry/backoff
- **Easy setup**: Wizard handles permissions and application selection

## Quick Start

### For users

Download the installer from the newest production release for your platform on the [Releases page](https://github.com/p-doom/crowd-cast/releases):

- macOS: `CrowdCast.dmg`
- Windows: `crowd-cast-setup.exe`
- Linux: production packaging is currently fail-closed pending a pre-execution trusted OBS closure

Linux support is limited to GNOME on Wayland and sway. GNOME supports per-app capture; sway currently supports full-screen capture.

### Building from source

```bash
# Clone the repository
git clone https://github.com/p-doom/crowd-cast.git
cd crowd-cast

# Build (endpoint required at build time)
CROWD_CAST_API_GATEWAY_URL="https://your-api-gateway.execute-api.region.amazonaws.com/prod/presign" \
  cargo build --release

# Run the setup wizard
./target/release/crowd-cast-agent --setup
```

> **Build speed:** `cargo build --release` is tuned for fast incremental rebuilds
> (~seconds, not minutes) — LTO is off because it costs minutes and buys nothing for
> this libobs-backed app. For an even quicker loop use `cargo run` (debug).

On macOS, `build.rs` automatically installs OBS binaries via `cargo-obs-build` during
`cargo build`. Set `CROWD_CAST_SKIP_OBS_INSTALL=1` to skip this behavior.

On **Linux** there is no automatic OBS install, so the linker has to be told where
`libobs` lives — otherwise the build fails at link time with
`rust-lld: error: unable to find library -lobs`. Set `LIBOBS_PATH` to a directory
that contains `libobs.so` (the unversioned linker symlink), built for the OBS ABI in
`CROWD_CAST_OBS_ABI` (default `32.0.2`):

```bash
# Linux build
LIBOBS_PATH=/path/to/obs/usr/lib \
CROWD_CAST_API_GATEWAY_URL="https://your-api-gateway.execute-api.region.amazonaws.com/prod/presign" \
  cargo build --release
```

`cargo check` does not link, so it will not catch a missing or wrong `LIBOBS_PATH` —
only `cargo build`/`run` will.

## Platform-Specific Setup

### macOS

1. Grant **Accessibility** permission to the agent (System Settings → Privacy & Security → Accessibility)

#### macOS Distribution

An operator provisions each dedicated macOS signing runner once, through an
interactive TTY. Password prompts are owned by Apple's tools and are never passed
through script arguments or environment variables:

```bash
scripts/setup-macos-signing.sh \
  --p12 /path/to/developer-id.p12 \
  --identity "Developer ID Application: Your Name (TEAMID)" \
  --apple-id operator@example.com \
  --team-id TEAMID
```

The matching Sparkle private key must also be pre-provisioned in that runner's
Keychain. Release builds, signing, notarization, GitHub publication, and the S3
appcast update are authorized only by the protected `macos-release.yml` workflow.
Developer workstations have no release publisher.

```bash
gh workflow run macos-release.yml --ref main -f channel=prod
```

Auto-updates are delivered via Sparkle using an appcast hosted on S3.

### Linux

Linux production release is fail-closed while the exact OBS runtime is moved out
of the former user-writable pre-main loader path and into a signed or read-only
package that can authorize it before process start.

Supported Linux sessions are GNOME on Wayland and sway. Other desktop sessions are blocked during setup so the agent does not run in an unvalidated capture mode. Linux auto-updates use a signed appcast hosted on S3 and install silently when recording and uploads are idle.

### Windows

Windows production release is fail-closed while the signed installer is migrated
to carry the exact OBS runtime closure under protected installation ACLs.

## Configuration

Most settings are managed through the setup wizard and the tray menu. The configuration file is at:

- macOS: `~/Library/Application Support/dev.crowd-cast.agent/config.toml`
- Linux: `~/.config/agent/config.toml`
- Windows: `%APPDATA%\agent\config.toml`

Key settings:

```toml
[capture]
target_apps = ["org.mozilla.firefox", "com.apple.Terminal"]
capture_all = false
idle_timeout_secs = 120          # Pause after 2 min of inactivity
single_active_app_capture = true # One app captured at a time (multi-scene)

[recording]
autostart_on_launch = true
notify_on_start_stop = true
segment_duration_secs = 300      # 5-minute recording segments

[upload]
delete_after_upload = true
```

Upload endpoint is set at build time via `CROWD_CAST_API_GATEWAY_URL`.

## Data Format

Input logs are stored in MessagePack format. Each file contains an array of `[timestamp_us, [event_type, event_data]]` tuples:

```
[0,         ["ContextChanged", ["com.apple.Terminal"]]]
[1234000,   ["KeyPress",       [0, "KeyA"]]]
[1334000,   ["KeyRelease",     [0, "KeyA"]]]
[1500000,   ["MouseMove",      [12.5, -3.2]]]
[2000000,   ["MousePress",     ["Left", 540.0, 320.0]]]
[2100000,   ["MouseRelease",   ["Left", 540.0, 320.0]]]
[2500000,   ["MouseScroll",    [0.0, -3.0, 540.0, 320.0]]]
[3999000,   ["ContextChanged", ["UNCAPTURED"]]]
```

Event types:

- `ContextChanged`: app switch (bundle ID or `UNCAPTURED` for untracked apps)
- `KeyPress` / `KeyRelease`: `[key_code, key_name]`
- `MouseMove`: `[delta_x, delta_y]`
- `MousePress` / `MouseRelease`: `[button, x, y]`
- `MouseScroll`: `[delta_x, delta_y, x, y]`

Timestamps are microseconds relative to the segment start. Video and input files share the same session/segment IDs for alignment.

## Development

This section is for contributors who want to modify crowd-cast.

### First Run (Recommended)

```bash
crowd-cast-agent --setup
```

This runs the interactive setup wizard that guides you through configuration.

### Normal Usage

```bash
crowd-cast-agent
```

The agent will:

1. Verify and initialize the release-bound libobs runtime
2. Initialize capture
3. Show in your system tray
4. Capture input when selected apps are in foreground

### Command Line Options

```
crowd-cast-agent [OPTIONS]

OPTIONS:
    -h, --help    Print help message
    -s, --setup   Run the setup wizard (re-select apps, etc.)

ENVIRONMENT:
    RUST_LOG      Set log level (e.g., debug, info, warn)
    CROWD_CAST_LOG_PATH
                  Override log directory (default: ~/Library/Logs/crowd-cast on macOS)
    CROWD_CAST_API_GATEWAY_URL
                  Lambda endpoint for pre-signed S3 URLs (set at build time)
```

### Building from Source

#### Prerequisites

**macOS (Apple Silicon):**

```bash
brew install simde       # Required for ARM builds
brew install create-dmg  # Required for release DMG packaging
```

#### Build Steps

```bash
# 1. Clone with submodules
git clone --recursive https://github.com/p-doom/crowd-cast.git
cd crowd-cast

# 2. Build the agent (macOS auto-installs OBS binaries in build.rs)
cargo build

# 3. Run tests
cargo test
```

### libobs-rs Integration

The agent uses [libobs-rs](https://github.com/joshprk/libobs-rs) to embed OBS functionality. Key crates:

- `libobs` - Raw FFI bindings to libobs
- `libobs-wrapper` - Safe Rust wrapper
- `libobs-bootstrapper` - Verifies exact native bundle inputs used by supported build paths
- `cargo-obs-build` - Integrates the exact native bundle during supported builds

The fork at `libobs-rs/` includes macOS support from [PR #53](https://github.com/joshprk/libobs-rs/pull/53).

### Adding New Capture Sources

To add support for new capture types, implement them in `src/capture/sources.rs`:

```rust
pub fn new_window_capture(ctx: &ObsContext, window_name: &str) -> Result<ObsSourceRef> {
    // Use libobs-wrapper to create window capture source
}
```

## Releasing

### macOS

Provision the dedicated signing runner interactively once:

```bash
scripts/setup-macos-signing.sh \
  --p12 /path/to/developer-id.p12 \
  --identity "Developer ID Application: Your Name (TEAMID)" \
  --apple-id operator@example.com \
  --team-id TEAMID
```

Import the matching Sparkle signing key into the runner's Keychain, then use the
protected CI workflow. The workflow verifies the exact runner, toolchain, Apple
signing identity, notary profile, Sparkle public key, and native bundle before it
builds or publishes anything.

```bash
gh workflow run macos-release.yml --ref main -f channel=prod
```

Auto-updates are delivered via Sparkle using an appcast hosted on S3.

### Windows

Windows production release is fail-closed while the installer is migrated to
carry the exact OBS runtime closure under protected installation ACLs. The
release workflow cannot publish the former per-user loader plus first-launch
download design.

### Linux

Support coming soon...

## Backend Setup

The agent expects a Lambda endpoint that returns pre-signed S3 URLs. Example Lambda handler:

```python
import boto3
import json

s3 = boto3.client('s3')
BUCKET = 'your-bucket'

def handler(event, context):
    body = json.loads(event['body'])
    file_name = body['fileName']
    version = body['version']
    user_id = body['userId']
    
    key = f"uploads/{version}/{user_id}/{file_name}"
    
    content_type = (
        "application/msgpack" if file_name.endswith(".msgpack") else "video/mp4"
    )

    upload_url = s3.generate_presigned_url(
        'put_object',
        Params={'Bucket': BUCKET, 'Key': key, 'ContentType': content_type},
        ExpiresIn=3600
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'uploadUrl': upload_url,
            'key': key,
            'contentType': content_type,
        })
    }
```

## Utilities

Overlay keylogs on top of a screen capture:

```bash
python scripts/overlay_keylogs.py --video capture.mp4 --input input.msgpack --output capture_with_keys.mp4
```

To just generate subtitles (ASS):

```bash
python scripts/overlay_keylogs.py --input input.msgpack --ass-out keylogs.ass
```

## Contributing

Contributions welcome! Please open an issue first to discuss proposed changes.

## License

MIT License, see [LICENSE.md](LICENSE.md)
