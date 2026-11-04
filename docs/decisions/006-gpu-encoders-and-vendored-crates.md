# 006: Hardware encoders through cros-codecs (VAAPI) and NVENC, with vendored patches

Date: 2026-10-27 to 2026-10-28. Status: accepted.

## Problem
Encoding is the biggest CPU cost of a session. Intel and AMD offer VAAPI; NVIDIA offers NVENC.

## Decision
- An `Encoder` trait with OpenH264, a VAAPI backend (`cros-codecs`, BSD-3, from ChromiumOS) and an NVENC backend, chosen at run time. `WAYDESK_ENCODER=auto` tries VAAPI, then NVENC, then software.
- `cros-codecs`, `cros-libva` and `nvidia-video-codec-sdk` are vendored in `patches/` with small diffs.
- A rate controller of our own picks the quantiser from what the client's link carries.

## Why
Reusing a maintained encoder crate was cheaper than writing the bitstream code. The patches fix what real drivers did, for example the quantiser in the slice headers (see 007) and an output buffer sized for a full raw picture (a 1.8 MB keyframe of full-screen noise did not fit the fixed 1.5 MB and ended the connection).

## Cost and risks
Three vendored crates to keep in step. A GPU encoder that cannot start falls back to OpenH264 on the CPU. Another project reached the same radeonsi packed-header problem independently and vendored `cros-libva` too, which suggests the approach is sound.

## Evidence
`patches/cros-codecs.diff`, `patches/cros-libva.diff`, `patches/nvidia-video-codec-sdk.diff`, commits 4c295b1 and 53e3607.
