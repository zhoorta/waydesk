# 007: Zero-copy capture, and the quantiser in the slice headers

Date: 2026-10-28. Status: accepted.

## Problem
With a GPU encoder the picture still crossed the CPU twice (capture copy and colour conversion). Separately, a first rate controller sent new parameter sets at each quantiser change, and the Windows App on a Mac then showed the whole screen washed out until the next keyframe (the "veil").

## Decision
- Capture into GPU buffers (dmabuf) and convert BGRA to NV12 on the GPU's video processor. `WAYDESK_DMABUF=0` goes back to shared memory.
- Change the quantiser by writing it into the slice headers of the next picture, with no new parameter sets and no keyframe.

## Why
The full-screen animation went from about 21 % of a core to 2 to 3 %. The veil bug was found and fixed before release by comparing what the Windows App showed with the stream.

## Cost and risks
NVIDIA's GBM linear buffer is refused today, so zero-copy from NVIDIA may never be possible. DMA-BUF is only worth offering when a GPU encoder will use it: reading a GPU buffer back on the CPU is far slower than shared memory.

## Evidence
`docs/GPU-PLAN.md`, changelog 0.4.0, commit 2082cd5.
