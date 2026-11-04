# 003: RDP through IronRDP, with a patched copy in the repository

Date: reconstructed (2026-10). Status: accepted.

## Problem
The product must work with the clients people already have (Windows App, mstsc, Remmina, FreeRDP) and speak H.264, audio and clipboard. Writing an RDP server from scratch was out of the question. A rival Rust RDP server (rcarmo/wrdp) was tried on 2026-10-19 and dropped as too immature.

## Decision
Build on IronRDP (Devolutions) and keep a patched copy of `ironrdp-server` in `patches/ironrdp-server` (a diff and the modified copy, with the MIT/Apache files kept).

## Why
Patches were needed for things the library does not offer, for example telling a refused client why (a Set Error Info PDU with a refusal reason, so the user sees "out of memory" or "denied" instead of a dropped connection), and the pointer work for the Windows App. Vendoring keeps the build reproducible.

## Cost and risks
We follow upstream by hand. A stalled-client problem is open upstream as IronRDP issue #2224 and the local fix is not published. Pointer shapes needed an AND mask for the Windows App; the finding is in the changelog and could help other IronRDP users.

## Evidence
`patches/ironrdp-server.diff`, commit 7c0f9da (refusals), memory notes on the stall fix.
