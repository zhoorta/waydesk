# 014: AGPL-3.0-or-later

Date: 2026-11-01 (release 0.5.0). Status: accepted.

## Problem
Waydesk was MIT/Apache-2.0 until 0.5.0 and the changelog does not record why it changed.

## Decision
License under the AGPL, version 3 or later. Third-party code in the repository keeps its own licences (the IronRDP patches, `cros-codecs`, and others). The three copyleft programs shipped as binaries (matugen, quickshell, a patched pcmanfm-qt) have their source published at `waydesk.dev/apt/source/`.

## Why
The AGPL requires source for modified versions offered over a network, while charging for installing, hosting and supporting stays allowed, which fits StackCare's model. All 411 Rust crates the server builds on are permissive, so they can be included.

## Cost and risks
Some companies avoid AGPL software; for them the README points to StackCare for another licence.

## Evidence
`LICENSE`, `CHANGELOG.md` (0.5.0), README "Names and licence".
