# 015: Reuse an existing shell; Chromium as the default browser

Date: 2026-10-16 (shell), 2026-10-26 (browser). Status: accepted.

## Problem
A Windows-like desktop needs a bar, launcher, notifications and a file manager. Writing a shell was the old (dropped) hobby-OS plan.

## Decision
Use DankMaterialShell on quickshell (pinned: DMS 2.0), patched per file where needed (kill-process, "pin to desktop", lean mode that drops the desktop widget layer and clipboard history window, saving 19 MB per session). The file manager is a rebuilt pcmanfm-qt with the desktop-only menu entries removed. Chromium is the default browser, pinned first in the dock: the Debian deb where it exists, otherwise Flathub (Ubuntu's Chromium package is a snap stub).

## Why
No custom shell or apps to maintain. The shell's memory floor was measured: 283 of 360 MB is the renderer, so further trimming has little left to give.

## Cost and risks
Patches break when the shell updates (DMS moved files between 1.6 and 2.0), so they apply per file and an unmatched one is skipped. The shell is still unpinned upstream in places.

## Evidence
Commits 24a549f, 726439b, 74f0e42; `docs/DMS-PACKAGE.md`.
