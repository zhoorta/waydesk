# 011: Own session stack, per-distribution builds, Flatpak apps

Date: 2026-10-23. Status: accepted; the Fedora and Arch parts are changed by 012.

## Problem
Ubuntu 26.04 has stock sway, no quickshell and no Chromium deb. Qt, wlroots and sway versions differ per distribution, and the title-bar patch has to run everywhere.

## Decision
1. Ship the patched sway, quickshell, shell and helpers as Waydesk's own packages (for example `waydesk-sway`, `waydesk-quickshell`), and always start those.
2. Build per distribution in a container from the same recipes; Debian and Ubuntu share the packaging.
3. Take apps from Flatpak where possible (Chromium from Flathub gives one browser everywhere).
4. Fedora last, when there is demand (an rpm repository, SELinux policy for the helper, firewalld).

## Why
It removes version pins and races with the distribution. Result: Debian 13 and Ubuntu 26.04 LTS pass clean installs from the published repository on x86 and arm64.

## Cost and risks
We follow sway and quickshell upstream ourselves. There is no rpm yet. Flatpak Chromium costs more memory than the Debian deb (measured earlier at 270 MB per Chromium user for the deb).

## Evidence
`docs/PORTABILITY.md`.
