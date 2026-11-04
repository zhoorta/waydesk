# 012: Arch support and other desktops (Plasma, COSMIC, Hyprland)

Date: 2026-10-30 (reverses the "not now" of 2026-10-24 in 011/PORTABILITY). Status: accepted.

## Problem
Arch/Omarchy was first judged a poor fit: a rolling release moves sway, wlroots and Qt under a private stack, and Omarchy owns the session. Later, a Hyprland backend and the demand of Omarchy users changed the cost.

## Decision
- Target generic Arch (not Omarchy-specific) with a PKGBUILD and a signed pacman repository (`waydesk.dev/arch`, x86_64 and aarch64).
- `waydesk-admin users set NAME --desktop cosmic|plasma|hyprland`. Plasma and COSMIC run as one fullscreen window inside the session's headless sway, since their own compositors cannot make a headless output; Waydesk bridges the clipboard and keyboard layout. Hyprland (0.55 and later, needs a GPU) is a compositor of its own, one per account.
- Users may bring their own sway or Hyprland configuration; `waydesk-admin config check NAME` says whether it will work.

## Why
The cheap probe on an x86 box showed the server builds on Arch, and the Hyprland backend measured well: on an i7-7700, Omarchy held 20 heavy users and the Waydesk desktop 21. Cost per idle session: about 940 MB with COSMIC, 750 MB with Plasma 6.8.

## Cost and risks
Rolling release breakage on upgrade; the other desktops are tested with an Intel GPU and not under load. Fedora is still not done.

## Evidence
`docs/ARCH.md`, `docs/HYPRLAND.md`, `docs/COSMIC.md`, `docs/PLASMA.md`, `docs/BRING-YOUR-OWN-CONFIG.md`, changelog 0.5.0.
