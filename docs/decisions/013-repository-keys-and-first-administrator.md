# 013: Own apt repository, the maintainer holds the key, every install creates an administrator

Date: 2026-10-22 (moved to waydesk.dev on 2026-10-24). Status: accepted.

## Problem
Users must install with one command and trust what they get; RDP logs in with PAM passwords, so a server without an account in `waydesk-users` is unusable.

## Decision
- A signed apt repository (now `waydesk.dev/apt`, and a pacman repository). José generates and holds the signing key; nothing in the automation touches it, and tests use throwaway keys. The key fingerprint is printed in the README for a manual check.
- No default account or password anywhere. Every install path creates an administrator: `waydesk-setup-admin` (server package), `waydesk-firstboot` (appliance image, which also makes the per-server RDP certificate).
- The "our distro" idea is a Debian 13 based appliance image with Waydesk preinstalled, not a new distribution (design only).

## Why
StackCare sells ready servers and wants one-step deployments while keeping control of the trust anchor.

## Cost and risks
The first download cannot be verified by the repository itself. Open: back up the key (two USB sticks and a revocation certificate), a trademark and package-name search, the appliance image build.

## Evidence
`docs/APPLIANCE.md`, `packaging/repo/`, README install section.
