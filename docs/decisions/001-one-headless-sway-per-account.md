# 001: One headless sway per account, not one shared compositor

Date: 2026-10-16 (design), built in milestones 1 to 6. Status: accepted.

## Problem
The first server (one user, one client at a time) put every session on one shared sway as separate outputs. That means one uid, one Wayland socket and one clipboard: any user could capture or type into another user's session.

## Decision
Every account gets its own headless sway (`WLR_BACKENDS=headless`), started as that user in its own logind session, with its own `XDG_RUNTIME_DIR` (0700). The session survives disconnects, and a reconnect returns to the same windows.

## Why
Isolation comes from the operating system (uids, runtime directories), not from our code policing a shared compositor. Memory, task and CPU ceilings can then be set per account through systemd slices (see 008).

## Cost and risks
Every session carries its own compositor and shell: about 400 MB of RAM for an extra session in the early measurements, and the shell was the largest part (see 015). That is why density work, memory protection and the lean shell patches exist.

## Evidence
`docs/MULTIUSER-DESIGN.md` (sections 1 to 3), `docs/MEASUREMENTS.md`.
