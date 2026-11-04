# 002: Root helper, unprivileged daemon, session as the user

Date: 2026-10-16 (design). Status: accepted.

## Problem
The daemon parses untrusted network input and, in the first version, also held the login logic. A non-root process can only check its own password with PAM.

## Decision
Three parts:
- `waydeskd` runs as the `waydesk` user with no login. It does TLS and the RDP protocol and sends credentials to the helper.
- `waydesk-helper` runs as root, has no network, and only checks a password through PAM and starts or finds a session. It takes no program, path or arguments from the daemon. They talk over a Unix socket whose peer credentials are checked.
- `waydesk-session` runs as the real user, in its own logind session.
The daemon and the helper are one binary; the helper unit is sandboxed with a system call filter and resource limits.

## Why
A bug in the RDP parser lands in an account with no privileges. The root part is small enough to review, which is where an outside reviewer is told to start (`src/helper.rs`, `src/auth.rs`, `src/link.rs`, `src/proto.rs` and the unit files).

## Cost and risks
Passwords are not wiped from memory, and the helper trusts the daemon's claim of the client's address, so a compromised daemon can poison the per-address lockout counters (the per-account counter holds). Listed in `docs/THREAT-MODEL.md`. Four internal security passes found and fixed issues; no independent review has been done.

## Evidence
`docs/MULTIUSER-DESIGN.md` (sections 3 and 4), `docs/SECURITY-REVIEW.md`, `docs/THREAT-MODEL.md`.
