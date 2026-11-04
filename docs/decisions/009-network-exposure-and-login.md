# 009: Loopback by default, plain TLS login, lockout per account and address

Date: 2026-10-20 (lockout), 2026-10-25 (access tooling). Status: accepted, with open items.

## Problem
RDP exposed to the internet is attacked constantly, and the login is a Linux password, not an RDP-specific credential.

## Decision
- The port listens on `127.0.0.1:3389`. People reach it through an SSH tunnel or WireGuard; `waydesk-admin vpn`, `cert` and `access` set up a VPN, a local certificate authority and an address allowlist.
- Plain TLS login, with PAM checking the password in the helper. A login group (`waydesk-users`) is required.
- Lockout counts failures per (account, address), with delays doubling from 60 s to 1 h, answered identically for unknown and known accounts. This replaced a global lockout that let a stranger lock everyone out.
- No default account and no default password.

## Why
A tunnel or VPN removes the attack surface that matters most, and per-account counters stop a stranger from locking the owner out.

## Cost and risks
Open: no second factor, distributed guessing is logged but not stopped (`pam_faillock` can, at the cost of lockout by strangers), the helper trusts the daemon's address, no NLA, Chromium from Flathub uses `--password-store=basic`, no fuzzing and no independent review. Two-factor login (TOTP) and LDAP/AD are planned.

## Evidence
`docs/THREAT-MODEL.md`, `docs/SECURITY-REVIEW.md`, `docs/ACCESS.md`, `docs/WIREGUARD.md`.
