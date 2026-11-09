# Portal: design, stage 1 (one host)

Status: draft, 2026-11-09. Nothing built. Open edition (AGPL), like the web gateway it grows out of.

## What it is

One web site, served by one small Rust binary (`waydesk-portal`), where
- **people** sign in and open their desktop, and
- **administrators** see and manage the accounts, sessions and settings of the host.

Stage 1 manages the host it runs on. Stages 2 and 3 are listed at the end; nothing in stage 1 should make them harder.

## Why a Rust binary

A sysadmin should install it with `apt install waydesk-portal`, edit one file and start one unit. So: `axum`, server-rendered templates (askama), htmx, SQLite, and the scripts, styles and htmx compiled into the binary. No PHP, web server, database server, queue or build step to keep patched. It shares code with the daemon and the web gateway (`allow.rs`, `gateway.rs`, the audit line format).

## Pages

People (every account in the login group):
1. **Sign in:** account, password, TOTP code. One form, the same refusal text for every failure.
2. **My desktop:** state (running or not, since when, desktop, GPU), buttons: *Open in the browser* (the web gateway), *Download .rdp file* (host, address, resolution), *End my session*.
3. **My account:** change password, enrol or remove TOTP, show recovery codes once.

Administrators (members of the admin group):
4. **Overview:** host health (memory, swap, GPU roles and load, sessions against capacity), the same numbers as `waydesk-admin status`.
5. **Users:** list, add, enable or disable, set desktop and GPU, limits, reset password (shown once). Same actions and checks as `waydesk-admin users`.
6. **Sessions:** list, end one. Who is connected from which address.
7. **Settings:** access mode (local, LAN, VPN, custom) and allowlist, certificate status, TOTP policy (off, optional, required). Changes that could lock the admin out ask for confirmation and show the command that undoes them.
8. **Audit:** the audit log, searchable by account, address and kind, with export. Read only. (Present only where the audit log exists.)

## How it is built

```
browser --HTTPS--> waydesk-portal (user waydesk-portal, no privileges)
                      |-- sign-in: PAM through the existing helper (same lockout as RDP)
                      |-- user pages: daemon gateway port + web gateway (open in browser)
                      '-- admin pages: admin requests to the root helper over its Unix socket
```

- **Sign-in** goes through the helper's `Authenticate`, so the per-account and per-address lockout is shared with RDP and cannot be bypassed from the web. TOTP uses the code already written for the web gateway (`totp.rs`).
- **Admin check:** membership of the admin group (default `waydesk-admins`), looked up through NSS on every request, never cached in the cookie. Works with LDAP and sssd later.
- **Admin actions:** `waydesk-admin` needs root, the portal must not have it. The root helper gets a narrow `AdminReq` set (list, add, enable, disable, set, limit, end session, status), the same functions `waydesk-admin` calls, with no shell and no free-form arguments. The helper accepts it only on a socket the portal's user can reach. *Decision needed:* does the helper re-check the admin's identity, or trust the portal's word (as it trusts the daemon for the source address, THREAT-MODEL)? Recommendation: the portal passes the session's signed admin name and the helper checks the group itself, so a compromised portal can only act as an admin who is signed in.
- **Sessions on the web:** cookie `__Host-` prefixed, `HttpOnly`, `Secure`, `SameSite=Strict`; idle 30 min, absolute 8 h; CSRF token on every form (header on htmx requests); a strict Content-Security-Policy, no inline script; HSTS on the HTTPS listener.
- **Database:** SQLite (`/var/lib/waydesk-portal/portal.db`), holding only portal sessions, TOTP secrets (or a pointer to the web gateway's directory) and portal settings. Users and sessions stay where they are: the system's accounts and `waydesk-admin`. Nothing is copied that can drift.
- **Listening:** loopback by default, like everything else here; reverse-proxy mode (trusted proxy list, forwarded address) as the web gateway has it. The allowlist applies before TLS.

## What it does not do in stage 1

No other hosts, no SSO or LDAP login, no per-group policy, no session recording, no email. No password for the portal itself: every credential is a system account.

## Tests

- Unit: cookie and CSRF handling, admin-group check, every `AdminReq` validated (names, sizes), the template output escaped.
- Mutation-style: remove the CSRF check, the admin check or the idle limit and a test must fail.
- VM: sign in as a user and as an admin, open and end a session, add and disable an account, a wrong password counts against the lockout shared with RDP, a non-admin gets 403 on every admin path.
- Security pass before release, like the four earlier ones.

## Order of work

1. Skeleton: listener, sign-in with PAM and TOTP, session cookie, *My desktop* with *Download .rdp*. (Usable by people alone.)
2. Helper `AdminReq` for read-only calls: overview, users, sessions.
3. Admin writes: add, enable or disable, set, limit, end session.
4. Settings, then audit view (enterprise branch only until the audit log is open).
5. Packaging: `.deb`, unit, `waydesk-admin portal enable|status`, docs.

## Later

- **Stage 2, several hosts:** each host dials out to the portal with a single-use join token that carries the portal's certificate fingerprint; entitlements per user or group; audit events collected from all hosts; the portal list shows hosts with state. The data model is the part to copy from ghost's Veil: devices, entitlements (user or group, name), join tokens, placements.
- **Stage 3, only on demand:** SSO and OIDC, LDAP, per-group switches, session recording.
- A StackCare hub integration: the Laravel hub lists portal hosts as another kind of server through a small API. Nothing here depends on it.
