# Portal: design, stage 1 (one host, direct access from the browser)

Status: draft, rewritten 2026-11-09. Open edition (AGPL). The portal **is** the web gateway (`web/`, merged from `web-gateway`) grown into a site; there is no separate product.

## Goal

A person opens `https://desktops.example.org`, signs in and gets their desktop in the browser, **with no VPN and no RDP client**. Only port 443 is public; the RDP port stays closed to the internet. Administrators manage the host from the same site. Native RDP clients keep working for whoever is on a VPN or the LAN; the portal can offer a `.rdp` file as an extra for them, not as the way in.

Stage 1 manages the host it runs on. Stages 2 and 3 are at the end; nothing here should make them harder.

## Why a Rust binary

A sysadmin installs it with `apt install waydesk-portal`, edits one file and starts one unit. `axum`, server-rendered templates (askama), htmx, SQLite, with the scripts, styles and client compiled into the binary. No PHP, web server, database server or build step to keep patched. It shares code with the daemon (`allow.rs`, `gateway.rs`, the audit line format) and already has TOTP (`web/src/totp.rs`) and the limits (`web/src/limits.rs`).

## Which protocol reaches the browser

**Decision (José, 2026-11-09): a thin stream first, RDP in the browser as the fallback.**

- The daemon's `src/proto.rs` already carries what a browser needs: H.264 frames, key and pointer input (evdev codes), resize, clipboard, audio, cursors, flow-control credits. RDP is only one front end for it.
- A new front end `serve_web` in the daemon speaks WebSocket (binary messages) after the gateway preamble; the browser client is WebCodecs + canvas, a few hundred lines of JS, and drops the 5.8 MB IronRDP bundle and the 46 third-party patches (IronRDP's browser client has no H.264 upstream: #1977, #2347).
- The portal does not care which protocol runs behind it: it authenticates, then bridges one WebSocket to the daemon's gateway port. The bridge is the swap point. If the thin stream does not measure up (packet loss and delay with netem, against the IronRDP prototype on `web-gateway`), the IronRDP bundle goes into the same portal.
- Risks: a second front end to test and keep in step with RDP; browser input goes straight into the daemon, so sizes and rates are validated (reuse `check_frame`) and the session is bound to the account the portal asserted.
- WebTransport only as a later optional upgrade; WebRTC rejected (no reverse proxy, ICE is wasted client to server).

## Pages

People (every account in the login group):
1. **Sign in:** account, password, TOTP code. One form, the same refusal text for every failure.
2. **My desktop:** state (running or not, since when, desktop, GPU) and buttons: *Open* (the desktop in this tab or a new one, fullscreen, ctrl+alt+del, clipboard), *End my session*. For VPN users, an optional *Download .rdp file*.
3. **My account:** change password, enrol or remove TOTP, show recovery codes once.

Administrators (members of the admin group):
4. **Overview:** host health (memory, swap, GPU roles and load, sessions against capacity), the numbers of `waydesk-admin status`.
5. **Users:** list, add, enable or disable, set desktop and GPU, limits, reset password (shown once). Same actions and checks as `waydesk-admin users`.
6. **Sessions:** list, end one; who is connected from which address.
7. **Settings:** access mode and allowlist, certificate status, TOTP policy (off, optional, required). Changes that could lock the admin out ask for confirmation and show the command that undoes them.
8. **Audit:** the audit log, searchable by account, address and kind, with export. Read only.

## How it is built

```
browser --HTTPS/WSS--> waydesk-portal (user waydesk-portal, no privileges)
                          |-- sign-in: PAM through the root helper (same lockout as RDP) + TOTP
                          |-- desktop: WebSocket bridged to the daemon's gateway port (account and real IP asserted)
                          '-- admin pages: admin requests to the root helper over its Unix socket
```

- **Sign-in** goes through the helper's `Authenticate`, so the per-account and per-address lockout is shared with RDP and cannot be bypassed from the web. The password reaches the portal over HTTPS and is passed on, not stored or logged. On the same helper connection the portal asks for a **ticket** (256 bit, bound to the account and the client address, up to 8 hours, revoked at sign-out) and keeps only that: the browser stream's daemon connection redeems it (`Redeem`, which also re-checks that the account may still log in), so the password is typed once and nothing keeps it after the sign-in check. The ticket never reaches the browser.
- **Admin check:** membership of the admin group (default `waydesk-admins`), looked up through NSS on every request, never cached in the cookie. Works with LDAP and sssd later.
- **Admin actions:** `waydesk-admin` needs root; the portal must not have it. The root helper gets a narrow `AdminReq` set (list, add, enable, disable, set, limit, end session, status): the same functions `waydesk-admin` calls, no shell, no free-form arguments, accepted only on a socket the portal's user can reach. **Decision: the helper re-checks the admin.** The portal passes the signed-in admin's name and the helper checks the group itself, so a compromised portal can only act as an admin who is signed in (it cannot invent one).
- **Web sessions:** cookie `__Host-` prefixed, `HttpOnly`, `Secure`, `SameSite=Strict`; idle 30 min, absolute 8 h; CSRF token on every form (header on htmx requests); strict Content-Security-Policy, no inline script; HSTS on the HTTPS listener.
- **Database:** SQLite (`/var/lib/waydesk-portal/portal.db`) holding only portal sessions, TOTP secrets and portal settings. Users and sessions stay where they are (system accounts, `waydesk-admin`); nothing is copied that can drift.
- **Listening:** loopback by default; reverse-proxy mode (trusted proxy list, forwarded address, public origin) exactly as the gateway has it today; direct HTTPS with the daemon's certificate or a certificate for the portal's name. The allowlist applies before TLS. Per-address and total limits on sign-ins and sessions stay.

## What it does not do in stage 1

No other hosts, no SSO or LDAP login, no per-group policy, no session recording, no email. No password for the portal itself: every credential is a system account.

## Tests

- Unit: cookie and CSRF handling, admin-group check, every `AdminReq` validated (names, sizes), template output escaped, `serve_web` frame and input validation.
- Mutation-style: remove the CSRF check, the admin check, the idle limit or the account binding and a test must fail.
- VM: sign in as a user and as an admin; open and end a session; add and disable an account; a wrong password counts against the lockout shared with RDP; a non-admin gets 403 on every admin path; a stream bound to account A cannot reach B.
- Measurement: thin stream against IronRDP in the browser under netem loss and delay, and on a poor mobile link (José's: ~110 ms, 0.6 Mbit/s up).
- Security pass before release, like the earlier ones.

## Order of work

1. **Done 2026-11-09:** gateway work committed (`web-gateway` f296e1f) and merged into `open-enterprise` (975ae60): token bridge, TOTP, limits, reverse-proxy mode, daemon gateway port.
2. Portal skeleton from `web/`: sign-in through the helper plus TOTP, cookies and CSRF, *My desktop* page, WebSocket bridge to the daemon gateway port (still with the IronRDP page behind *Open* until step 3 exists).
3. `serve_web` in the daemon and the browser client (video, input, resize, then clipboard, audio, cursors); measure against IronRDP; decide.
4. Helper `AdminReq`, read-only first (overview, users, sessions), then writes.
5. Settings, audit view, packaging (`.deb`, unit, `waydesk-admin portal enable|status`, docs).

## Later

- **Stage 2, several hosts:** each host dials out to the portal with a single-use join token that carries the portal's certificate fingerprint; entitlements per user or group; audit events from all hosts; the list shows hosts with state. Data model to copy from ghost's Veil: devices, entitlements, join tokens, placements.
- **Stage 3, only on demand:** SSO and OIDC, LDAP, per-group switches, session recording.
- A StackCare hub integration: the Laravel hub lists portal hosts as another kind of server through a small API. Nothing here depends on it.
