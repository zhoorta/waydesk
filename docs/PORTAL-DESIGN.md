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

## Without the portal (the CLI alone stays complete)

**Decision (2026-11-17): the portal is optional.** `waydesk` (daemon, `waydesk-admin`, helper) is a complete product on its own; `waydesk-portal` is a separate package that depends on it and adds a front end. A person with one computer who only wants RDP installs `waydesk`, runs `waydesk-setup-admin`, and connects with any RDP client over a VPN or the LAN. Nothing in the daemon requires the portal, a database or a web server.

What the portal adds, and so what is missing without it: browser access (no client, no VPN), the per-person *My desktops* page, one place to assign people to servers, single sign-on and a combined audit view.

Rules that keep both ways working:

1. **Every portal action is also a `waydesk-admin` command.** The portal's `AdminReq` calls the same functions the CLI calls. A feature is not done until the CLI has it.
2. **One source of truth per host.** System accounts and the host's configuration hold users and assignments. The portal reads and writes the same data, so starting with the CLI and adding the portal later migrates nothing.
3. **Packaging:** `waydesk` alone, `waydesk-portal` optional, same version number.

Several servers without the portal, from least to most work:

1. **Declarative users file (first).** `/etc/waydesk/users.toml` lists this host's accounts (desktop, GPU, memory limit, groups). `waydesk-admin apply` reconciles the host to it and prints the diff (`--dry-run` first). Ansible, Salt or a git repo pushes one file per host, so "alice may use gpu-1" is a line in that host's file. Large organisations keep their own configuration management instead of a second control plane.
2. **Fleet monitoring (first).** `waydesk-admin status --json` gets a documented schema and an optional Prometheus-format endpoint, so Zabbix, Grafana or the StackCare hub can show all servers.
3. **Fan-out over SSH (if small teams ask).** `waydesk-admin --hosts web-1,web-2 users list` merges the output of the same command run on each host; names and tags come from `~/.config/waydesk/hosts`. No new daemon.
4. **Directory accounts (with the directory work).** With LDAP/sssd the accounts are the same on every host; each host only has `allowed_group`, so assigning a person means adding them to a directory group. The portal's directory sync is the same mechanism with a page on top.

## Three sizes, one design

The portal switches on only what the installation needs (mockup: `web/mockup/index.html`, size switcher at the bottom left).

- **Personal:** one computer, one person who is also the admin. Pages: My desktop, Computers, My account, Settings. Adding a computer shows a one-line install command with a single-use join code (the new host dials out; no inbound port).
- **Team (about 3 servers, 9 people):** adds Overview, Servers, Users, Sessions, Audit. Users have a *Servers* list; desktop, GPU and memory are set per server. *My desktops* shows one card per assigned server (running, not started, under maintenance, offline).
- **Organization (about 14 servers, 480 people):** adds Groups (one level, no nesting, optionally kept in step with a directory group), sign-in sources (single sign-on, directory sync, local accounts), roles (administrator, operator, auditor), pools (tags) and a placement rule, bulk actions, paging and a fleet overview. Audit can be forwarded to syslog.

Multi-server model (stage 2): the portal owns the users; assigning a person to a server creates a system account there with a password nobody sees; the portal reaches it through tickets; native RDP clients use an app password the portal issues. Servers enrol by dialling out with a single-use join code (1 hour). One running desktop per person per server; a person may run desktops on several servers at once. Open: whether OIDC/LDAP come in stage 2 or 3 (leaning: local accounts first, data model ready for both).

## Changes from the portal: the runner (decided 2026-11-17)

The root helper cannot make the changes itself: its unit runs under `ProtectSystem=full` and a small capability set (no write to `/etc`, no `CAP_FOWNER`), so `useradd`, `gpasswd` and `chpasswd` fail inside it. Loosening the sandbox of the process that checks passwords was rejected. Instead:

```
browser --POST /api/admin/do (Origin + CSRF + rate)--> portal --Redeem + Admin--> helper (sandboxed, root)
   helper: still an administrator? action in the closed list?  --one line of JSON--> /run/waydesk-admin.sock (0600, root)
   waydesk-admin@.service (socket activated, no sandbox): `waydesk-admin serve-request`
   runner: checks the list and the actor again, runs the matching `waydesk-admin` command line with a clean environment
           (SUDO_UID = the actor, WAYDESK_VIA=portal, WAYDESK_SOURCE = address) and prints one line of JSON
```

- **Closed list** (`src/adminaction.rs`): add user (RDP group only), enable, disable (with or without ending the session), new random password, set desktop and graphics, memory limit, end session. Not in it: removing an account, `sudo`/`wheel` and `waydesk-admins` membership (command line only). Names, desktops, graphics and sizes are checked against short rules; the command line is built from the action, never from what the browser sent.
- **Rules of the command line apply as for `sudo`:** nobody switches off their own access; the audit line (`admin.user.add`, ...) names the actor, says `via: portal` and the address. The new password is in the answer once and nowhere else (no log line, no cache, `no-store`).
- **Who may talk to the runner:** only root (the helper). A compromised helper can ask for these actions, not for arbitrary commands.
- Not yet: the same unit files for Arch and Fedora packages; a live test on a machine with systemd.

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
