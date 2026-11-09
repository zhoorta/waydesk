# waydesk: audit log (design draft, 2026-10-29)

Status: built (2026-10-29), not released; the differences from the first draft are in section 11. First item of "Access control and auditing" in the roadmap. Written from reading `helper.rs`,
`auth.rs`, `main.rs` and `waydesk-admin.rs`; the file locations in section 5 have to be checked against the packaging
before building.

## 0. Decisions (2026-10-29)

- Client `connection` events are in the audit file (`origin: daemon`).
- A user name that is not a valid account name is logged as its length only, with `user_invalid: true`.
- Default retention 26 weeks, set in the logrotate file.
- Admin actions from the panel are attributed through `PKEXEC_UID` (see section 4).

## 1. Goal and non-goals

Goal: an answer, afterwards and without guessing, to "who logged in, from where, when, what did they and the
administrators change, and what was refused". Machine readable, forwardable to a central syslog, and small enough for
one person to review.

Non-goals: recording what users do inside a session (that is session recording, "later"), a tamper-proof log on the
same machine (root can edit any local file; the protection is forwarding off the machine, section 6), a web viewer.

## 2. What exists today

Useful facts are already logged with `tracing` to the journal, mixed with debug and operational lines:

- `auth.rs`: `login accepted (PAM)`, `login rejected (PAM)`, lockouts, `many failed logins of one account`.
- `helper.rs`: `session registered`, `session ended`, `reconnecting to the running session`, `session unit started`,
  `session refused` (memory, user limit).
- `main.rs`: `client connected`, `client disconnected` (with duration), refusals by `WAYDESK_ALLOW_FROM`.
- `waydesk-admin`: logs nothing about what it changes (users add/remove/passwd/disable/sudo/limit, groups).

Problems: no stable event names or fields, the free text changes with every edit, admin actions are not recorded at
all, and the daemon (unprivileged, parses network input) is the author of some lines, so a bug there could forge them.

## 3. Principles

1. **Separate stream.** Audit events do not go through `tracing`. A small `audit` module writes them, so a change to a
   debug message can never change the audit record.
2. **The root helper is the authority.** Login results, session start/end and refusals are decided in the helper, so it
   writes them. The daemon cannot write to the audit file. Facts only the daemon knows (client connect/disconnect,
   source-address refusals) reach the helper as a bounded `HelperReq::Event{kind, peer}` and are marked
   `"origin":"daemon"`.
3. **Never log secrets.** No passwords, no tokens, no clipboard or file contents. A user name typed into the wrong
   field is often a password: the name is cut to 64 characters, control characters are escaped, and a name that is not
   a valid account name is logged as `"user":null,"user_invalid":true` plus its length, not its text.
4. **One line, one event, JSON.** Newlines in any field are escaped, so a hostile user name cannot fake a second event.
5. **Stable names.** Event names and field names are documented here and in REFERENCE.md and change only with a major
   version.

## 4. Events

Fields common to all: `ts` (UTC, RFC 3339, milliseconds), `seq` (counter since the helper started; a gap shows a
lost line), `host`, `version`, `event`, `outcome` (`ok`, `fail`, `refused`), `origin` (`helper` or `daemon`).

| Event | Extra fields | When |
|---|---|---|
| `login` | `user`, `uid`, `source`, `reason` on failure: `bad_password`, `unknown_user`, `not_in_group`, `account_locked`, `account_expired`, `rate_limited` | every PAM authentication |
| `login.lockout` | `key` (user or address), `seconds` | a rate limit starts |
| `login.guessing` | `user`, `failures`, `window_min` | the existing "many failed logins from any address" watch |
| `session.start` | `user`, `uid`, `session` (unit), `source`, `size`, `gpu` | new session process |
| `session.reconnect` | `user`, `uid`, `session`, `source` | existing session taken over |
| `session.end` | `user`, `uid`, `session`, `seconds`, `reason`: `logout`, `disconnected_timeout`, `killed_by_admin`, `crashed`, `memory` | session unregisters |
| `session.refused` | `user`, `reason`: `memory`, `users_limit` | `Refused` answers |
| `connection` | `source`, `outcome`, `reason`: `not_allowed`, `too_many` ; on success also `seconds` at disconnect | daemon origin |
| `admin.user.add/remove/disable/enable/passwd/sudo` | `actor`, `actor_uid`, `target`, `via` (`cli` or `panel`) | `waydesk-admin` commands; passwd records that it changed, never the value |
| `admin.user.limit` | as above plus `limits` (`memory=2G`) | `users limit` |
| `admin.group` | `actor`, `target`, `group`, `change` (`add`/`remove`) | group membership changes |
| `admin.access` / `admin.cert` / `admin.vpn` | `actor`, `actor_uid`, `action` (`lan`, `local-ca`, `add`...), `target` where there is one (a VPN client name) | the shell scripts in `packaging/admin`; they log through `waydesk-admin audit-event` (below), never by writing the file themselves |
| `admin.session.end` | `actor`, `target` | administrator ends someone's session |
| `admin.config` | `actor`, `setting`, `old`, `new` | policy changes (`status` settings, GPU, user limit) |
| `audit.start` / `audit.stop` | `reason` | helper start/stop, log reopened |

The actor of an admin action is the caller that `waydesk-admin` already identifies (`caller_uid()`: `PKEXEC_UID` or
`SUDO_UID`). The Users & Access panel runs `pkexec /usr/bin/waydesk-admin ...` (polkit action `org.waydesk.admin`,
`users-panel/shell.qml`), so `PKEXEC_UID` is the administrator at the panel and `via` is `panel`; with `SUDO_UID`,
`via` is `sudo`. With neither (a root shell, `waydesk-setup-admin`, the package scripts) the actor is
`root` and `via` is `root`. The scripts `access`, `cert` and `vpn` run under the same process, so they inherit those
variables and call a hidden `waydesk-admin audit-event` subcommand that validates the event name against the closed
list and writes it; shell never builds JSON.

Later additions already fit the same shape: `clipboard.blocked`, `file.transfer`, `session.idle_limit` (roadmap items
that follow this one).

## 5. Storage and format

Example line (wrapped here, one line in the file):

```
{"ts":"2026-10-29T14:03:11.482Z","seq":412,"host":"srv1","version":"0.4.0","origin":"helper","event":"login",
 "outcome":"fail","reason":"bad_password","user":"ana","source":"10.0.0.23"}
```

- **File:** `/var/log/waydesk/audit.log`, opened `O_APPEND|O_CLOEXEC|O_NOFOLLOW` by the helper, mode 0640, owner root,
  group `adm`. The directory is 0750 root. Not readable by the `waydesk` daemon account.
- **Syslog:** every event is also sent to `/dev/log` with identifier `waydesk-audit`, facility `authpriv`, the JSON as
  the message. That reaches journald and rsyslog, so forwarding to a central server is the system's existing job
  (rsyslog `omfwd`, `systemd-journal-upload`). The helper (root, no network) does **not** get a network client for
  this: a syslog-over-TCP client with TLS and retries is a lot of code in the most privileged process.
- **Rotation:** package ships `/etc/logrotate.d/waydesk` (weekly, keep 26, compress). The helper reopens the file on
  `SIGHUP` (`postrotate`) and also when its inode changes.
- **Retention and privacy:** IP addresses and account names are personal data under the GDPR. Default 26 weeks,
  documented in REFERENCE.md with the reason; shorter is the administrator's choice in the logrotate file.
- **If the file cannot be written** (disk full, permissions): log a `warn` to the journal and carry on, because
  locking everyone out of a server over a full disk is worse for most users. A switch `audit_required = true` in the
  helper configuration makes authentication fail closed instead, for sites where an unlogged login is not acceptable.

## 6. Tamper evidence (what it does and does not give)

A local file written by root proves nothing against root. Two cheap measures, no more:

- `seq` gaps and `audit.start`/`audit.stop` markers show deleted lines or a stopped helper.
- Forwarding to another machine is the real control; REFERENCE.md says so and shows an rsyslog forwarding example.

A hash chain (each line carries the hash of the previous) is easy to add later if someone asks; it adds nothing
without off-machine anchoring, so it is not in the first version.

## 7. Reading it

`waydesk-admin audit [--since 1d] [--user NAME] [--event login] [--outcome fail] [--json]`: reads the current and the
rotated files, filters, prints a table (or the raw lines with `--json`). Read-only; allowed for members of the
administrator group like `status`. A tab in the Users & Access panel comes after that and is not part of the first
version.

## 8. Code changes

- New `src/audit.rs` (about 250 lines): `Event` builder, JSON escaping, file + syslog sinks, reopen on `SIGHUP`,
  `seq`. No dependencies beyond what is vendored (`serde_json` only if already present; otherwise hand-written
  escaping, it is a dozen fields of strings and numbers).
- `proto.rs`: `HelperReq::Event { kind: u8, peer: String }` with a closed list of kinds and a length limit on `peer`;
  the helper validates it as an IP and stamps `origin: daemon`.
- `auth.rs` and `helper.rs`: emit events at the places listed in section 2, next to the existing `tracing` lines
  (those stay, for debugging).
- `waydesk-admin.rs`: emit `admin.*` events after the action succeeds, and `outcome: fail` with the error class if it
  fails. It runs as root already, so it opens the file itself (same append rules).
- `packaging/`: directory, logrotate file, `postrotate` signal, upgrade keeps the file.

## 9. Tests

- Unit: escaping (newline, quote, control, invalid UTF-8, 10 kB name), field limits, stable output for a fixed
  event (golden line).
- VM: wrong password, right password, lockout, reconnect, memory refusal, `users add/passwd/remove`, rotation with
  `SIGHUP`, helper killed and restarted (`seq` restarts, `audit.start` marks it), daemon account cannot read or
  write the file.
- Security: the daemon cannot make the helper write an arbitrary line; fuzz `HelperReq::Event` decoding next to the
  existing `proto` tests.

## 10. Open questions

1. `seq` restarting at 0 on every helper start: acceptable with the `audit.start` marker, or persist a boot-wide
   counter? (Leaning: marker only.)
2. Log the password-field-as-username case at all? Proposed above as length only; the alternative is to drop those
   attempts from the audit file and keep them in the journal.
3. Should `connection` (client connect/disconnect) be in the audit file or only `login` and `session.*`? It is noisy
   on a server scanned from the internet, but the allow list normally keeps that out. Leaning: include, under
   `origin: daemon`.
4. (Settled) Panel actions go through `pkexec`, so the actor is `PKEXEC_UID`, the administrator who typed the
   password in the polkit dialog. Remaining gap: a `su -` root shell has no caller, so it is logged as `root`.
5. Does the 0.4.0 arm64 build change anything for `/dev/log` or logrotate? No expected difference; confirm on the
   Ubuntu 26.04 machine.

## 11. As built (differences from the draft above)

- **No `HelperReq::Event`.** Every daemon connection already holds one helper connection from accept to disconnect, so the helper writes `connection.end`
  itself when that connection closes (with the user, the source from the login, and the seconds since the login). The daemon cannot forge it, and the
  protocol did not change. Connections that never log in and addresses refused by `WAYDESK_ALLOW_FROM` are **not** in the audit file, only in the journal: writing
  them would let an unauthenticated scanner drive writes in the root helper. This narrows decision 1 of section 0 (connection events) to logged-in clients.
- **No `audit-event` subcommand.** `waydesk-admin` runs the `access`, `cert` and `vpn` scripts itself and writes their lines from Rust after the script ends.
- **`via` is `pkexec`, `sudo` or `root`**, not `panel`: the panel and a terminal `pkexec` look the same to the program.
- **`admin.config`, `audit.stop` and `session.end` reasons** are not built. `session.end` has `seconds` only.
- **`seq`** is only on the helper's lines; `waydesk-admin` is short-lived and its lines are not numbered.
- **A lockout is logged once** (`login.lockout`, then one `login` with `reason: rate_limited`), not once per refused attempt, so a flood cannot fill the disk.
  Failed logins that reach PAM are bounded by the 2 s delay and the connection limit (at most about 30 lines a second); the logrotate file also has `maxsize 200M`.
- **Tested** in an arm64 Debian container (unit tests; the real helper with PAM and a client speaking the helper protocol: success, wrong password, not in
  the group, unknown user, a password typed as a name, a bad source address, lockout, rotation with `SIGHUP`, `--audit-required` with an unwritable log; the
  admin commands as root through `sudo`/`pkexec` variables). **Not tested yet:** the `session.*` events (they need a systemd machine with sway: the test server),
  the packaged `LogsDirectory=` and logrotate files, and `systemd-journal-upload`/rsyslog forwarding.
