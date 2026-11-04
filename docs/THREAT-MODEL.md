# Threat model and open items

Who we assume is hostile, what each part can and cannot do, and what is known to be missing. The four internal review passes are in
[`SECURITY-REVIEW.md`](SECURITY-REVIEW.md). How the port is reached (and who may connect) is in [`ACCESS.md`](ACCESS.md).

## Threat model

- **Attacker on the network:** sees only TLS. Can guess passwords; failures are counted per account and per address, delayed, and answered identically for unknown and known accounts.
- **Compromised daemon:** runs as an unprivileged user with a system call filter and a narrow capability set. It can read the streams of live sessions and type into them, and sees passwords in transit. It cannot start a session for an account that did not authenticate on the same connection, and the helper takes no program, path or arguments from it.
- **Malicious account:** has its own sway, its own runtime directory (0700) and its own clipboard; it cannot capture or inject into another account's session. Memory, tasks and CPU ceilings apply per account.
- **Clipboard images:** the client's bitmap and the session's PNG are both untrusted and are decoded in the unprivileged daemon with the `png` crate (pure Rust), after checking the declared size (16 megapixels, 16384 a side, 16 MiB of PNG) and before allocating; formats that are not plain 24/32 bit bitmaps are refused. A session may announce two images a second. A compromised daemon could already read the clipboard; the new surface is the decoder. Files are not carried.
- **Clipboard files (`--clipboard-files in`, off by default):** the client's file list and bytes are untrusted. The daemon refuses lists over 100 files, 64 MiB a file or 256 MiB in all, folders and unacceptable names; the session, which writes the files as the account into a private spool under `$XDG_RUNTIME_DIR`, checks again, builds every path itself, creates files exclusively without following links, and accepts bytes only in order. One transfer at a time; 30 s without data or 10 minutes ends it. A compromised daemon could place up to 256 MiB of chosen files in the spool and on the clipboard whatever the switch says (the session does not know it); the user still has to paste them. - **Clipboard files, session to client (`--clipboard-files out`, off by default):** the session is the untrusted side here (it names and sizes the files it offers); the daemon checks names, counts and sizes, answers ranges of at most 1 MiB, keeps at most 16 waiting, and passes only answers that match a request. The session serves only the regular files it recorded when the account copied them (never a path from the daemon), refuses links and folders, and refuses a file that changed. A compromised daemon can therefore read only files the account has just copied in its own session. Nothing is offered unless the account copies files.
- **Out of scope:** drive, printer and smartcard redirection, RD Gateway, running exposed to the internet, GPU sharing.

## Open items

- Plain TLS login (above); a second factor is not available.
- The helper trusts the daemon's claim of the client's source address, so a compromised daemon can poison the per-address counters (the per-account counter still holds).
- Passwords are not wiped from memory; daemon and helper are one binary.
- Many failed logins from many addresses are logged, not stopped. `pam_faillock` in the PAM stack of the service does it, with the trade-off that a stranger can then lock the owner out.
- Chromium from Flathub runs with `--password-store=basic`: nothing in a Waydesk session unlocks a keyring, so saved passwords and cookies sit under a fixed key, protected by the home directory's permissions only.
- No fuzzing of the RDP side, no independent review. Four internal passes are written down in [`docs/SECURITY-REVIEW.md`](https://github.com/zhoorta/waydesk/blob/main/docs/SECURITY-REVIEW.md); an outside review should start at `src/helper.rs`, `src/auth.rs`, `src/link.rs`, `src/proto.rs` and the unit files.
