# 016: Clipboard files

Date: 2026-11-04. Status: accepted; both stages built 2026-11-04 and tested with FreeRDP on Linux (copy, limits, refusals, a changed file); not tested with the Windows App or a file manager.

## Problem
The clipboard carries text and images ([010](010-explicit-non-goals.md)). Business users also expect to copy files from their own machine and paste them into the session, and back. `ironrdp-cliprdr` 0.7 implements the protocol (file list, ranged file contents, locks, name sanitising) and the patched `ironrdp-server` forwards every event, but Waydesk's backend ignores them and does not advertise the capabilities, so clients never offer files. The unprivileged network daemon cannot write into an account's home, and the account's files must not be readable by the daemon, so the file work belongs to the session process, as the clipboard already does.

## Decision
Build it in two stages, each behind its own switch, off by default.

**Switches.** `--clipboard-files` on the daemon (and `WAYDESK_CLIPBOARD_FILES=in|out|both|off` in `/etc/default/waydesk`; default `off`). Per-group switches from the roadmap come later and only narrow this one. The capability flags `STREAM_FILECLIP_ENABLED`, `CAN_LOCK_CLIPDATA` and `FILECLIP_NO_FILE_PATHS` are advertised only when a direction is on.

**Stage 1: client to session (`in`).**
1. The client's format list names `FileGroupDescriptorW`. The daemon asks for it (`SendInitiatePaste`) and receives the descriptors in `on_remote_file_list`.
2. The daemon checks the list before anything else: at most 100 files, 256 MiB in total, 64 MiB for one file (constants in `proto.rs` for now, not settings), no directories in stage 1 (a directory descriptor or a name with a path refuses the whole list), names through `clean_name` (`sessionfiles.rs`), then again by the session. A refused list ends with a log line and no paste.
3. The daemon sends the session `Down::FilesBegin { id, names, sizes }`. The session creates `$XDG_RUNTIME_DIR/waydesk-files/<id>/` (0700; a tmpfs, so a transfer cannot fill the account's home, and it is capped by the same totals) and answers `Up::FilesReady`.
4. The daemon fetches each file with RANGE requests of 256 KiB, one in flight, against the locked list (`clip_data_id`), and relays each chunk as `Down::FilesData { id, index, offset, bytes }`. The session writes at the offset it expects (sequential only), refuses a chunk past the declared size, and never follows a path the daemon names: it builds the path from the index and a name it has sanitised itself (a single path component, no control characters, a leading dot replaced by an underscore, ` (2)` before the extension on collision, `O_CREAT|O_EXCL|O_NOFOLLOW`).
5. When all files are complete the session sets the Wayland clipboard to `text/uri-list` and `x-special/gnome-copied-files` (`copy\nfile:///...`) with `wl-copy`, so a paste in the file manager copies from the spool into the destination. A second transfer, a new clipboard owner or the end of the connection removes the spool.

A transfer has a deadline (30 s without a chunk, 10 minutes in all) and the daemon takes one transfer at a time per connection.

**Stage 2: session to client (`out`).** The session watches `text/uri-list`. For a list of regular files (no directories, no symlinks out of the home, same totals) it sends `Up::FilesOffered { id, names, sizes }`; the daemon announces them with `SendInitiateFileCopy`. When the client asks for contents the daemon sends `Down::FilesRead { id, index, offset, len }`; the session opens the file by index from the list it recorded (never by a name from the daemon), checks that size and inode still match, and answers with `Up::FilesData`. This stage reads files the account could already read, but it is the one that can leak, so it is separate and has its own switch.

**Not in scope.** Directory trees (stage 3, if asked for), drag and drop, resume, per-file progress in the client (the client shows its own).

## Why
- The session process already runs as the account and already holds the Wayland clipboard; the daemon, which parses the network, never gets a path to open or write.
- A spool on tmpfs plus the totals bound memory and disk per account without touching the account's quota; the file manager does the final copy, where the user chooses the destination.
- Ranged, one-chunk-in-flight transfer keeps the daemon's memory flat and lets the link's existing back-pressure do the throttling.
- Separate directions because the risks differ: `in` writes into the account (bounded, in a private directory), `out` reads from it.

## Cost and risks
- A compromised daemon can already type into every session; with `in` it can also put up to 256 MiB of chosen files in a spool and offer them on the account's clipboard. The user still has to paste them somewhere, but a file manager paste of a hostile name is the classic path to trouble, hence the name rules above and the refusal of paths and directories.
- `out` lets a compromised daemon ask for any file the session has offered, and only those; it cannot name a file. A session that offers `~/.ssh/id_ed25519` is the user's own act.
- The size limits are policy, not protocol: the library accepts `u64` sizes and `u32` chunk sizes from the peer and trusts the caller.
- Clients differ (Windows App on macOS, Microsoft's client on Windows, FreeRDP); each needs a real test, and Windows App on macOS is known to be slow to answer clipboard requests (see the `SETTLE` comment in `src/clipboard.rs`).
- Antivirus and DLP scanning of transferred files is not provided.
- Four new link messages and a new session module widen `proto.rs`; they get the same round-trip, truncation and size tests, and the fuzz targets that are still missing for the RDP side become more pressing.

## Built (stage 1)
`proto.rs` (`FilesBegin`, `FilesData`, `FilesCancel`, `FilesReady`, `FilesFailed`), `sessionfiles.rs` (spool, names, order checks; unit-tested in isolation), `clipboard.rs` (capabilities, `on_remote_file_list`, one range in flight, 30 s idle and 10 min total watchdog), `sessionclip.rs` (`set_uri_list`), `link.rs`, `worker.rs`, and the switch `--clipboard-files off|in` / `WAYDESK_CLIPBOARD_FILES`. The clipboard offers `text/uri-list` only (`wl-copy` offers one type); if a file manager needs `x-special/gnome-copied-files`, that is a change in `set_uri_list`. The switch lives in the daemon; the session enforces the limits whatever the daemon asks.

## Built (stage 2)
`--clipboard-files out|both`. The daemon tells the session (`Down::FilesOut`) that files may be offered; the session watches for a `text/uri-list` on its clipboard, and for a list of regular files (no folders, no links, 100 files, 64 MiB each, 256 MiB in all, names cleaned like stage 1) records path, size, device, inode and modification time and sends `Up::FilesOffered`. The daemon announces them (`SendInitiateFileCopy`), answers SIZE requests itself and RANGE requests (at most 1 MiB, cut at the end of the file, 16 waiting at most) through `Down::FilesRead`; the session opens the recorded path with `O_NOFOLLOW`, checks that size, inode and time are unchanged and answers with `Up::FilesData` or `Up::FilesReadFailed`. A new session or client copy replaces the offer. Tested: two files (19 bytes, 2.5 MB random) read byte for byte through FreeRDP's mount; a file changed after the offer is refused (the client sees an I/O error). A list the session cannot offer (a folder, a link) is not offered as files; the paths may go to the client as text, as before.

## Plan
1. `proto.rs`: `FilesBegin`, `FilesData`, `FilesReady`, `Cancel` (Down), `FilesReady`, `FilesFailed` (Up), with limits and tests.
2. `sessionfiles.rs`: spool, name rules, offset checks, clipboard set; unit tests for hostile names (`..`, absolute, NUL, long, duplicate, Unicode separators, `.`-prefixed, devices) and for out-of-order or oversized chunks.
3. `clipboard.rs`: capability flags, `on_remote_file_list`, request loop, totals check, deadlines.
4. Threat-model entry and the switch documented in `docs/REFERENCE.md`; ADR 010 updated.
5. Tests on the Linux box with FreeRDP (`/clipboard`) first, then the Windows App on macOS and a Windows client. Stage 2 after stage 1 has been used for a while.

## Evidence
`ironrdp-cliprdr` 0.7: `backend.rs` (`on_remote_file_list`, `on_file_contents_*`), `lib.rs` (`sanitize_file_path`, `MAX_FILE_COUNT`, lock and pending-request limits). `patches/ironrdp-server/src/server.rs:1183-1189` forwards the file messages. `src/clipboard.rs`, `src/sessionclip.rs`, `src/link.rs` (gates).
