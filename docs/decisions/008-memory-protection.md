# 008: Memory is protected by admission control, ceilings and zram

Date: 2026-10-21, zram sizing 2026-10-23. Status: accepted.

## Problem
Each desktop session takes hundreds of megabytes. One more login on a full machine meant the kernel's out-of-memory killer picking victims among everyone's sessions.

## Decision
- A new session is refused when the machine is full; the client is told why (out of memory or user limit, see 003).
- Every account has memory, swap, task and CPU-weight ceilings in its systemd slice (`waydesk-admin users limit`); `user-.slice` gets `TasksMax`, `MemoryHigh` 80 % and `MemoryMax` 90 %.
- zram as large as RAM (at most 16 GiB), where Debian's default is half (at most 4 GiB).
- CPU uses weights, not a hard quota, by default: a cap wastes idle cores, and the desktop's own software rendering counts against it. A per-account `--cpu-quota` is planned as the exception.
- A session without a client for `--compact-after` seconds (default 600, 0 = never; set in `WAYDESK_SESSION_ARGS`) is compacted: the worker sends one byte to the root helper, which writes the account's memory to swap with `memory.reclaim` on `user-UID.slice` (src/compact.rs; the helper unit keeps `/sys/fs/cgroup/user.slice` writable). Programs keep running; the account's pages come back when touched. Once per absence, and the helper does it at most once a minute per account. It is only as good as the swap behind it: with the packaged zram the pages stay in RAM, compressed.

## Why
Measured: zram compresses about 4.5 to 1, giving 8 heavy users on 8 GB instead of 6, with no kill. A 12-vCPU, 23 GB server held 12 heavy users and refused the 13th.

Compaction, measured 2026-11-20 on a 2 vCPU / 4 GB Arch server (sway session plus a 300 MB idle program in the account's slice, zram): 359 MB in RAM went to 10 MB (384 MB in swap, which is mostly zeros here, so the compression is better than real programs give; expect 2 to 4 to 1), the host's available memory rose by about 400 MB, the program was still running afterwards and a reconnect took a few seconds. The first run of a real browser session is not measured.

## Cost and risks
Active users on 8 GB are not yet measured (idle ones were). The slice limits also apply to administrators logged in over ssh.

## Evidence
Commit fd2abe5, commit e97f040, `docs/MEASUREMENTS.md`, `docs/ROADMAP.md`.
