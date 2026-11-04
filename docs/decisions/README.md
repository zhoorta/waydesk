# Decision records

Short records of the choices that shaped Waydesk: the problem, what was decided, why, and what it costs. Each one points at the document or the measurement that backs it. They were compiled on 2026-11-04 from the design notes, the changelog and the git history, so the dates are those of the decision where the history shows one, and a few records say "reconstructed" where the reasoning is written down only in a design note.

A record is not rewritten when things change: a later record supersedes it and both stay (see 011 and 012 for an example). Template: [`TEMPLATE.md`](TEMPLATE.md).

| # | Decision | Status |
|---|---|---|
| [001](001-one-headless-sway-per-account.md) | One headless sway per account, not one shared compositor | Accepted |
| [002](002-three-process-privilege-split.md) | Root helper, unprivileged daemon, session as the user | Accepted |
| [003](003-ironrdp-patched-copy.md) | RDP through IronRDP, with a patched copy in the repository | Accepted |
| [004](004-h264-over-egfx.md) | H.264 over EGFX as the picture codec | Accepted |
| [005](005-gpu-detect-and-use-never-require.md) | GPU: detect and use, never require | Accepted |
| [006](006-gpu-encoders-and-vendored-crates.md) | Hardware encoders through cros-codecs (VAAPI) and NVENC, with vendored patches | Accepted |
| [007](007-zero-copy-capture-and-qp-in-slice-headers.md) | Zero-copy capture, and the quantiser in the slice headers | Accepted |
| [008](008-memory-protection.md) | Memory is protected by admission control, ceilings and zram | Accepted |
| [009](009-network-exposure-and-login.md) | Loopback by default, plain TLS login, lockout per account and address | Accepted, open items |
| [010](010-explicit-non-goals.md) | What Waydesk does not do | Accepted |
| [011](011-private-session-stack-per-distribution.md) | Own session stack, per-distribution builds, Flatpak apps | Accepted |
| [012](012-arch-and-other-desktops.md) | Arch support and other desktops (Plasma, COSMIC, Hyprland) | Accepted, supersedes part of 011 |
| [013](013-repository-keys-and-first-administrator.md) | Own apt repository, the maintainer holds the key, every install creates an administrator | Accepted |
| [014](014-agpl-licence.md) | AGPL-3.0-or-later | Accepted |
| [015](015-existing-shell-and-chromium.md) | Reuse an existing shell; Chromium as the default browser | Accepted |
