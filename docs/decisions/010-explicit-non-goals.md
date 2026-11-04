# 010: What Waydesk does not do

Date: 2026-10-16. Status: accepted (revisit on demand).

## Decision
Out of scope on purpose: drive, printer and smartcard redirection, RD Gateway, load balancing, GPU sharing between accounts, and running exposed on the open internet without a VPN or tunnel. The clipboard carries text and, since 2026-11-04, images (see below); files are not carried yet.

## Why
The design note lists them as non-goals without giving reasons. The working reason is scope: a single maintainer and a product small enough to review.

## Cost and risks
Business users ask for drive and printer redirection and for clipboard files and images. A comparable project (Oxydesk) offers them. Clipboard images and files, auto-reconnect and drive redirection are candidates to revisit, in that order of cost; each needs its own threat-model entry first.

## Update 2026-11-04: clipboard images
Images are in, first of the three candidates. The client's CF_DIB (24 or 32 bit, uncompressed) is converted to PNG in the network daemon and handed to the session (`wl-copy --type image/png`); the session's PNG goes the other way and becomes a 24 bit CF_DIB. Limits: 16 megapixels, 16384 pixels a side, PNG at most 16 MiB, two images a second from a session. Transparency is shown on white. Text wins when both are offered. Threat-model entry: `docs/THREAT-MODEL.md`. Files and drive redirection are still out.

## Evidence
`docs/MULTIUSER-DESIGN.md` section 1, `docs/THREAT-MODEL.md`, `docs/ROADMAP.md`.
