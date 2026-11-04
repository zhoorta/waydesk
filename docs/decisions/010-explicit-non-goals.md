# 010: What Waydesk does not do

Date: 2026-10-16. Status: accepted (revisit on demand).

## Decision
Out of scope on purpose: drive, printer and smartcard redirection, RD Gateway, load balancing, GPU sharing between accounts, and running exposed on the open internet without a VPN or tunnel. The clipboard is text only.

## Why
The design note lists them as non-goals without giving reasons. The working reason is scope: a single maintainer and a product small enough to review.

## Cost and risks
Business users ask for drive and printer redirection and for clipboard files and images. A comparable project (Oxydesk) offers them. Clipboard images and files, auto-reconnect and drive redirection are candidates to revisit, in that order of cost; each needs its own threat-model entry first.

## Evidence
`docs/MULTIUSER-DESIGN.md` section 1, `docs/THREAT-MODEL.md`, `docs/ROADMAP.md`.
