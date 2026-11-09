# GPU placement and a GPU kept for AI

Status: design of 2026-10-31; the placement itself (sections 1 to 5) is built and unit-tested, not yet run on a machine with two GPUs. Step A (`waydesk-admin users set NAME --gpu ...`, a fixed GPU per account) is built (1b7b646). This is Step B: the server
chooses the GPU for an account's session, and a GPU can be kept for something else (a local model). Nothing here is measured yet; the numbers to decide the
open points come from the RTX 4000 SFF Ada box (Intel UHD 770 + RTX, same machine).

## What exists, and the constraint it sets

- `WAYDESK_GPU=auto|off|/dev/dri/renderDN` (`/etc/default/waydesk`), per account `/etc/default/waydesk.d/UID.env` (read later, so it wins). `auto` = the first usable node.
- The choice is made by each session process when it starts (`gpu::usable_node()`, called from the worker, the capture and the encoder), as the account, from the
  environment its unit gave it. A session keeps its card until it is restarted (sway cannot move to another GPU while running).
- The encoder follows the card (VA-API on Intel/AMD, NVENC on NVIDIA, matched by PCI). `waydesk-admin status` already reads each card's load (`gpuinfo.rs`) and each
  session's `render` node (`/run/waydesk/status/UID.json`).

So: placement has to happen **once, before the session starts, by something that sees all sessions**. A session process cannot do it (many start at once, as
the account, and an account must not be able to hold a lock that stops others logging in).

## Design

### 1. Where it runs
`ExecStartPre=+/usr/bin/waydesk-admin gpu place %i` in `waydesk-session@.service` (the `+` runs it as root). It takes `flock` on `/run/waydesk/gpu.lock` (root-owned),
decides, and writes `/run/waydesk/gpu/UID.env` with `WAYDESK_GPU=<node>`; the unit reads that file last (`EnvironmentFile=-/run/waydesk/gpu/%i.env`).
Nothing else in the session changes: it already honours `WAYDESK_GPU` and the encoder follows.

- It acts only when the effective setting is the new value **`balance`**. An account pinned with `--gpu` (or `off`) is left alone and its file in `/run/waydesk/gpu/` is removed.
  `auto` keeps today's meaning (first node), so nothing changes for existing servers; `balance` is opt-in.
- Several sessions starting together serialise on the lock, and each decision counts the claims already written, so the second one sees the first's choice.
  (Hyprland sessions that started together stalled before: the same race, in another place.)

### 2. The choice
Candidates: render nodes that exist, are not reserved (below), open read/write for the account, and have enough free video memory (NVIDIA through NVML; integrated
GPUs use system memory and are not checked). Then the lowest score wins:

    score = (sessions already on the node + 1) / weight          tie: lower busy %, then the lower node name

- Sessions on a node = the claim files in `/run/waydesk/gpu/` whose session is alive (the unit is active), not the status files: a session that is starting has no status yet.
- Weight: `WAYDESK_GPU_WEIGHTS=renderD128=1,renderD129=4`; default by kind: discrete (NVIDIA, AMD with own VRAM) 4, integrated 1. A first guess to be replaced by measurement
  (video engine and render engine at N sessions on each card).
- Nothing usable: the session is made in software, as today, and `place` logs why. (Option: refuse the login instead, like the memory check. See open points.)

### 3. A GPU kept for AI (or anything else)
**Roles (2026-10-31).** `WAYDESK_GPU_ROLES=renderD128=render,renderD129=inference,renderD130=both` says what each card is for, any number of each: `render` (sessions only), `inference`
(a model only: the placement skips it, NVENC for other cards' sessions stays off it), `both` (sessions placed on it, the free-memory floor protects the model). Unlisted cards are `render`.
`status` shows each card's role and one line, `CUDA_VISIBLE_DEVICES=GPU-a,GPU-b`, for the cards a model may use (`inference` and `both`); nothing in Waydesk makes the model service obey it,
that is the service's own setting. Warnings: a session on an `inference` card (pinned by hand), a session that renders on one card and encodes on another. The reserve below is the same
thing as `inference` for the cards it names.

`WAYDESK_GPU_ROLES=renderD129=inference`: `balance` never puts a session there. An explicit `--gpu renderD129` for
one account still works (an administrator who pins by hand means it). `status` shows the card as `reserved`.

When a card is shared with a model instead of reserved (one GPU machines), `WAYDESK_GPU_MIN_FREE_VRAM_MB=N` (default 0) keeps sessions off a card whose free memory has
fallen below N, so a model that is loaded is not pushed out and a model that has to load does not fail for lack of memory.

The reserve also binds the encoder: a session that renders on another card (the Intel one, say) never takes NVENC on a reserved NVIDIA card; it uses the first NVIDIA card that
is not reserved, or OpenH264 when there is none (found on 2026-10-31: with no VAAPI driver on the Intel chip, an Intel-pinned session fell back to NVENC and held 193 MiB of the
model's card). A session placed on the reserved card itself keeps it.

### 4. Keeping the model on its card
The inference service is pinned with `CUDA_VISIBLE_DEVICES`, which counts in CUDA order, not render node order. `waydesk-admin status` prints the card's NVML UUID instead
(`CUDA_VISIBLE_DEVICES=GPU-...`), which does not depend on the counting order (`CUDA_DEVICE_ORDER`). Not done by Waydesk: starting or limiting the model itself.
Sharing the model between accounts safely (the service answers any local account) needs a per-account check; a unix socket with peer credentials would give it.
That is a separate piece and is not needed for the first measurements.

### 5. Visibility
- `status` AI line and column (2026-10-31): with `WAYDESK_AI_ENDPOINT` set, the model the service holds and its video memory (Ollama's `/api/ps`), and the connections each account has open to the service's port, read from `/proc/net/tcp` (no proxy; root-only view). No token counts: that needs a proxy that counts requests.
- `waydesk-admin status`: per card, the sessions on it (count and names), `reserved`, free memory; `--json` the same.
- `users list`: the GPU column shows the pin, or `balance` (with the node a running session got).
- Audit: `gpu.place` events (account, node, score of the candidates, reason for a fallback) so a surprising choice can be explained afterwards.

## Not in this step
- Moving a running session to another card (not possible without restarting it). A rebalancing helper could end the idlest sessions at night; no.
- Per-user VRAM limits. NVIDIA gives no cgroup for it; the free-memory guard is the only protection.
- A load-based decision at the moment of start (current busy %) as the main factor: GPU load changes in seconds and a session lasts days, so session count by weight is
  the stable measure and busy % only breaks ties.

## Open points (to settle with the RTX box)
1. **Do sessions on the RTX cost VRAM, and how much?** Unmeasured (the iGPU numbers are system RAM). Measure with `nvidia-smi` at 1, 5, 10 sessions with the same workload.
   This sets the default for `MIN_FREE_VRAM_MB` and whether an RTX can be shared with a 14B model at all.
2. **Is the weight 4:1 right?** Run N sessions pinned to each card with the heavy workload and compare fps, encoder bitrate and CPU. The ratio should follow the result.
3. **Encoder session limit.** Consumer NVIDIA cards cap concurrent NVENC sessions (the driver limit has changed between releases); a professional card such as the RTX 4000
   Ada should not. Check on the box, and if there is a cap the weight must stop at it (a full card = a candidate that is skipped).
4. **No candidate: software or refuse?** Software keeps users working but costs CPU (measured: 15 % against 5 % of the machine at 20 users). Refusing is clearer for an
   administrator. Proposal: software, with the log line and a `status` warning.
5. **Does an inference run slow the sessions on the same card?** The AI-load phase of the capacity plan: sessions on the UHD 770 with the model on the RTX (expected: no effect),
   then sessions on the RTX with the model on the RTX (expected: encoder fine, render engine contended).

## Decisions taken (2026-10-31)
- No candidate: software rendering, with a log line and an audit entry (`gpu.place`), and a `Warning` line in `status`.
- A hard reserve (the `inference` role) and the free-memory floor (`WAYDESK_GPU_MIN_FREE_VRAM_MB`), both.
- Not checked by `place`: that the account itself may open the node (the udev rule gives the group `waydesk-users` access; the session logs and falls back if not).

## Order of work
1. (done, 2026-10-31) `waydesk-admin gpu place UID` (lock, claims, score, env file) with unit tests for the score and the claims (no GPU needed), the unit change, `balance` accepted by
   `users set --gpu` and by `WAYDESK_GPU`.
2. (done, 2026-10-31) `reserve`, `MIN_FREE_VRAM_MB`, the status lines (sessions per card, reserved, the UUID to pin a model, the software warning), audit events.
3. On the RTX box: open points 1 to 3, then the combined AI-load run.
