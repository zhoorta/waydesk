# 005: GPU: detect and use, never require

Date: 2026-10-27. Status: accepted.

## Problem
Most cheap servers have no GPU, but a GPU changes density and latency a lot when it exists.

## Decision
At session start, if a render node exists the session renders on it (`WLR_RENDERER=gles2`), otherwise on the CPU (pixman). Any failing step falls back to the software behaviour; if a session cannot be made on the GPU it is made again once in software and the log says so. `WAYDESK_GPU=auto|off|<node>` overrides, `auto` by default. Per account, `waydesk-admin users set --gpu` pins a card; `WAYDESK_GPU_ROLES` keeps a card for inference.

## Why
The same package must work on a 4 euro VPS and on a GPU server, and a driver problem must never leave an account without a desktop. The case that proved it: Debian's NVIDIA 550 lets sway start and then gives it no buffers; NVIDIA 615 or newer is required for NVIDIA rendering.

## Cost and risks
Render nodes are shared and there is no per-account GPU quota. Cards with their own memory under many users, AMD, and several users on one NVIDIA card (NVENC session limits) are not measured yet (roadmap).

## Evidence
`docs/GPU-PLAN.md`, changelog 0.4.0 and 0.5.0, commit 6c487c2. Measured on an i7-7700 with an HD 630: the OpenGL benchmark went from 167 to 2840 points and a full-screen animation from 107 % to 21 % of a core.
