# 004: H.264 over EGFX as the picture codec

Date: reconstructed (2026-10). Status: accepted.

## Problem
A desktop is mostly text and flat colour, but also video and animation. The codec decides bandwidth, CPU per session and how sharp text looks.

## Decision
Send H.264 over the RDP graphics pipeline (EGFX). The software baseline is OpenH264 in its screen-content mode; a GPU encoder replaces it when there is one (see 005 to 007). A `WAYDESK_H264_USAGE=camera` option trades twice the bandwidth for a third of the CPU.

## Why
The bandwidth is low enough for a VPN or SSH tunnel, and the target clients (Windows App, FreeRDP) decode H.264. Measured: on a moving screen 89 % of OpenH264's time is its motion search; screen mode costs about 8 ms per frame at 720p whatever changed.

## Cost and risks
H.264 4:2:0 loses sharpness on thin coloured text (PSNR is about 12 dB lower in screen mode at rest than camera mode). Oxydesk, a similar project, chose RemoteFX as its default for exactly this reason (its ADR 019, 2026-10-26) at the price of 50 to 140 ms of CPU per full frame. If blurry text is reported, a 4:4:4 or lossless option is the next step. The OpenH264 patent position and the name are not cleared.

## Evidence
`docs/MEASUREMENTS.md`, `docs/ROADMAP.md` ("H.264 CPU on a lightly changing desktop"), commit c005e53.
