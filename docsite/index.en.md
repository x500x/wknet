# wknet

A pure kernel-mode HTTP/HTTPS/WebSocket client for Windows drivers.

Transport is WSK; cryptography is kernel CNG/BCrypt. No WinHTTP, WinINet, or SChannel. Public API is four namespaces: `wknet::http`, `wknet::websocket`, `wknet::crypto`, `wknet::codec`.

## Fit / not a fit

| Fit | Not a fit |
|-----|-----------|
| Outbound HTTP(S) / WebSocket from a kernel driver | HTTP server / inbound request parser |
| Explicit security defaults and capability bounds | Automatic trust of the system CA store |
| One product API across HTTP/1.1 · HTTP/2 · HTTP/3 | QUIC migration / WebTransport and other non-goals |

## Hard constraints

1. Sync paths require `PASSIVE_LEVEL`; handles are heap objects with paired Create / Close·Release.
2. Trust anchors, CA bundles, pins, and revocation evidence are **caller-supplied**; hostname checks never fall back to CN.
3. Trace defaults to `Off`; HTTP/3 defaults to `Auto` (learn from authenticated Alt-Svc).

## Start here

1. [Build](build.md) — produce `wknetlib.lib`
2. [First request](first-request.md) — minimal GET / POST
3. [Integration checklist](integration-checklist.md) — pre-flight
4. [Capability matrix](capability-matrix.md) — implemented / opt-in / refused / non-goals

Task recipes: [Cookbook](cookbook.md). Signatures: [API overview](api/overview.md).
