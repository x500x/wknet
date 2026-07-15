# wknet

A pure kernel-mode HTTP/HTTPS/WebSocket client library for Windows drivers.

Transport main path is WSK; cryptography main path is kernel CNG/BCrypt. No WinHTTP, WinINet, or SChannel. Public API is four namespaces: `wknet::http`, `wknet::websocket`, `wknet::crypto`, `wknet::codec`.

## Scope

wknet is a kernel-mode HTTP/HTTPS/WebSocket **client**. It is for drivers that issue requests and want explicit security defaults, with one product API across HTTP/1.1, HTTP/2, and HTTP/3.

It does not provide an HTTP server or inbound request parser, and it does not ship a system CA store. Features such as QUIC migration and WebTransport are not supported today; see the [capability matrix](capability-matrix.md).

## Integration notes

- Call sync paths at `PASSIVE_LEVEL`. Public handles are heap objects; pair Create with Close / Release.
- Trust anchors, CA bundles, pins, and revocation evidence are caller-supplied. Hostname verification does not fall back to CN.
- Trace defaults to `Off`. HTTP/3 defaults to `Auto` and learns from authenticated Alt-Svc.

## Start here

1. [Build](build.md) — produce `wknetlib.lib`
2. [First request](first-request.md) — minimal GET / POST
3. [Integration notes](integration-checklist.md) — link, lifetime, trust
4. [Capability matrix](capability-matrix.md) — support scope and limits

Recipes: [Cookbook](cookbook.md). Signatures: [API overview](api/overview.md).
