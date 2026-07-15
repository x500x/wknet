# Integration notes

What to settle when linking the library into a driver: build, calling conventions, lifetime, trust, and protocol choices.

## Build and link

- Toolchain: VS 2022 with matching WDK / SDK
- Link `wknetlib.lib`; additional include directory points at `include`
- Product code includes only `<wknet/Wknet.h>` (or fine-grained public headers), never `src/wknetlib` internals
- Debug / Release treat warnings as errors

## Calling conventions

- Sync HTTP / WebSocket / TLS / certificate paths run at `PASSIVE_LEVEL`
- Public handles come from Create and leave via Close / Release; failure paths may Release unconditionally (`nullptr` is fine)
- `SendOptions` / `AsyncOptions` are heap objects too — matching Create / Release
- Inspect `_Must_inspect_result_` return values

## Lifetime and unload

- Reuse one `Session` for same-host requests so the pool can hit
- `Response` lifetime is independent of `Request` / `AsyncOp` — release each
- After async APIs, call `wknet::http::Destroy()` on the unload path, then tear down WSK and other subsystems
- WebSocket: do not race `Close` with new I/O on the same handle; a common pattern is single-threaded connect → send → receive → close
- `wknet::websocket::Receive` `Message.Data` points at an internal buffer valid until the next receive / close

## Trust and defaults

- Production uses `CertPolicy::Verify` with a caller-supplied `CertificateStore` (anchors / pins)
- Do not leave `NoVerify` in release configuration
- HTTPS→HTTP redirects are refused by default; cross-origin redirects strip sensitive headers
- On stale connection failure, only `GET` / `HEAD` / `OPTIONS` auto-retry once; POST and similar methods are never auto-replayed
- Hard revocation: explicit `RequireRevocationCheck` plus verifiable OCSP/CRL evidence

## Diagnostics

- Product Trace defaults to `Off` (Info when needed); do not log bodies, cookies, secrets, or full URL queries
- Prefer component filters; avoid global Max in production

## Protocol choices

- HTTP/3 defaults to `Auto`; use `Disabled` when unwanted, `Required` for prior knowledge
- h2c, pipelining, 0-RTT, permessage-deflate and other default-off features stay off until explicitly enabled
- Support scope and limits: [Capability matrix](capability-matrix.md)

Recipes: [Cookbook](cookbook.md). Semantics: [Session & pool](session-and-pool.md), [Async model](async-model.md).
