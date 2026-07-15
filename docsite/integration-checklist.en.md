# Integration checklist

Confirm every item before production. A single miss is enough to stay off the release path.

## Build and link

- [ ] Matching VS 2022 + WDK + SDK
- [ ] Link `wknetlib.lib`; additional include dir points at `include`
- [ ] Product code only `#include <wknet/Wknet.h>` (or fine-grained public headers) — never `src/wknetlib` internals
- [ ] Debug/Release treat warnings as errors

## Calling conventions

- [ ] Sync HTTP / WebSocket / TLS / certificate paths only at `PASSIVE_LEVEL`
- [ ] All public handles come from Create and leave via Close / Release; unconditional Release on failure paths (accepts `nullptr`)
- [ ] Option objects such as `SendOptions` / `AsyncOptions` are heap objects too — matching Create / Release
- [ ] Every `_Must_inspect_result_` return value is inspected

## Lifetime and unload

- [ ] Reuse one `Session` for same-host requests so the pool can hit
- [ ] `Response` lifetime is independent of `Request` / `AsyncOp` — release each
- [ ] If async APIs were used, call `wknet::http::Destroy()` before unload, then tear down WSK / other subsystems
- [ ] WebSocket: do not race `Close` with new I/O on the same handle; safest is single-threaded connect → send → receive → close
- [ ] `wknet::websocket::Receive` `Message.Data` points at an internal buffer valid until the next receive/close

## Security defaults

- [ ] Production uses `CertPolicy::Verify` with a caller-supplied `CertificateStore` (anchors / pins)
- [ ] `NoVerify` is not left in release configuration
- [ ] HTTPS→HTTP redirects are refused by default; cross-origin redirects strip sensitive headers
- [ ] Only `GET` / `HEAD` / `OPTIONS` auto-retry once on stale connection failure; POST and friends are never auto-replayed
- [ ] Strong revocation uses explicit `RequireRevocationCheck` plus verifiable OCSP/CRL evidence

## Observability

- [ ] Product Trace stays at default `Off` (or Info when needed); never log bodies, cookies, secrets, or full URL queries
- [ ] Prefer component filters over global Max in production

## Protocol choices (as needed)

- [ ] HTTP/3 default `Auto` is acceptable; use `Disabled` or prior-knowledge `Required` deliberately
- [ ] Opt-in only for h2c / pipeline / 0-RTT / permessage-deflate and other default-off features
- [ ] Read the [capability matrix](capability-matrix.md); non-goals are not on the dependency path

After the checklist: day-to-day recipes in [Cookbook](cookbook.md); semantics in [Session & pool](session-and-pool.md) and [Async model](async-model.md).
