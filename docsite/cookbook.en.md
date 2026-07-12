# Cookbook

A set of production-grade patterns for the `wknet::http` and `wknet::websocket` product APIs. Compilable examples live under `src/wknettest/samples`.

### Samples

| Sample | Demonstrates | Key APIs |
|--------|--------------|----------|
| QuickGet | Minimal correct GET + status check + guarded release | `Get` / `ResponseStatusCode` / `ResponseRelease` |
| SessionReuse | Multiple requests to same host hitting pool keep-alive | `Get` (same Session) |
| PostJson | POST JSON + custom headers + read response headers | `BodyCreateJson` / `HeadersAdd` / `SendEx` |
| StreamingDownload | Callback streaming without buffering whole body | `SendOptions.OnHeader/OnBody` |
| HttpsTls | HTTPS + explicit TLS: SNI, ALPN, always-on cert verify | `SendOptions.Tls` / `TlsConfig` |
| AsyncRequest | Async issue → wait → fetch response | `AsyncGetEx` / `AsyncWait` / `AsyncGetResponse` |
| AsyncCancel | Cooperative cancel (still wait for drain) | `AsyncCancel` / `AsyncWait` / `AsyncGetStatus` |
| WebSocketEcho | connect→send→recv→close with full-duplex timing | `wknet::websocket::Connect` / `wknet::websocket::SendText` / `wknet::websocket::Receive` / `wknet::websocket::Close` |

### RAII guards (KhttpScopeGuard.h)

`SessionGuard`, `RequestGuard`, `ResponseGuard`, `AsyncOpGuard`, `WebSocketGuard` — each calls the matching release/close on destruction (at `PASSIVE_LEVEL`). Members: `Receive()`, `Get()`, `Detach()`, `Reset()`, `operator bool`. Non-copyable, movable.

### Notes

1. **IRQL**: all calls and guard destruction at `PASSIVE_LEVEL`.
2. **Ownership**: `Response` lifetime is independent of `Request`/`AsyncOp`.
3. **Unload**: call `wknet::http::Destroy()` before unload after using async APIs. Synchronous-only paths do not require it, but may call it unconditionally.
4. **WebSocket full-duplex**: never run `wknet::websocket::Close` concurrently with new I/O on the same handle; safest is single-threaded connect→send→recv→close.
5. **`wknet::websocket::Receive`'s `message.Data`** points to an internal buffer valid until the next receive/close.

See `src/wknettest/samples/HighLevelApiSamples.cpp` and `tests/high_level_api_tests.cpp`.
