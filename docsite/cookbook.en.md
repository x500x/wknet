# Cookbook

Task-oriented index of compilable samples under `src/wknettest/samples` and the user-mode tests.

## Sample locations

| Path | Content |
|------|---------|
| `src/wknettest/samples/HighLevelApiSamples.cpp` | Session, sync/async HTTP, body shapes, TLS, HTTP/2, WebSocket |
| `src/wknettest/samples/AdvancedScenarioSamples.cpp` | Redirects, error statuses, large responses, concurrent async, timeouts, TLS failure, WS fragments |
| `src/wknettest/samples/ExternalTrustStore.cpp` | External trust store / certificates |
| `src/wknettest/samples/HttpApiSamples.cpp` | Driver-side sample entry |
| `tests/high_level_api_tests.cpp` | User-mode API regression |

Public header: `#include <wknet/Wknet.h>`. WebSocket may also use `#include <wknet/websocket/WebSocket.h>`.

## Scenarios

| Scenario | Reference | Main API |
|----------|-----------|----------|
| Minimal GET | [First request](first-request.md), `HighLevelApiSamples` | `Get` / `ResponseStatusCode` / `ResponseRelease` |
| Same-host multi-request (pool) | Reuse one `Session` for successive `Get` | `SessionCreate` + reuse |
| POST JSON / form / file | `HighLevelApiSamples` body section | `BodyCreateJson*` / `BodyCreateForm` / `BodyCreateFile*` |
| Custom request headers | `HeadersAdd` + `SendEx` | `HeadersCreate` / `SendEx` |
| Streaming download | `SendOptions.OnHeader` / `OnBody` | `SendOptionsCreate` + `SendEx` |
| HTTPS + TLS | `ExternalTrustStore`, [TLS & trust](tls-and-trust.md) | `TlsConfig` / `CertificateStore` |
| Async request | `HighLevelApiSamples` async section | `AsyncGetEx` / `AsyncWait` / `AsyncGetResponse` |
| Async cancel | Advanced concurrent/cancel section | After `AsyncCancel`, still `AsyncWait` + `AsyncRelease` |
| WebSocket echo | `HighLevelApiSamples` WS section | `websocket::Connect` / `SendText` / `Receive` / `Close` |
| HTTP/3 Auto | [HTTP/3 & QUIC](http3-quic.md) | `SessionConfig.Http3.Mode` |

## Shared conventions

- Call and release at `PASSIVE_LEVEL`
- Release `Response` separately from the `Request` / `AsyncOp` that produced it
- After async APIs, call `wknet::http::Destroy()` on the unload path
- WebSocket: do not race `Close` with new I/O on the same handle; `Message.Data` is valid until the next receive/close
- `BodyCreateJson*` forwards bytes only; it does not parse JSON

Handle rules: [API overview](api/overview.md). Error semantics: [Errors & FAQ](errors-and-faq.md).
