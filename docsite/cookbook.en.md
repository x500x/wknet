# Cookbook

Recipes by task. Compilable samples live under `src/wknettest/samples` and the user-mode tests; there is no separate `samples/Cookbook*` tree.

## Sample sources (source of truth)

| Path | Content |
|------|---------|
| `src/wknettest/samples/HighLevelApiSamples.cpp` | Session, sync/async HTTP methods, body shapes, TLS, HTTP/2, WebSocket |
| `src/wknettest/samples/AdvancedScenarioSamples.cpp` | Redirects, error statuses, large responses, concurrent async, timeouts, TLS failure, WS fragments |
| `src/wknettest/samples/ExternalTrustStore.cpp` | External trust store / certificate scenarios |
| `src/wknettest/samples/HttpApiSamples.cpp` | Driver-side sample entry |
| `tests/high_level_api_tests.cpp` | User-mode API regression |

Umbrella include: `#include <wknet/Wknet.h>`. WebSocket may also use `#include <wknet/websocket/WebSocket.h>`.

## Scenario index

| Scenario | Where to look | Key API |
|----------|---------------|---------|
| Minimal GET | [First request](first-request.md), `HighLevelApiSamples` | `Get` / `ResponseStatusCode` / `ResponseRelease` |
| Same-host multi-request (pool hit) | Reuse one `Session` for successive `Get` | `SessionCreate` + reuse |
| POST JSON / form / file | `HighLevelApiSamples` body section | `BodyCreateJson*` / `BodyCreateForm` / `BodyCreateFile*` |
| Custom request headers | `HeadersAdd` + `SendEx` | `HeadersCreate` / `SendEx` |
| Streaming download | `SendOptions.OnHeader` / `OnBody` | `SendOptionsCreate` + `SendEx` |
| HTTPS + explicit TLS | `ExternalTrustStore`, [TLS & trust](tls-and-trust.md) | `TlsConfig` / `CertificateStore` |
| Async request | `HighLevelApiSamples` async section | `AsyncGetEx` / `AsyncWait` / `AsyncGetResponse` |
| Async cancel | Advanced concurrent/cancel section | After `AsyncCancel` still `AsyncWait` + `AsyncRelease` |
| WebSocket echo | `HighLevelApiSamples` WS section | `websocket::Connect` / `SendText` / `Receive` / `Close` |
| HTTP/3 Auto | [HTTP/3 & QUIC](http3-quic.md) | `SessionConfig.Http3.Mode` |

## Discipline (every scenario)

1. **IRQL**: calls and guard-style release at `PASSIVE_LEVEL`.
2. **Ownership**: release `Response` separately from the `Request`/`AsyncOp` that produced it.
3. **Unload**: after async APIs, call `wknet::http::Destroy()` before unload.
4. **WebSocket timing**: do not race `Close` with new I/O; `Message.Data` lives until the next receive/close.
5. **JSON**: the library does not parse JSON — it only forwards bytes.

Handle rules: [API overview](api/overview.md). Error semantics: [Errors & FAQ](errors-and-faq.md).
