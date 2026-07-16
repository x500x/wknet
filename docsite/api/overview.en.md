# API overview

`#include <wknet/Wknet.h>`

Namespaces: `wknet::http` · `wknet::websocket` · `wknet::sse` · `wknet::codec` · `wknet::crypto`

## Conventions

| Item | Notes |
|------|-------|
| IRQL | HTTP / WebSocket / certificate / async entry points at `PASSIVE_LEVEL` |
| Returns | Mostly `NTSTATUS`; check `_Must_inspect_result_`; success via `NT_SUCCESS` |
| Handles | Opaque heap objects; `Create` to obtain, `Close` / `Release` to free |
| Options | `SendOptions` / `AsyncOptions` via `*Create` / `*Release` |
| Null | `Close` / `Release` accept `nullptr` |
| Exceptions | No C++ exceptions |

## Handles

| Type | Namespace | Create / obtain | Free | Header |
|------|-----------|-----------------|------|--------|
| `Session` | `wknet::http` | `SessionCreate` | `SessionClose` | `http/Session.h` |
| `Request` | `wknet::http` | `RequestCreate` | `RequestRelease` | `http/Request.h` |
| `Response` | `wknet::http` | `Send*` / `AsyncGetResponse` | `ResponseRelease` | `http/Response.h` |
| `AsyncOp` | `wknet::http` | `Async*` / `ConnectAsync*` | `AsyncRelease` | `http/AsyncOp.h` |
| `Headers` | `wknet::http` | `HeadersCreate` | `HeadersRelease` | `http/Headers.h` |
| `Body` | `wknet::http` | `BodyCreate*` | `BodyRelease` | `http/Body.h` |
| `Cache` | `wknet::http` | `CacheCreate` | `CacheRelease` | `http/Cache.h` |
| `CertificateStore` | `wknet::http` | `CertificateStoreCreate` | `CertificateStoreClose` | `http/Certificate.h` |
| `WebSocket` | `wknet::websocket` | `Connect*` | `Close` / `CloseEx` | `websocket/WebSocket.h` |
| `SseClient` | `wknet::sse` | `Connect*` | `Close` | `sse/Sse.h` |

`SendOptions` / `AsyncOptions`: [Sync HTTP](http-sync.md) / [Async HTTP](http-async.md).

## Headers

| Header | Contents |
|--------|----------|
| `wknet/Wknet.h` | Public API umbrella |
| `wknet/http/Types.h` | Enums, config structs, callbacks, defaults |
| `wknet/http/Session.h` | `SessionCreate` / `SessionClose` |
| `wknet/http/Request.h` | `RequestCreate` / `RequestRelease` |
| `wknet/http/Headers.h` | Request headers |
| `wknet/http/Body.h` | Request body |
| `wknet/http/Options.h` | `SendOptionsCreate` / `AsyncOptionsCreate` |
| `wknet/http/Http.h` | Sync `Send` / `Get` / `Post` … |
| `wknet/http/HttpAsync.h` | Async `AsyncSend` / `AsyncGet` … |
| `wknet/http/AsyncOp.h` | Wait, cancel, take `Response` |
| `wknet/http/Response.h` | Status / body / headers / trailers |
| `wknet/http/Lifecycle.h` | `Destroy` |
| `wknet/http/Certificate.h` | `CertificateStore`, pins, mTLS types |
| `wknet/http/Cache.h` | In-memory cache |
| `wknet/websocket/WebSocket.h` | WebSocket connect and I/O |
| `wknet/sse/Sse.h` | Server-Sent Events client |
| `wknet/codec/Codec.h` | Content-coding / EXI / Pack200 |
| `wknet/crypto/Aead.h` | AEAD |
| `wknet/crypto/TlsCredential.h` | `TlsClientCredential` (via `Certificate.h`) |
| `wknet/Trace.h` | Diagnostics |

`Wknet.h` includes the public headers above (`TlsCredential.h` via `Certificate.h`). Fine-grained includes may take only the headers needed.

## Defaults

| Function | Returns |
|----------|---------|
| `DefaultSessionConfig()` | `SessionConfig` |
| `DefaultTlsConfig()` | `TlsConfig` |
| `DefaultSendOptions()` | `SendOptions` value |
| `DefaultConnectConfig()` | `websocket::ConnectConfig` or `sse::DefaultConnectConfig()` |

Use `SendOptionsCreate` / `AsyncOptionsCreate` when passing `SendOptions` / `AsyncOptions` to APIs (constructors are private).

## Pages

| Page | Contents |
|------|----------|
| [Session & config](session-config.md) | `Session`, `SessionConfig`, `Http3`, proxy, pool, cache |
| [Request & response](request-response.md) | `Request`, `Headers`, `Body`, `Response` |
| [Sync HTTP](http-sync.md) | `Send` / method-specific send, `SendOptions` |
| [Async HTTP](http-async.md) | `AsyncSend`, `AsyncOp`, `Destroy` |
| [WebSocket](websocket.md) | `Connect` / send / receive / close |
| [SSE](sse.md) | `SseClient` Connect / Receive / Close |
| [TLS options](tls-options.md) | `TlsConfig`, `CertificateStore`, mTLS |
| [Codec & crypto](codec-crypto.md) | Decode and AEAD |
