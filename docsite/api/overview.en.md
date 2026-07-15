# API Overview

Namespaces: `wknet::http` · `wknet::websocket` · `wknet::codec` · `wknet::crypto`  
Umbrella header: `<wknet/Wknet.h>`

## Role

Handle table, calling conventions, and header map for the public high-level API. Signatures and fields are taken from the headers; task recipes live in the [Cookbook](../cookbook.en.md).

## Calling conventions

| Item | Rule |
|------|------|
| IRQL | High-level HTTP / WebSocket / certificate / async entry points require `PASSIVE_LEVEL` |
| Returns | Mostly `NTSTATUS`; `_Must_inspect_result_` must be checked; success via `NT_SUCCESS` |
| Handles | Opaque heap objects; obtain via `Create` / send results; free via `Close` / `Release` |
| Options | `SendOptions` / `AsyncOptions` via `*Create` / `*Release` |
| Null | `Close` / `Release` accept `nullptr` |
| Errors | No C++ exceptions; failures return `NTSTATUS` and usually clear out-params |

## Opaque handles

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

`SendOptions` / `AsyncOptions` are heap objects too (Create / Release). See [Sync HTTP](http-sync.en.md) / [Async HTTP](http-async.en.md).

## What `<wknet/Wknet.h>` includes

`Wknet.h` aggregates **only** the public high-level headers. It does **not** pull in the low-level engine or transport internals:

```cpp
#include <wknet/WknetConfig.h>
#include <wknet/Trace.h>
#include <wknet/http/AsyncOp.h>
#include <wknet/http/Body.h>
#include <wknet/http/Cache.h>
#include <wknet/http/Certificate.h>
#include <wknet/http/Headers.h>
#include <wknet/http/Http.h>
#include <wknet/http/HttpAsync.h>
#include <wknet/http/Lifecycle.h>
#include <wknet/http/Options.h>
#include <wknet/http/Request.h>
#include <wknet/http/Response.h>
#include <wknet/http/Session.h>
#include <wknet/http/Types.h>
#include <wknet/websocket/WebSocket.h>
#include <wknet/crypto/Aead.h>
#include <wknet/codec/Codec.h>
```

Product code usually includes only `<wknet/Wknet.h>`. Use the map below for finer-grained includes.

## Header map

| Header | Contents |
|--------|----------|
| `wknet/Wknet.h` | High-level umbrella (above) |
| `wknet/http/Types.h` | Enums, config structs, callbacks, defaults |
| `wknet/http/Session.h` | `SessionCreate` / `SessionClose` |
| `wknet/http/Request.h` | `RequestCreate` / `RequestRelease` (some setters under test macro) |
| `wknet/http/Headers.h` | Request header handle |
| `wknet/http/Body.h` | Request body handle |
| `wknet/http/Options.h` | `SendOptionsCreate` / `AsyncOptionsCreate` |
| `wknet/http/Http.h` | Sync `Send` / `Get` / `Post` … |
| `wknet/http/HttpAsync.h` | Async `AsyncSend` / `AsyncGet` … |
| `wknet/http/AsyncOp.h` | Wait, cancel, take `Response`, release |
| `wknet/http/Response.h` | Status / body / header / trailer read-only |
| `wknet/http/Lifecycle.h` | `Destroy` async drain |
| `wknet/http/Certificate.h` | `CertificateStore*`, pin / mTLS types |
| `wknet/http/Cache.h` | RFC 9111 in-memory cache |
| `wknet/websocket/WebSocket.h` | WebSocket connect and I/O |
| `wknet/codec/Codec.h` | Content-coding / EXI / Pack200 decode |
| `wknet/crypto/Aead.h` | AEAD encrypt/decrypt |
| `wknet/crypto/TlsCredential.h` | `TlsClientCredential` (via `Certificate.h`) |
| `wknet/Trace.h` | Diagnostics (not required for request path) |

Low-level `session::` and WSK transport are **outside** the `Wknet.h` public aggregate; see [Internals](../internals.md).

## Default factories

| Function | Returns | Header |
|----------|---------|--------|
| `DefaultSessionConfig()` | `SessionConfig{}` | `Types.h` |
| `DefaultTlsConfig()` | `TlsConfig{}` | `Types.h` |
| `DefaultSendOptions()` | value-semantic default `SendOptions` | `Types.h` |
| `DefaultConnectConfig()` | `websocket::ConnectConfig` | `Types.h` |

Create heap options with `SendOptionsCreate` / `AsyncOptionsCreate`. Constructors of `SendOptions` / `AsyncOptions` are private.

## See also

- [Session & Config](session-config.en.md)
- [Request & Response](request-response.en.md)
- [Sync HTTP](http-sync.en.md)
- [Async HTTP](http-async.en.md)
- [WebSocket](websocket.en.md)
- [TLS options](tls-options.en.md)
- [Codec & Crypto](codec-crypto.en.md)
- [First request](../first-request.en.md)
- [Cookbook](../cookbook.en.md)
