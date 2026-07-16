# Capability matrix

This page describes what wknet supports today, what is enabled by default, and which behaviors are rejected. Sections are grouped by status for integration review.

1. **Implemented** — available now; usable under default configuration unless noted  
2. **Default-off** — implemented, but must be enabled explicitly  
3. **Policy rejection** — requests or responses rejected by protocol or security policy  
4. **Not supported** — not provided in the current release  

Scope: HTTP/HTTPS/WebSocket/SSE client. Transport main path is WSK; cryptography main path is CNG/BCrypt. WinHTTP, WinINet, and SChannel are not used. Trust anchors, CA bundles, pins, and revocation evidence are caller-supplied. Synchronous paths require `PASSIVE_LEVEL`.

---

## 1. Implemented

### HTTP/1.1 (RFC 9110/9112)

- Request bodies: `Content-Length`, library-generated chunked, streaming `BodyCreateStream` / `RequestSetBodySource`; caller-supplied `Transfer-Encoding`/`TE` is rejected.
- Request trailers: chunked path only; forbidden fields and CRLF injection rejected.
- Responses: status line HTTP/1.0/1.1 only; bounded header line/block/count; **obs-fold rejected**; multiple `Content-Length` or `TE`+`CL` conflict → `STATUS_INVALID_NETWORK_RESPONSE`.
- Body framing: CL / chunked / close-delimited; no body for 1xx, 204, 205, 304, HEAD.
- Read-only `206` / `Content-Range`; Range and conditional helpers; optional RFC 9111 in-memory cache participates in validation and partial combining.
- `Content-Encoding`: gzip/deflate/br/compress/zstd/dcz/aes128gcm/exi/pack200-gzip/identity (max two layers, reverse decode; bounded expansion).
- Interim 1xx (except 101) swallowed and reparsed; automatic redirects; keep-alive pool reuse.
- Proxy: HTTPS **CONNECT**; cleartext HTTP absolute-form; `Proxy-Authorization` only from explicit config.

### HTTP/2 (RFC 9113 + HPACK)

- Preface + SETTINGS; client `ENABLE_PUSH=0`; CONTINUATION flood guards; flow control and pseudo-header checks.
- Pooled stream leases: multiple same-origin H2 requests; DATA sliced by flow control and `MAX_FRAME_SIZE`; request trailers as final HEADERS.
- Modes: TLS ALPN `h2`; h2c prior knowledge / Upgrade are **opt-in** (next section).
- RFC 8441 extended CONNECT when peer advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` (WebSocket).
- GOAWAY/`REFUSED_STREAM` may yield `STATUS_RETRY`; high level fresh-retries safe methods once only.

### HTTP/3 + QUIC v1 + QPACK

- WSK Datagram + kernel CNG main path; QUIC v1 packets/frames, TLS 1.3 over QUIC, ACK/loss/PTO, flow control, CIDs, close state machine.
- HTTP/3: critical control/QPACK unidirectional streams, SETTINGS, HEADERS/DATA, 1xx, trailers, GOAWAY/cancel; server push is rejected.
- Default `Http3ConnectMode::Auto`: first HTTPS uses TCP; only an exact `h3` Alt-Svc from a response that already passed certificate and TLS-policy checks is cached. DNS/UDP may target the alternative; SNI, certificate checks, and `:authority` remain bound to the origin.
- HTTP/3 is not used for `CertPolicy::NoVerify`, HTTP proxies, cleartext HTTP, h2c, WebSocket, non-HTTP ALPN, or requests with `Http2Priority`.
- TCP fallback is allowed only while the request is still unsent, or when the one-replay safety rules apply.

### WebSocket (RFC 6455)

- ws/wss; **constant-time** Accept compare; subprotocols; caller opening headers (library-controlled headers rejected).
- `wss` may offer `h2,http/1.1` → RFC 8441 or fall back to HTTP/1.1 Upgrade; `ws://` never implicitly uses h2c.
- Fragmented send / optional fragment receive; auto-Pong; UTF-8/length/control-frame limits; active/passive close.
- Handshake 3xx/401/407 are **not** auto-followed → `STATUS_NOT_SUPPORTED`.

### Server-Sent Events (WHATWG event-stream)

- `wknet::sse::SseClient`: `Connect` / `Receive` / `Close`; **GET only**; default requires `Content-Type: text/event-stream`.
- Parser: partial chunks, comments, `id`/`event`/`data`/`retry`, multi-line data; `Last-Event-ID` tracking and reconnect injection.
- Auto-reconnect on by default; exponential backoff + `retry:`; **no reconnect on HTTP 4xx open**; `Close` aborts delay.
- Timeouts: separate `ConnectTimeoutMs` / body idle `IdleTimeoutMs` / per-`ReceiveTimeoutMs` (long streams are not bound to a single 30s whole-response deadline).
- Response bodies are truly incremental: when set, `SendOptions.OnBody` is invoked **multiple times** in arrival order; `finalChunk` is true only at the real end.
- First release: identity Content-Encoding; no SSE server; no POST-body SSE.

### TLS / certificates / crypto

- TLS 1.2/1.3 single-version path; no in-handshake automatic downgrade; EMS + secure renegotiation indication; CBC requires EtM.
- Certificates: bounded chains, hostnames (IP → iPAddress SAN only; DNS names do not fall back to CN), offline revocation evidence, SPKI pins, mTLS callback signatures (private keys remain with the caller).
- Crypto: CNG first; ChaCha20-Poly1305, X25519, and similar filled by in-kernel software; minimum RSA 2048.

### Session behavior (key defaults)

| Behavior | Default |
|----------|---------|
| `MaxRedirects` | **10**; exhausted hops return the current 3xx **without error** |
| HTTPS→HTTP redirect | **Rejected** |
| Stale retry | **GET/HEAD/OPTIONS** only, exactly once |
| close-delimited / 101 | **Not returned to the pool** |
| TRACE | **Off** (`SendFlagAllowTrace`) |
| Sync IRQL | **PASSIVE_LEVEL** |

---

## 2. Default-off

Features that are implemented but disabled by default, with the fields that enable them. Headers: `Types.h`, `Cache.h`, `websocket/WebSocket.h`.

| Capability | Object | Fields / usage |
|------------|--------|----------------|
| `Expect: 100-continue` | `SendOptions` | `Flags \|= SendFlagExpectContinue`; optional `ExpectContinueTimeoutMs` (default 1000) |
| TRACE | `SendOptions` | `Flags \|= SendFlagAllowTrace` (body / trailers / sensitive headers still rejected) |
| HTTP/1.1 pipeline | `SessionConfig` | `EnableHttp11Pipeline = true`; `Http11PipelineMaxDepth` (default 4, cap 64); `Http11PipelineMethodMask` (default GET\|HEAD\|OPTIONS) |
| h2c | `SendOptions` | `Http2CleartextMode = PriorKnowledge` or `Upgrade` |
| HTTP/2 PING keepalive | `SessionConfig` | `Http2KeepAlive.Enabled = true`; `IdleMs` / `IntervalMs` / `AckTimeoutMs` (defaults 30000 / 30000 / 5000) |
| HTTP/2 priority | `SendOptions` | `Http2Priority` → `Http2Priority{ StreamDependency, Weight(1..256), Exclusive }` |
| permessage-deflate | `ConnectConfig` | `PerMessageDeflate.Enable = true`; optional `Client/ServerNoContextTakeover`, `Client/ServerMaxWindowBits` (8..15) |
| TLS 1.2 compatibility / renegotiation | `TlsConfig.Policy` | `Profile = CompatibilityExplicit`, then `EnableTls12RsaKeyExchange` / `EnableTls12Cbc` / `EnableTls12Sha1Signatures` / `EnableTls12Renegotiation`; `TlsConfig.MaxTls12Renegotiations` (default 1, cap 4) |
| post-handshake client auth | `TlsConfig.Policy` | `EnablePostHandshakeClientAuth = true`, plus `TlsConfig.ClientCredential` |
| Hard revocation | `TlsConfig.Policy` | `RequireRevocationCheck = true`; caller supplies verifiable OCSP/CRL evidence |
| In-memory cache | `SessionConfig` / `SendOptions` | `CacheCreate` → `SessionConfig.Cache`; per-send `SendFlagBypassCache` / `NoCacheStore` / `OnlyIfCached` or `SendOptions.Cache` |

Examples:

```cpp
// Per send
wknet::http::SendOptions* options = nullptr;
wknet::http::SendOptionsCreate(&options);
options->Flags |= wknet::http::SendFlagExpectContinue;
options->ExpectContinueTimeoutMs = 1000;
options->Flags |= wknet::http::SendFlagAllowTrace;
options->Http2CleartextMode = wknet::http::Http2CleartextMode::PriorKnowledge;

wknet::http::Http2Priority priority = {};
priority.Weight = 16;
options->Http2Priority = &priority;

wknet::http::SendEx(session, wknet::http::Method::Get,
    url, urlLen, nullptr, nullptr, options, &response);
wknet::http::SendOptionsRelease(options);

// Session
wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
config.EnableHttp11Pipeline = true;
config.Http11PipelineMaxDepth = 4;
config.Http11PipelineMethodMask =
    wknet::http::Http11PipelineMethodGet |
    wknet::http::Http11PipelineMethodHead |
    wknet::http::Http11PipelineMethodOptions;
config.Http2KeepAlive.Enabled = true;
config.Tls.Policy.Profile = wknet::http::TlsSecurityProfile::CompatibilityExplicit;
config.Tls.Policy.EnableTls12Cbc = true;
config.Tls.Policy.RequireRevocationCheck = true;

wknet::http::Cache* cache = nullptr;
wknet::http::CacheOptions cacheOptions = {};
cacheOptions.MaxBytes = 16 * 1024 * 1024;
cacheOptions.MaxEntries = 256;
cacheOptions.Mode = wknet::http::CacheMode::Private;
wknet::http::CacheCreate(&cacheOptions, &cache);
config.Cache = cache;

wknet::http::Session* session = nullptr;
wknet::http::SessionCreate(&config, &session);

// WebSocket
wknet::websocket::ConnectConfig cfg = wknet::websocket::DefaultConnectConfig();
cfg.Url = "wss://example.com/ws";
cfg.UrlLength = 18;
cfg.PerMessageDeflate.Enable = true;
wknet::websocket::WebSocket* ws = nullptr;
wknet::websocket::ConnectEx(session, &cfg, &ws);
```

TLS 1.3 0-RTT (`EnableEarlyData` / `EarlyDataReplaySafe`) exists only on internal TLS connection options and is not mapped to `TlsConfig` / `SendOptions`, so the product HTTP API cannot enable it. HTTP/3 application-data 0-RTT is listed under “Not supported”.

---

## 3. Policy rejection

The following behaviors are rejected by design. Rejection here is policy, not a missing implementation.

| Behavior | Handling |
|----------|----------|
| Caller-written request `Transfer-Encoding` / `TE` | Rejected; the library owns framing |
| HTTP `br` as Transfer-Encoding | Rejected; `br` is Content-Encoding only |
| HTTP/2 `PUSH_PROMISE` | Protocol error |
| Unrequested/invalid WebSocket extensions | Rejected |
| Auto-follow WS handshake redirect / 401 / 407 | `STATUS_NOT_SUPPORTED` |
| In-handshake TLS 1.3→1.2 automatic downgrade | Not done; only verified evidence allows explicit upper-layer reconnect |
| Cert matching: IP via dNSName/CN; DNS via CN fallback | Not done |
| Automatic HTTPS→HTTP redirect | Rejected by default |
| Online OCSP/CRL fetch | Library never initiates |

---

## 4. Not supported

| Capability | Notes |
|------------|-------|
| HTTP server / inbound request parser | Client library; no server role |
| SSE server / POST-body SSE | Client GET event-stream only |
| On-disk persistent HTTP cache | In-memory NonPaged cache objects only |
| Local HTTP/2 priority-tree bandwidth scheduling | Not implemented |
| WebSocket extensions other than permessage-deflate | Not negotiated |
| Online revocation fetching | Library does not initiate OCSP/CRL network fetch |
| Streaming Content-Encoding on SSE/OnBody paths (gzip/br, …) | First release requires identity; architecture can grow |
| QUIC v2, H3 0-RTT application data, active migration, multipath, ECN, DPLPMTUD, WebTransport, QUIC Datagram, WebSocket over H3 | Not supported |
| WinHTTP / WinINet / SChannel as kernel main path | Not used |
| Separate client layer / second connection lifecycle | Not provided |

---

## Implementation strategy and trust model

- Transport: WSK. TLS/HTTP/certificates: kernel-path implementations.
- Cryptography: CNG/BCrypt first; gaps filled by in-kernel software.
- Trust: callers explicitly supply anchors, CA bundles, revocation evidence, and pins; the library never hard-codes system CAs.

Direction summary: [roadmap](roadmap.en.md). For capability status, use this matrix.
