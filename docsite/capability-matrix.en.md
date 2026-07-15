# Capability Matrix

Capabilities are booked in four classes. Keep them separate when you read:

1. **Implemented** — available by default, or as the documented default  
2. **Default-off** — present in code; must be turned on explicitly  
3. **Security refusal** — blocked on purpose by policy  
4. **Non-goal** — not offered, and not planned as a compatibility shim  

Hard constraints: client only; WSK + CNG; no WinHTTP/SChannel; no separate client layer; caller-supplied trust anchors; `PASSIVE_LEVEL` on synchronous paths.

---

## 1. Implemented

### HTTP/1.1 (RFC 9110/9112)

- Request bodies: `Content-Length`, library-generated chunked, streaming `BodyCreateStream` / `RequestSetBodySource`; caller-supplied `Transfer-Encoding`/`TE` is a **security refusal**.
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
- HTTP/3: critical control/QPACK unidirectional streams, SETTINGS, HEADERS/DATA, 1xx, trailers, GOAWAY/cancel; **server push is a security refusal**.
- **Default `Http3ConnectMode::Auto`**: first HTTPS uses TCP; exact `h3` Alt-Svc learned only from **authenticated** responses; alternatives affect DNS/UDP only while SNI/cert/`authority` stay origin-bound.
- Never selects H3: `NoVerify`, proxy, cleartext HTTP, h2c, WebSocket, non-HTTP ALPN, HTTP/2 priority.
- TCP fallback only while the request is unsent or satisfies the **one-replay** safety rules.

### WebSocket (RFC 6455)

- ws/wss; **constant-time** Accept compare; subprotocols; caller opening headers (library-controlled headers rejected).
- `wss` may offer `h2,http/1.1` → RFC 8441 or fall back to HTTP/1.1 Upgrade; `ws://` never implicitly uses h2c.
- Fragmented send / optional fragment receive; auto-Pong; UTF-8/length/control-frame limits; active/passive close.
- Handshake 3xx/401/407 are **not** auto-followed → `STATUS_NOT_SUPPORTED`.

### TLS / certificates / crypto

- TLS 1.2/1.3 single-version path; no in-handshake automatic downgrade; EMS + secure renegotiation indication; CBC requires EtM.
- Certificates: bounded chains, hostnames (IP → iPAddress SAN only; **DNS never falls back to CN**), offline revocation evidence, SPKI pins, mTLS callback signatures (private keys never enter the library).
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

## 2. Default-off (explicit opt-in)

| Capability | How to enable |
|------------|---------------|
| `Expect: 100-continue` | `SendFlagExpectContinue` |
| HTTP/1.1 pipelining | `EnableHttp11Pipeline=true` (default methods GET/HEAD/OPTIONS) |
| h2c prior knowledge / Upgrade | `SendOptions.Http2CleartextMode` |
| HTTP/2 PING keepalive | `Http2KeepAlive.Enabled=true` |
| HTTP/2 per-request priority | `SendOptions.Http2Priority` |
| WebSocket permessage-deflate | `PerMessageDeflate.Enable=true` |
| TLS 1.2 RSA-kx / CBC / SHA-1 / renegotiation | `CompatibilityExplicit` + matching switches |
| TLS 1.3 0-RTT | `EnableEarlyData` + `EarlyDataReplaySafe` |
| TLS 1.3 post-handshake client auth | `EnablePostHandshakeClientAuth` |
| Hard revocation requirement | `RequireRevocationCheck` |
| TRACE method | `SendFlagAllowTrace` |
| RFC 9111 in-memory cache | Caller creates and attaches `SessionConfig.Cache` / send options |

---

## 3. Security refusals / policy constraints

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

## 4. Explicit non-goals

| Capability | Conclusion |
|------------|------------|
| HTTP server / inbound request parser | Non-goal (client only) |
| On-disk persistent HTTP cache | Non-goal (in-memory NonPaged cache objects only) |
| Local HTTP/2 priority-tree bandwidth scheduling | Non-goal |
| WebSocket extensions other than permessage-deflate | Non-goal |
| Online revocation fetching | Non-goal |
| QUIC v2, H3 0-RTT application data, active migration, multipath, ECN, DPLPMTUD, WebTransport, QUIC Datagram, WebSocket over H3 | Non-goal |
| WinHTTP / WinINet / SChannel as kernel main path | Non-goal |
| Separate client layer / second connection lifecycle | Non-goal |

---

## Implementation strategy and trust model

- Transport: WSK. TLS/HTTP/certificates: kernel-path implementations.
- Cryptography: CNG/BCrypt first; gaps filled by in-kernel software.
- Trust: callers explicitly supply anchors, CA bundles, revocation evidence, and pins; the library never hard-codes system CAs.

Direction summary: [roadmap](roadmap.en.md). For capability status, use this matrix.
