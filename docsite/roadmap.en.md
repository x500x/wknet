# Roadmap & Non-Goals

Explicit boundaries help correct usage. The following are intentionally **out of scope** or **deferred**, plus ongoing improvement directions.

**Non-goals.** HTTP/1.1: `Expect: 100-continue` (rejected), pipelining, TRACE, streaming upload, zero-aggregation streaming response delivery (incremental `OnBody` callbacks exist, responses may still aggregate), obs-fold (rejected). HTTP/2: PRIORITY frames, automatic background PING keepalive (explicit low-level `SendPing` exists), h2c at high-level khttp. WebSocket (fragment send + receive-fragment callback are supported): permessage-deflate (RFC 7692), automatic-by-default high-level WebSocket over HTTP/2 (RFC 8441 is available via explicit opt-in), handshake redirect/401 following. Proxy: plaintext HTTP over proxy (HTTPS CONNECT is supported via high-level Session config and low-level `HttpsClient` options). TLS: TLS 1.2 renegotiation (signaling only), online OCSP/CRL fetch (omitted in kernel; static entries supported), 0-RTT (implemented, off by default). Other: HTTP/3·QUIC, server/inbound request parsing.

**Off by default, explicitly enable.** TLS 1.2 RSA kx / CBC / renegotiation / SHA-1 (via `TlsPolicy` + `CompatibilityExplicit`), post-handshake client auth, required revocation check, TLS 1.3 0-RTT.

**Future directions.** Continue tightening protocol-safety ledgers such as timeouts, cancellation, frame/control-signal and malicious-input bounds while leaving normal buffered responses unlimited by default; reduce repeated allocations on hot paths via Workspace/lookaside/connection-resident buffers; evaluate moving WebSocket over HTTP/2 from explicit opt-in toward automatic selection with a compatibility plan.

This describes current public behavior for fit assessment; see [Capability Matrix](capability-matrix.md) for the current state.
