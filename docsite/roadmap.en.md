# Roadmap & Non-Goals

Explicit boundaries help correct usage. The following are intentionally **out of scope**, **security-rejected**, or **explicit opt-in**, plus ongoing improvement directions.

**Non-goals / security rejections.** HTTP/1.1: pipelining, TRACE, inbound request parser/server role, obs-fold normalization (rejected), caller-supplied `Transfer-Encoding`/`TE` (rejected because the library owns framing). HTTP/2: PRIORITY frames, automatic background PING keepalive (explicit low-level `SendPing` exists), server push (`ENABLE_PUSH=0`; `PUSH_PROMISE` is rejected). WebSocket (fragment send + explicit `ReceiveOptions.DeliverFragments` receive-fragment delivery are supported): permessage-deflate (RFC 7692), automatic-by-default high-level WebSocket over HTTP/2 (RFC 8441 is available via explicit opt-in), handshake redirect/401/407 following (currently rejected with `STATUS_NOT_SUPPORTED`; any future support must be explicit opt-in). TLS: TLS 1.2 renegotiation (signaling only), online OCSP/CRL fetch (omitted in kernel; static entries supported). Other: HTTP/3·QUIC.

**Off by default, explicitly enable.** TLS 1.2 RSA kx / CBC / renegotiation / SHA-1 (via `TlsPolicy` + `CompatibilityExplicit`), post-handshake client auth, required revocation check, TLS 1.3 0-RTT, `Expect: 100-continue` (`SendFlagExpectContinue`), high-level h2c prior knowledge / Upgrade (`SendOptions.Http2CleartextMode`), and WebSocket over HTTP/2 (`ConnectConfig.AllowWebSocketOverHttp2`).

**Future directions.** Continue tightening protocol-safety ledgers such as timeouts, cancellation, frame/control-signal and malicious-input bounds while leaving normal buffered responses unlimited by default; reduce repeated allocations on hot paths via Workspace/lookaside/connection-resident buffers; evaluate moving WebSocket over HTTP/2 from explicit opt-in toward automatic selection with a compatibility plan; keep plaintext HTTP over proxy absolute-form separate from HTTPS CONNECT tunneling and continue auditing opaque proxy-auth forwarding.

This describes current public behavior for fit assessment; see [Capability Matrix](capability-matrix.md) for the current state.
