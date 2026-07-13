# Roadmap & Non-Goals

Explicit boundaries help correct usage. The following are intentionally **out of scope**, **security-rejected**, or **explicit opt-in**, plus ongoing improvement directions.

**Non-goals / security rejections.** HTTP/1.1: inbound request parser/server role, obs-fold normalization (rejected), caller-supplied `Transfer-Encoding`/`TE` (rejected because the library owns framing). TRACE is available only with explicit `SendFlagAllowTrace`. HTTP/2: server push (`ENABLE_PUSH=0`; `PUSH_PROMISE` is rejected). WebSocket (fragment send + explicit `ReceiveOptions.DeliverFragments` receive-fragment delivery are supported): handshake redirect/401/407 following (currently rejected with `STATUS_NOT_SUPPORTED`; any future support must be explicit opt-in). TLS: online OCSP/CRL fetch (omitted in kernel; static/provider-returned evidence supported). Other: QUIC v2, WebTransport, QUIC Datagram, and WebSocket over HTTP/3.

**In implementation, not publicly enabled.** QUIC v1 + HTTP/3 + QPACK are being implemented behind the M0-M9 gates in `docs/plans/2026-07-13-http3-quic-design.md`. Existing public `Send*` behavior is unchanged, and transparent `Http3ConnectMode::Auto` remains disabled until the protocol ledger, interoperability, kernel WSK integration, and full regression gates all pass. Development uses only an explicit required-H3 test path; incomplete paths are not treated as a production fallback architecture.

**Off by default, explicitly enable.** TLS compatibility features, post-handshake client auth, required revocation checks, TLS 1.3 0-RTT, `Expect: 100-continue`, HTTP/1.1 pipelining, h2c, HTTP/2 PING keepalive, per-request priority (`SendOptions.Http2Priority`), and WebSocket permessage-deflate.

**Future directions.** Continue tightening protocol-safety ledgers such as timeouts, cancellation, frame/control-signal and malicious-input bounds while leaving normal buffered responses unlimited by default; reduce repeated allocations on hot paths via Workspace/lookaside/connection-resident buffers; keep plaintext HTTP over proxy absolute-form separate from HTTPS CONNECT tunneling and continue auditing opaque proxy-auth forwarding.

This describes current public behavior for fit assessment; see [Capability Matrix](capability-matrix.md) for the current state.
