# Roadmap

Direction only. Full capability classification is in the [Capability Matrix](capability-matrix.en.md).

## Current main path (landed)

- Kernel client: HTTP/1.1, HTTP/2, **HTTP/3 (QUIC v1 + QPACK)**, WebSocket (including optional RFC 8441).
- Transport WSK + crypto CNG; self-implemented TLS 1.2/1.3; caller-supplied trust anchors.
- H3 default `Auto`: after learning validated Alt-Svc, later HTTPS may prefer QUIC. Proxies, cleartext HTTP, WebSocket, and `NoVerify` stay on TCP paths.
- Session owns the pool, redirects (default 10 hops), one stale retry for safe methods, and a 4-thread async queue.

## Deliberate boundaries

- **Client only**; no server / inbound parser.
- No WinHTTP / SChannel main path; no separate client layer.
- Online OCSP/CRL fetch, on-disk HTTP cache, local H2 priority scheduling, other WS extensions, and QUIC v2 / migration / multipath / WebTransport / WS-over-H3 are not supported today (see matrix section 4).
- Default-off features (pipelining, h2c, 0-RTT, legacy TLS, PING keepalive, …) are listed under “Default-off” in the matrix; they exist in code and stay off until enabled.

## Forward directions (summary)

- Keep tightening bounded defenses for timeouts, cancellation, frame/control signals, and malicious input; normal buffered responses stay without an overly low library-wide byte hard cap by default.
- Reduce repeated hot-path allocation (Workspace / lookaside / connection-resident buffers).
- Proxy paths: keep cleartext absolute-form separate from HTTPS CONNECT; audit opaque auth forwarding.
- H3/QUIC: interoperability, performance, and diagnostics. Avoid compatibility fallback layers that replace protocol design.

When assessing fit: read [Architecture](architecture.en.md), [Session & Pool](session-and-pool.en.md), and [TLS & Trust](tls-and-trust.en.md), then verify boundaries against the [Capability Matrix](capability-matrix.en.md).
