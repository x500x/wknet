# Glossary

| Term | Meaning |
|------|---------|
| **wknet** | This library: a Windows kernel-mode HTTP/WebSocket client stack |
| **WSK** | Windows Sockets Kernel — transport main path |
| **CNG / BCrypt** | Kernel cryptography APIs — crypto main path |
| **SChannel / WinHTTP / WinINet** | System TLS/HTTP components — **not used on the main path** |
| **IRQL / PASSIVE_LEVEL** | Interrupt request level; sync HTTP/WS/TLS/cert paths require `PASSIVE_LEVEL` |
| **NTSTATUS** | Kernel return code; test with `NT_SUCCESS()` ([Errors & FAQ](errors-and-faq.en.md)) |
| **Session** | Policy and resource owner: pool, TLS defaults, proxy, H3, optional cache |
| **Connection pool** | Reuses connections by origin/TLS/proxy identity; close-delimited and 101 never return |
| **ConnPolicy** | `ReuseOrCreate` / `ForceNew` / `NoPool` |
| **Transport** | Opaque byte-stream services unifying plaintext and TLS I/O |
| **Workspace** | Session-resident reusable buffers that reduce hot-path allocation |
| **ALPN** | TLS application-layer protocol negotiation (e.g. `h2`, `http/1.1`) |
| **SNI** | TLS server-name indication |
| **h2 / h2c** | HTTP/2 over TLS / cleartext HTTP/2 (prior knowledge or Upgrade; off by default) |
| **HPACK / QPACK** | HTTP/2 / HTTP/3 header compression |
| **Alt-Svc** | Alternative service advertisement; H3 Auto learns exact `h3` **only from authenticated HTTPS responses** |
| **HTTP/3 / QUIC** | HTTP over UDP/QUIC v1; one of the default Auto main paths |
| **AEAD** | Authenticated encryption (AES-GCM, ChaCha20-Poly1305, …) |
| **Trust Anchor** | Caller-supplied trust root; the library never hard-codes system CAs |
| **SPKI pin** | Leaf Subject Public Key Info hash pin |
| **0-RTT / early data** | TLS 1.3 early data; off by default, requires replay-safe declaration |
| **chunked** | HTTP/1.1 chunked transfer encoding (library-generated request framing) |
| **close-delimited** | Response body ended by connection close — **not pooled** |
| **stale retry** | Exactly one ForceNew retry of GET/HEAD/OPTIONS after a reused-connection failure |
| **RFC 8441** | WebSocket over HTTP/2 extended CONNECT |
| **Drain / Destroy** | Unload-time drain of in-flight async work via `wknet::http::Destroy()` |
| **WDK** | Windows Driver Kit |

Capability classes: [Capability Matrix](capability-matrix.en.md).
