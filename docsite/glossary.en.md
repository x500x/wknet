# Glossary

| Term | Meaning |
|------|---------|
| **WSK** | Windows Sockets Kernel — the network main path |
| **CNG / BCrypt** | Kernel cryptography — the crypto main path |
| **SChannel** | System TLS; **not** used here (TLS is self-implemented) |
| **IRQL / PASSIVE_LEVEL** | Interrupt Request Level; sync HTTP/WS/TLS/cert paths require `PASSIVE_LEVEL` |
| **NTSTATUS** | Kernel return code; test with `NT_SUCCESS()` |
| **Transport** | Opaque byte-stream services for plaintext/TLS |
| **Workspace** | Session-resident reusable buffers |
| **HeapObject / HeapArray** | RAII heap wrappers replacing raw new/delete |
| **Connection pool** | Connection reuse keyed by `session::ConnectionPoolKey` |
| **Public API** | `wknet::http` / `wknet::websocket` / `wknet::crypto` / `wknet::codec` |
| **ALPN / SNI** | Protocol negotiation (`h2`/`http/1.1`) / target hostname in TLS |
| **h2 / h2c** | HTTP/2 over TLS / cleartext HTTP/2 |
| **HPACK** | HTTP/2 header compression (RFC 7541) |
| **AEAD / HKDF / ECDHE** | Authenticated encryption / HMAC key derivation / ephemeral DH |
| **SPKI pin / Trust Anchor** | Public-key-hash pinning / trusted chain root |
| **0-RTT / Session Ticket** | TLS 1.3 early data (off by default) / resumption ticket |
| **chunked / close-delimited** | HTTP/1.1 chunked encoding / body ended by connection close (not pooled) |
| **Drain** | Internal unload-time wait for in-flight async work |
| **WDK** | Windows Driver Kit |
