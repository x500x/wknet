# KernelHttp Wiki

**A pure kernel-mode HTTP/HTTPS client library for Windows kernel drivers**

KernelHttp is a pure kernel-mode HTTP/HTTPS client library for Windows kernel driver development. Built from the ground up, it implements a kernel-friendly client protocol stack: HTTP/1.1, HTTP/2, WebSocket, and TLS 1.2/1.3 handshake, record protection, and certificate validation.

- 🔒 **Pure kernel-mode**: no WinHTTP / WinINet / SChannel dependency
- 🌐 **WSK transport** + 🔐 **CNG/BCrypt cryptography**
- 🎯 **Two-layer API**: high-level `khttp` / `kws` and low-level `engine` (`Kh*`)
- 🔄 Connection pool, async, certificate pinning, response decoding

### 📚 Navigation

**Getting started**: [Getting Started](getting-started.md) · [Build & Test](build-and-test.md)

**Protocol reference**: [Capability Matrix](capability-matrix.md) (read first) · [Architecture](architecture.md) · [HTTP/1.1](http1.md) · [HTTP/2 & HPACK](http2.md) · [WebSocket](websocket.md) · [TLS & Certificates](tls-and-certificates.md) · [Cryptography](cryptography.md)

**API reference**: [High-Level API](high-level-api.md) · [Low-Level API](low-level-api.md) · [Configuration](configuration.md) · [Client Classes](client-classes.md) · [Transport Layer](transport-layer.md) · [NTSTATUS](ntstatus-reference.md)

**Mechanics**: [Connection Pool](connection-pool.md) · [Async Model](async-model.md) · [Memory Model](memory-model.md)

**Guides / project**: [Cookbook](cookbook.md) · [FAQ](faq.md) · [Roadmap](roadmap.md) · [Glossary](glossary.md) · [Contributing](contributing.md)
