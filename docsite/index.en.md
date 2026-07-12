# wknet

**An HTTP/HTTPS/WebSocket client library for Windows kernel drivers**

wknet uses WSK as its kernel transport path and CNG/BCrypt for cryptography. It implements HTTP/1.1, HTTP/2, WebSocket, TLS 1.2/1.3, certificate validation, and content codecs.

- Public APIs: `wknet::http`, `wknet::websocket`, `wknet::crypto`, `wknet::codec`
- Internal layers: `rtl`, `net`, `tls`, `http1`, `http2`, `ws`, `transport`, `session`
- Tracing defaults to Off; tests and wknettest select Max
- Public headers live only under `include/wknet`; implementation headers remain source-local
- There is no parallel client-class or compatibility API

## Navigation

- [Getting started](getting-started.md) · [Build and test](build-and-test.md)
- [Capability matrix](capability-matrix.md) · [Architecture](architecture.md)
- [HTTP/1.1](http1.md) · [HTTP/2](http2.md) · [WebSocket](websocket.md)
- [TLS and certificates](tls-and-certificates.md) · [Cryptography](cryptography.md)
- [Product API](high-level-api.md) · [Internal interface boundaries](low-level-api.md)
- [Module boundaries](client-classes.md) · [Transport](transport-layer.md)
- [Connection pool](connection-pool.md) · [Async model](async-model.md) · [Memory model](memory-model.md)
