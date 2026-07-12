# Transport Layer

### Opaque `Transport` services

`transport/Transport.h` declares only the incomplete `Transport` type and service functions for plaintext/callback creation, TLS wrapping, send, receive, timed receive, state queries, and close. The operation table and contexts live in `TransportPrivate.hpp` and are never included across module boundaries.

The production path is: opaque `WskSocket*` → opaque `Transport*` → for HTTPS the same transport service uses an opaque `TlsConnection*` → HTTP/1.1, HTTP/2, or WebSocket. `ITransport`, `WskTransport`, and `TlsTransport` have been removed without compatibility aliases.

### Scratch allocation

Scratch allocation belongs to `rtl`. `WorkspaceScratchAllocator` obtains heap-backed request Workspace memory; protocol aggregate buffers do not live on the kernel stack, and hot buffers are retained for reuse.

### WSK layer

- `WskClient.h` exposes only Create/Initialize/ResolveAll/Shutdown/Close services for opaque `WskClient*`.
- `WskSocket.h` exposes only Create/Connect/Send/Receive/Close/Destroy services for opaque `WskSocket*`.
- Layouts live in `WskClientPrivate.hpp` and `WskSocketPrivate.hpp` and are owned by `net`.
- Resolution caching remains bounded to 16 entries with a five-minute TTL; an empty `AF_UNSPEC` result triggers explicit IPv4 and IPv6 queries.
- WSK owns cancellation, timeout handling, and outstanding-I/O drain.

### Test transport

`WKNET_USER_MODE_TEST` uses the callback backend for deterministic byte streams. Tests consume the same opaque `Transport` services and do not implement a parallel transport interface.
