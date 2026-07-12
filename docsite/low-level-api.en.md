# Internal Interface Boundaries

wknet guarantees only the public API under `include/wknet`. Interfaces under `src/wknetlib` exist for internal layering and user-mode protocol tests; they are not an installable ABI and product callers must not include them.

## Internal services

| Layer | Representative interfaces | Responsibility |
|---|---|---|
| `session` | `HttpSend`, `WsConnect`, `ConnectionPool*` | Product policy and orchestration |
| `transport` | `ITransport`, `WskTransport`, `TlsTransport`, `ProxyConnect` | Byte-stream adapters and proxy tunnels |
| `http1` | request builder, response parser, transfer coding | HTTP/1.x protocol logic |
| `http2` | `Http2Connection`, HPACK, frames, streams | HTTP/2 state machine |
| `ws` | frames, handshake validation, permessage-deflate | WebSocket protocol logic |
| `tls` | `TlsConnection`, records, certificate validation | TLS and trust decisions |
| `net` | `WskClient`, `WskSocket` | WSK capabilities |

## Test hooks

User-mode tests may inject transports, IRQL, or async scheduling only through the narrow `WKNET_USER_MODE_TEST` surface in `include/wknet/test/Test.h`. Test hooks are not part of the normal `Wknet.h` product path.

## Constraints

- Public bridges do not include `net/WskSocket.h` or `tls/TlsConnection.h`.
- Protocol layers do not modify connection-pool fields directly.
- Internal headers are not copied into `include/wknet`.
- Parallel handle APIs, client classes, and compatibility layers are not restored.
