# Architecture

## Layers

```text
wknet::http / websocket / crypto / codec
                    │
           thin http_api bridge
                    │
                 session
          ┌─────────┼─────────┐
       transport  http1/http2  ws
          │             │       │
        net            tls    codec
          └─────────────┴───────┘
                    rtl
```

- `http_api` maps parameters and wraps opaque public handles.
- `session` owns routing, redirects, proxy policy, pooling, async work, and HTTP/WebSocket orchestration.
- `transport::ITransport` is the only I/O seam used by protocol layers.
- `net` owns WSK lifecycle, resolution, sockets, and byte-stream operations.
- `tls` owns handshakes, record protection, resumption, and certificate validation.
- `http1`, `http2`, and `ws` own protocol state machines, not pooling policy.

## Request path

```text
wknet::http::SendEx
  → public argument mapping
  → session::HttpSend
  → HttpRoute / HttpProxy / ConnectionPool
  → HttpH1Dispatch or HttpH2Dispatch
  → transport::ITransport
  → WSK or TLS
```

WebSocket connections are orchestrated by `session::WsConnect`; HTTP/1.1 Upgrade and RFC 8441 share the same TLS, connection, and cancellation model.

## Ownership boundaries

- `ConnectionPool.cpp` is the sole writer of pool fields.
- Workspace and aggregate protocol buffers are heap-backed; hot buffers are retained and reused.
- `src/wknetlib` contains no `.inc` implementation fragments; responsibilities compile as independent `.cpp` units.
- There is no separate client layer or second network lifecycle.
