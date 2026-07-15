# Architecture

wknet is a **Windows kernel-mode HTTP client stack**. Public entry points are `wknet::http`, `wknet::websocket`, `wknet::crypto`, and `wknet::codec`. The transport main path is WSK; cryptography uses CNG/BCrypt. WinHTTP, WinINet, and SChannel are not used, and there is no server/inbound role.

## Layers

```text
wknet::http / websocket / crypto / codec
                    │
           thin http_api bridge
                    │
                 session
      ┌─────────────┼─────────────┐
  transport     http1/http2/http3   ws
      │              │              │
    net             tls           codec
      └──────────────┴──────────────┘
                    rtl
```

| Layer | Owns | Caller takeaway |
|-------|------|-----------------|
| Public API | Opaque handles, argument mapping, lifetime | The only stable surface |
| session | Routing, redirects, proxy, pool, async, protocol orchestration | Owns policy and pooling |
| transport | Opaque byte-stream services | Protocol layers never touch WSK IRPs directly |
| net | WSK lifecycle, resolution, sockets | Kernel sockets only |
| tls | Handshake, record protection, resumption, certificate validation | Trust anchors are caller-supplied |
| http1 / http2 / http3 / ws | Protocol state machines | Do not own pool policy |

There is no separate client layer and no second network connection lifecycle.

## Request path

```text
wknet::http::Send* / Get* / Post*
  → public argument mapping
  → session orchestration
  → route / proxy / pool / Alt-Svc
  → HTTP/1.1 | HTTP/2 | HTTP/3
  → transport → WSK or TLS (H3 is QUIC over Datagram)
```

- **HTTPS**: defaults to HTTP/1.1 or ALPN-negotiated `h2` over TCP TLS. With `Http3ConnectMode::Auto`, later requests may prefer HTTP/3 after an exact `h3` Alt-Svc is learned from a response that already passed certificate and policy checks.
- **WebSocket**: orchestrated by `session`. `wss` may use RFC 8441 (HTTP/2 extended CONNECT) or HTTP/1.1 Upgrade, sharing TLS, connection, and cancellation with HTTP.
- **HTTP/3 scope**: HTTPS without a proxy. Cleartext HTTP, h2c, WebSocket, and non-HTTP ALPN stay on the existing TCP paths.

## Ownership and buffers

- Pool fields are written only by the session pool module; pooled connections carry socket, transport, TLS, and optional H2/H3 state.
- Protocol and Workspace buffers are heap-backed; hot buffers are retained and reused.
- Synchronous HTTP / WebSocket / TLS / certificate paths require **`PASSIVE_LEVEL`**; otherwise the library returns `STATUS_INVALID_DEVICE_REQUEST` or `STATUS_INVALID_DEVICE_STATE`.
- After async APIs, call `wknet::http::Destroy()` on the driver unload path and wait for async work to finish before releasing resources.

## Caller conventions at a glance

| Point | Behavior |
|-------|----------|
| Role | Client only; no inbound parser / server |
| Main path | WSK transport, CNG crypto; WinHTTP / SChannel are not used |
| Trust | Caller-supplied anchors, CA bundles, pins, and revocation evidence; no built-in system CA store |
| Hostnames | IPs match iPAddress SAN only; DNS names do not fall back to CN |
| Redirects | HTTPS→HTTP refused by default; `MaxRedirects` defaults to 10 and exhausted hops return the current 3xx |
| TRACE | Off by default; enable with `SendFlagAllowTrace` |
| H3 Auto | Learns Alt-Svc only from HTTPS responses that already passed validation; SNI, certificate identity, and `:authority` remain bound to the origin |

Support scope and limits are documented in the [Capability Matrix](capability-matrix.en.md).
