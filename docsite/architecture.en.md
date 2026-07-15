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

- **Default HTTPS path**: HTTP/1.1 or ALPN `h2` over TCP TLS. With default `Http3ConnectMode::Auto`, exact `h3` Alt-Svc learned from authenticated responses can prefer HTTP/3 on later requests.
- **WebSocket**: orchestrated by session; `wss` may use RFC 8441 (HTTP/2 extended CONNECT) or HTTP/1.1 Upgrade, sharing TLS, connection, and cancellation models.
- **Cleartext HTTP / h2c / proxy / WebSocket / non-HTTP ALPN** never select HTTP/3.

## Ownership and buffers

- Pool fields are written only by the session pool module; pooled connections carry socket, transport, TLS, and optional H2/H3 state.
- Protocol and Workspace buffers are heap-backed; hot buffers are retained and reused.
- Synchronous HTTP / WebSocket / TLS / certificate paths require **`PASSIVE_LEVEL`**; otherwise the library returns `STATUS_INVALID_DEVICE_REQUEST` or `STATUS_INVALID_DEVICE_STATE`.
- Before unload: if async APIs were used, call `wknet::http::Destroy()` first to drain in-flight work.

## Hard constraints (caller contract)

| Constraint | Meaning |
|------------|---------|
| Client only | No inbound request parser / server role |
| WSK + CNG | Transport and crypto main paths; no WinHTTP / SChannel |
| Caller trust anchors | The library never hard-codes system CAs |
| Hostname matching | IP literals match iPAddress SAN only; DNS names **never fall back to CN** |
| Redirects | HTTPS→HTTP is rejected by default; `MaxRedirects` defaults to 10 and exhausted hops return the current 3xx without error |
| TRACE | Off by default; requires `SendFlagAllowTrace` |
| H3 Auto | Learns Alt-Svc only from **authenticated** HTTPS responses; SNI, certificate identity, and `:authority` stay bound to the origin |

Capability classes (implemented / default-off / security refusal / non-goal) live in the [Capability Matrix](capability-matrix.en.md).
