# HTTP/3 & QUIC Protocol Guide

HTTP/3 is a **main-path candidate** for HTTPS (default `Auto`): WSK Datagram + QUIC v1 + TLS 1.3 over QUIC + HTTP/3 + QPACK, with no MsQuic / SChannel / WinHTTP / WinINet dependency. Public request entry points remain `wknet::http::Send*`.

Configuration: [Session config](api/session-config.md). Support scope: [capability matrix](capability-matrix.md).

## Summary

| Topic | Behavior |
|-------|----------|
| Default mode | `Http3ConnectMode::Auto`: TCP first; learn exact `h3` Alt-Svc only from **authenticated** responses |
| `Disabled` | Do not learn, query, or use Alt-Svc; always TCP H1/H2 |
| `Required` | Prior-knowledge H3; does not consume Alt-Svc; **no** automatic TCP fallback |
| Identity boundary | Alternative changes DNS/UDP only; SNI / cert / `:authority` stay on the origin |
| Race / fallback | Move to TCP only if unsent or one safe-replay rule holds; **never** dual-submit |
| Not supported | QUIC v2, 0-RTT application data, migration, multipath, ECN, DPLPMTUD, WebTransport, Datagram, WS over H3 |

```cpp
wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
config.Http3.Mode = wknet::http::Http3ConnectMode::Auto;
config.Http3.Race = wknet::http::Http3RaceMode::DelayedTcpFallback;
config.Http3.RaceWindowMs = 250;          // probe window for DelayedTcpFallback
config.Http3.QuicProbeTimeoutMs = 1500;   // SequentialPreferHttp3
config.Http3.AltSvcMaxEntries = 64;
config.Http3.AltSvcMaxAgeSec = 604800;
```

## When H3 is selected

## Selection

HTTP/3 is used only for HTTPS origins. Under `Auto`, a cached `h3` Alt-Svc for the same security identity is required; `Required` uses H3 as prior knowledge.

The following stay on HTTP/1.1 or HTTP/2 over TCP: cleartext HTTP, h2c, HTTP proxies, WebSocket, explicit non-HTTP ALPN, and requests with `SendOptions.Http2Priority`. Responses under `CertPolicy::NoVerify` neither learn nor automatically use Alt-Svc.

## Alt-Svc and identity

The cache key includes origin scheme/host/port, effective TLS ServerName, certificate policy and store, TLS policy, client credential, and address-family policy. The bounded parser handles `clear`, `ma=0`, expiry, cross-host alternatives, IPv6 literals, `persist`, and multiple candidates.

When connecting to an alternative:

| Dimension | Value used |
|-----------|------------|
| DNS / UDP | Alternative host/port |
| SNI + certificate verification | Origin effective TLS ServerName |
| HTTP `:authority` | Original origin |
| Pool coalescing | H3 connections are **not** merged across origins |

An alternative host therefore cannot replace the authenticated request identity.

## Race, fallback, and replay

| Race mode | Timeout |
|-----------|---------|
| `DelayedTcpFallback` (default) | `RaceWindowMs` (default 250) as the QUIC probe window |
| `SequentialPreferHttp3` | `QuicProbeTimeoutMs` (default 1500) |

TCP after H3 failure is allowed only when:

1. The request is **provably unsent**, or  
2. The **one-shot** safe-replay rules hold  

**Auto-replay allowed by default**: `GET` / `HEAD` / `OPTIONS`, with no response started, no consumed body unless rewindable, and no caller prohibition.  
**Not auto-replayed**: `POST` / `PUT` / `PATCH` / `DELETE` / `CONNECT`.  
The request is **never** submitted to both H3 and TCP.

### Alt-Svc broken state

- Scope: candidate + address family  
- Network failure: 1–60 s exponential backoff  
- Protocol / certificate / SNI / ALPN failure: disable the candidate for the current entry lifetime  
- Cancellation and local resource exhaustion: **do not** poison the cache  
- Network configuration change: clear broken state  

## Protocol and resource bounds

- QUIC packets are hard-capped at 1200 bytes.
- Connections, streams, ACK ranges, sent-packet metadata, sparse CRYPTO/STREAM reassembly, CIDs, tokens, command queues, HTTP/3 field sections, QPACK dynamic tables and blocked bytes, and Alt-Svc entries/candidates all have NonPaged hard limits.
- HTTP/3: critical control/QPACK unidirectional streams, SETTINGS, HEADERS/DATA, 1xx, HEAD/204/304/CONNECT body semantics, request/response trailers, GOAWAY, and cancellation; **server push is safely refused**.
- QPACK: static/dynamic tables, blocked field sections, both instruction streams.

Logs do not expose raw packet/header/body bytes, URL queries, keys/IVs/nonces, tickets, Retry/NEW_TOKEN values, reset tokens, full CIDs, full origin/alternative authorities, certificate bytes, or credentials.

## Not supported

The current implementation does not include QUIC **v2**, **0-RTT application data**, active **migration**, **multipath**, **ECN**, **DPLPMTUD**, **WebTransport**, QUIC **Datagram**, Extended CONNECT over H3, or **WebSocket over HTTP/3**.

A separate TLS 1.3 0-RTT opt-in is not the same as HTTP/3 application-data 0-RTT.
