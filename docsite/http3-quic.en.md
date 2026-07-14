# HTTP/3 and QUIC

wknet's HTTP/3 client path combines WSK Datagram, QUIC v1, TLS 1.3 over QUIC, HTTP/3, and QPACK. It does not depend on MsQuic, SChannel, WinHTTP, or WinINet, and the public request entry points remain `wknet::http::Send*`.

## Connection modes

`SessionConfig.Http3.Mode` supports three modes:

- `Auto`: the default. The first HTTPS request without prior knowledge uses TCP TLS. Only an exact `h3` Alt-Svc from a certificate- and policy-verified response is cached, and a later request with the same security identity may prefer H3.
- `Disabled`: does not learn, query, or use Alt-Svc and stays on the existing TCP HTTP/1.1 or HTTP/2 path.
- `Required`: directly requires H3 for an HTTPS origin as explicit prior knowledge. It does not consume Alt-Svc and does not automatically fall back to TCP.

```cpp
wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
config.Http3.Mode = wknet::http::Http3ConnectMode::Auto;
config.Http3.Race = wknet::http::Http3RaceMode::DelayedTcpFallback;
config.Http3.RaceWindowMs = 250;
config.Http3.QuicProbeTimeoutMs = 1500;
config.Http3.AltSvcMaxEntries = 64;
config.Http3.AltSvcMaxAgeSec = 604800;
```

Plaintext HTTP, h2c, HTTP proxies, WebSocket, explicit non-HTTP ALPN, and `SendOptions.Http2Priority` never enter H3. Responses obtained with `CertPolicy::NoVerify` are not learned or used automatically.

## Alt-Svc and identity boundaries

The cache key includes origin scheme/host/port, effective TLS ServerName, certificate policy and store, TLS policy, client credential, and address-family policy. The bounded parser handles `clear`, `ma=0`, expiry, cross-host alternatives, IPv6 literals, `persist`, and multiple candidates.

When connecting to an alternative endpoint:

- DNS/UDP use the alternative host and port;
- SNI and certificate verification keep the origin's effective TLS ServerName;
- HTTP `:authority` remains the original origin;
- H3 connections are not coalesced across origins.

An alternative host therefore cannot replace the authenticated request identity.

## Fallback and replay

`DelayedTcpFallback` uses `RaceWindowMs` as the QUIC probe window, while `SequentialPreferHttp3` uses the separate `QuicProbeTimeoutMs`. H3 failure can move to TCP only while the request is provably unsent or satisfies the one-replay safety rules.

Automatic replay is limited to `GET`, `HEAD`, and `OPTIONS`, with no response started, no consumed body unless it can be rewound, and no caller prohibition. `POST`, `PUT`, `PATCH`, `DELETE`, and `CONNECT` are not replayed automatically. The request is never submitted to both H3 and TCP.

Alt-Svc broken state is scoped to a candidate and address family. Network failures use 1–60 second exponential backoff; protocol, certificate, SNI, or ALPN failures disable the candidate for the current entry lifetime. Cancellation and local resource exhaustion do not poison the cache, and network configuration changes clear broken state.

## Resource and security boundaries

QUIC packets are capped at 1200 bytes. Connections, streams, ACK ranges, sent-packet metadata, sparse CRYPTO/STREAM reassembly, CIDs, tokens, command queues, HTTP/3 field sections, QPACK dynamic tables and blocked bytes, and Alt-Svc entries/candidates all have explicit NonPaged limits and fault-injection coverage.

Logs do not expose packet/header/body bytes, URL queries, keys, IVs, nonces, tickets, Retry/NEW_TOKEN values, reset tokens, full CIDs, full origin/alternative authorities, certificate bytes, or credentials.

Representative diagnostics include:

- `quic.connection.*`, `quic.handshake.*`, `quic.loss.detected`, `quic.pto.fired`
- `http3.connection.*`, `http3.stream.*`, `qpack.*`
- `http.altsvc.stored/cleared/expired/rejected/broken`
- `http.protocol.select`, `http.connection.retry`, `http.request.failed`

## Current non-goals

The current main path does not implement QUIC v2, 0-RTT application data, active migration, multipath, ECN, DPLPMTUD, WebTransport, QUIC Datagram, Extended CONNECT over H3, or WebSocket over HTTP/3.

