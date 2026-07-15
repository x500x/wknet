# HTTP/2 Protocol Guide

HTTP/2 is the default secure multiplexed path over TLS ALPN `h2`. Same-origin pools reuse one connection via stream leases. Server push is unsupported; h2c, background PING, and per-request priority are explicit capabilities.

Public entry points: [HTTP sync](api/http-sync.md) / [Session config](api/session-config.md). WebSocket tunnels: [WebSocket](websocket.md).

## Summary

| Topic | Behavior |
|-------|----------|
| Default path | TLS ALPN `h2` (`PreferHttp2` defaults true) |
| h2c | **Opt-in**: `SendOptions.Http2CleartextMode` = `PriorKnowledge` or `Upgrade` |
| Multiplexing | One same-origin H2 connection carries multiple active requests; limited by local and peer `MAX_CONCURRENT_STREAMS` |
| Server push | **Unsupported**; any `PUSH_PROMISE` is a protocol error |
| Extended CONNECT | RFC 8441; default for `wss` (see WebSocket) |
| GOAWAY / RST | Untreated streams may map to `STATUS_RETRY`; safe methods get one fresh retry |
| Background PING | Session `Http2KeepAlive.Enabled` defaults **off** |
| Priority | Explicit `SendOptions.Http2Priority`; no local dependency-tree scheduler |

## Connection and SETTINGS

- Client sends the preface and SETTINGS with `ENABLE_PUSH=0`; ACKs immediately without blocking on the peer ACK.
- Peer `ENABLE_PUSH != 0`, illegal window/frame sizes, or illegal `ENABLE_CONNECT_PROTOCOL` → protocol/flow-control error.
- Missing ACK plus a later read timeout → GOAWAY `SETTINGS_TIMEOUT`.
- CONTINUATION flood guards: ≤64 frames, ≤4 empty frames (CVE-2024-27316 class).
- Accumulated header block over capacity → `ENHANCE_YOUR_CALM` / `STATUS_BUFFER_TOO_SMALL`.
- Connection-specific headers (`connection`/`transfer-encoding`/`upgrade`, …) are forbidden; `te` may only be `trailers`.

## Streams and body

- The pool grants stream leases on same-origin H2 connections; the frame loop demuxes HEADERS/DATA/WINDOW_UPDATE/RST by stream id.
- Request bodies are driven by a body source and sliced into DATA under `min(connection send window, stream remote window, peer MaxFrameSize)`.
- Request trailers: after the body, trailing HEADERS + END_STREAM (an HTTP/2 header block, separate from HTTP/1.1 chunked trailers); trailer pseudo-headers rejected; forbidden fields align with HTTP/1.1.
- Flow control: connection + per-stream; `InitialWindowSize` updates apply to active streams; overflow → `FLOW_CONTROL_ERROR`.
- 1xx interim: reject `:status 101` and interim+END_STREAM; other interim responses reset and continue to the final response.

## RFC 8441 extended CONNECT

- Shape: `:method: CONNECT` + `:protocol: websocket`.
- Requires peer `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`; otherwise `STATUS_NOT_SUPPORTED` and no stream is allocated.
- After a `2xx` response, bidirectional DATA carries tunnel payload.
- This is the HTTP/2 tunnel primitive; `wknet::websocket` selects it by default for `wss`, or forces HTTP/1.1 Upgrade with `Http11Only`.

## GOAWAY / RST and retry

| Condition | High-level semantics |
|-----------|----------------------|
| Clean GOAWAY and active stream id > lastStreamId | Stream **untreated** → `STATUS_RETRY` |
| `REFUSED_STREAM` and provably untreated | `STATUS_RETRY` |
| Non-zero GOAWAY error / other RST | Connection-disconnected failure |

The high-level layer performs **one** fresh retry only for **safe methods** (`GET`/`HEAD`/`OPTIONS`); non-idempotent methods with a body are not auto-replayed. Connection-level errors fan out to active streams.

## h2c (off by default)

| Mode | Notes |
|------|-------|
| `PriorKnowledge` | Cleartext HTTP/2 preface + SETTINGS |
| `Upgrade` | HTTP/1.1 Upgrade; **no request body**; reserves stream 1 and replays post-101 residual bytes |
| Default | `http://` does **not** auto-select h2c |

Mutually exclusive with HTTP/3 selection: explicit non-HTTP ALPN and HTTP/2 priority requests never enter H3 (see [HTTP/3 & QUIC](http3-quic.md)).

## Priority and PING

- **Priority**: `SendOptions.Http2Priority` attaches weight/dependency/exclusive on the first HEADERS (weight 1..256); self-dependency rejected. Complex local priority-tree scheduling is a non-goal.
- **Background PING**: enable with `SessionConfig.Http2KeepAlive.Enabled=true`; only idle reusable pooled H2 connections are scanned; ACK timeout or protocol error closes that idle connection. Defaults: idle/interval 30s, ACK timeout 5s.

## HPACK (behavioral bounds)

- Dynamic-table size updates only at the start of a block and ≤ negotiated size; header-list size is `name+value+32`.
- Encoder forces **Never-Indexed** for `authorization` / `cookie` / `proxy-authorization`.
- Huffman rejects overlong codes / EOS / illegal padding.

## Default-off checklist

| Capability | How to enable |
|------------|----------------|
| h2c | `SendOptions.Http2CleartextMode` |
| Background PING | `Http2KeepAlive.Enabled=true` |
| Per-request priority | `SendOptions.Http2Priority` |

Capability wording follows the [Capability matrix](capability-matrix.md).
