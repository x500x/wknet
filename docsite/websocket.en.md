# WebSocket Protocol Guide

`wknet::websocket` is the `ws` / `wss` client. For `wss`, TLS ALPN defaults to `h2,http/1.1` and prefers RFC 8441 extended CONNECT over HTTP/2; Auto falls back to HTTP/1.1 Upgrade when that path is unavailable. `ws://` does **not** implicitly use h2c.

API signatures: [WebSocket API](api/websocket.md). HTTP/2 tunnel primitive: [HTTP/2](http2.md).

## Summary

| Topic | Behavior |
|-------|----------|
| Transport | `TransportMode::Auto` (default); `Http11Only` forces H1 Upgrade |
| `wss` | Offers `h2,http/1.1` by default; h2 + `ENABLE_CONNECT_PROTOCOL` → RFC 8441 |
| Fragmented send | `Send*Ex` + `FinalFragment=false` / `SendContinuation` |
| Fragmented receive | Default: reassemble whole messages; `DeliverFragments=true` for wire fragments |
| permessage-deflate | **Opt-in**; off by default; unrequested extensions rejected |
| Close | Active: send close then wait (3s); passive: echo then close transport |
| `Message.Data` | Points at an internal buffer; valid until the **next Receive / Close** |

## Connect and handshake

```cpp
wknet::websocket::ConnectConfig cfg = wknet::websocket::DefaultConnectConfig();
cfg.Url = "wss://echo.example/ws";
cfg.UrlLength = 21;
// cfg.TransportMode = wknet::http::WebSocketTransportMode::Http11Only;
// cfg.PerMessageDeflate.Enable = true;
wknet::websocket::WebSocket* ws = nullptr;
wknet::websocket::ConnectEx(session, &cfg, &ws);
```

- `ConnectConfig.Headers` may carry `Origin` / `Authorization` / `Cookie`, etc.
- **Library-controlled headers are rejected**: `Host`, `Connection`, `Upgrade`, `Content-Length`, `Transfer-Encoding`, all `Sec-WebSocket-*`.
- `Sec-WebSocket-Accept` is compared in **constant time**; the selected subprotocol must be one that was offered.
- Opening-handshake 3xx / 401 / 407 are **not** followed by default: `STATUS_NOT_SUPPORTED` with the status preserved; other non-101 → `STATUS_INVALID_NETWORK_RESPONSE`.
- Up to 8 resolved addresses are tried; cancellation tokens apply end-to-end; sync paths require `PASSIVE_LEVEL`.

| Transport | Masking |
|-----------|---------|
| HTTP/1.1 Upgrade | Client frames are **always masked** (fresh key per frame) |
| RFC 8441 over H2 | **Unmasked** DATA tunnel per the RFC |
| Masked server frame | Protocol error → close **1002** |

## Fragmentation

### Send

- `SendText` / `SendBinary` default to whole messages with `FinalFragment=true`.
- Set `FinalFragment=false` on `*Ex` to start a fragmented message; continue with `SendContinuation` / `SendContinuationEx`.
- The library auto-chunks to the frame buffer: first frame uses the real opcode, later frames use Continuation.
- Text is validated with **incremental cross-fragment UTF-8**; an unfinished code point on the final fragment → `STATUS_INVALID_PARAMETER`.

### Receive

| `DeliverFragments` | Delivery |
|--------------------|----------|
| `false` (default) | Client-reassembled complete message; `FinalFragment=true` |
| `true` | Wire fragments: first Text/Binary, then Continuation; `FinalFragment` = real FIN |

Text still uses cross-fragment UTF-8 validation; a bad final fragment closes with **1007** / `STATUS_INVALID_NETWORK_RESPONSE`.

### `Message.Data` lifetime

`Message.Data` / `DataLength` refer to a library buffer readable until the **next successful Receive or Close on the same handle**. Copy the bytes if you need them longer.

## permessage-deflate (off by default)

- Enable with `ConnectConfig.PerMessageDeflate.Enable=true`.
- Configurable: `ClientNoContextTakeover` / `ServerNoContextTakeover` / `ClientMaxWindowBits` / `ServerMaxWindowBits` (only `8..15`).
- H1 Upgrade and RFC 8441 share the same offer/validation path; callers must not hand-write `Sec-WebSocket-Extensions`.
- Send sets RSV1 only on the first compressed Text/Binary fragment; continuations and control frames never set RSV1.
- Receive treats RSV1 on unnegotiated links, control frames, or continuations as a protocol error and closes.
- Inflate is bounded by `MaxMessageBytes`, output capacity, and expansion ratio. WebSocket extensions other than permessage-deflate are not negotiated.

## Control frames and Close

| Event | Handling |
|-------|----------|
| Ping | `AutoReplyPing` defaults on → automatic Pong |
| >100 control frames per receive | close **1008** |
| Masked frame / bad fragment state | close **1002** |
| Illegal UTF-8 (text/close) | close **1007** |
| Over `MaxMessageBytes` | close **1009** (`STATUS_BUFFER_TOO_SMALL`) |

Valid inbound close codes: 1000–1014 (except 1004/1005/1006) or 3000–4999; a close payload of length exactly 1 is a protocol error.

**Close sequencing**

1. **Active** `Close` / `CloseEx`: send close (`CloseEx` reason ≤123 bytes) → wait for peer close (default 3s; timeout/termination swallowed as success) → close transport.  
2. **Passive**: receive peer close → echo → close transport.  
3. **Concurrency**: never start new I/O on the same handle concurrently with `Close`; safest pattern is single-threaded connect→send→receive→close.

## Boundaries

- No compression by default; no default handshake redirect / 401/407 following.  
- WebSocket over HTTP/3 is not supported (see [HTTP/3](http3-quic.md)).  
- See the [capability matrix](capability-matrix.md) for support scope.
