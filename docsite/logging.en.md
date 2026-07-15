# Logging and diagnostics

wknet uses one tiered `wknet::Trace*` system. **Product default is `Off`**; tests and `wknettest` use `Max`. Levels are inclusive: `Info` enables Error / Warning / Info.

| Level | Content |
|-------|---------|
| `Off` | No output (product default) |
| `Error` | Operation cannot complete, or a protocol/security/state constraint failed |
| `Warning` | Anomaly with retry, path switch, or continued cleanup |
| `Info` | Key request, connection, TLS, session, and WebSocket lifecycle boundaries |
| `Verbose` | Address attempts, cache/pool decisions, frame dispatch, protocol stages |
| `Max` | High-frequency metadata: lengths, counts, windows, algorithm ids, frame headers |

No level may emit bodies, complete header values, cookies, credentials, keys, random values, raw certificates, URL queries, or kernel addresses.

## Components

Filter by RTL, Net, Transport, TLS, Crypto, Codec, HTTP/1, HTTP/2, HTTP/3, QUIC, WebSocket, Session, and related components. Each event belongs to exactly one accurate component.

## Correlation fields

Cross-layer events carry:

- `op`: globally unique 64-bit OperationId
- `conn`: globally unique 64-bit ConnectionId
- `stream`: HTTP/2 StreamId, or 0 outside HTTP/2
- `seq`: globally increasing sequence

Event names are stable lowercase dotted identifiers, for example:

```text
http.request.start
tls.handshake.failed status=0xC0000001
http2.stream.reset stream_id=3 error_code=0x00000008
quic.handshake.completed
http.altsvc.stored
```

## Buffer model

The runtime keeps a fixed set of resident, page-aligned NonPaged trace slots and does **not** allocate per event. When all slots are busy, events are dropped and counted without blocking network/protocol work. `TraceStatistics` exposes Emitted / DroppedBusy / FormatFailures / Truncated.

## Development check

Every new `wknetlib` feature must add suitable levels, components, and correlation fields. Before submit:

```powershell
pwsh -NoLogo -NoProfile -File .\tools\check-trace-events.ps1
```

The check rejects unstable event names, caller-supplied line endings, pointer formatting, and obvious sensitive-value formatting.
