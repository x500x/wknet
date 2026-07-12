# Logging and diagnostics

wknet uses one tiered `wknet::Trace*` logging system. The default level is `Off`; tests and `wknettest` use `Max`. Levels are inclusive: `Info`, for example, enables `Error`, `Warning`, and `Info` events.

| Level | Intended content |
| --- | --- |
| `Off` | No output. This is the product default. |
| `Error` | The current operation cannot complete, or a protocol, security, or state constraint was violated. |
| `Warning` | An anomaly occurred, but the operation can retry, switch paths, or continue cleanup. |
| `Info` | Important request, connection, TLS, session, and WebSocket lifecycle boundaries. |
| `Verbose` | Address attempts, cache/pool decisions, frame dispatch, and protocol-stage progress. |
| `Max` | High-frequency metadata such as lengths, counts, windows, algorithm identifiers, and frame headers. |

No level may expose bodies, complete header values, cookies, credentials, keys, random values, raw certificates, URL query strings, or kernel addresses.

## Components

Component filtering covers RTL, Net, Transport, TLS, Crypto, Codec, HTTP/1, HTTP/2, WebSocket, and Session. Each event belongs to exactly one accurate component.

## Correlation fields

Cross-layer events carry:

- `op`: a globally unique 64-bit OperationId;
- `conn`: a globally unique 64-bit ConnectionId;
- `stream`: the HTTP/2 StreamId, or 0 outside HTTP/2;
- `seq`: a globally increasing trace sequence.

Event names are stable lowercase dotted identifiers:

```text
http.request.start
tls.handshake.failed status=0xC0000001
http2.stream.reset stream_id=3 error_code=0x00000008
```

## Buffer model

The runtime keeps 32 resident trace slots. Each slot is exactly one page (4 KiB) and page-aligned, for approximately 128 KiB of nonpaged memory. Logging performs no per-event allocation. If every slot is busy, the event is dropped and counted without blocking networking or protocol work.

`TraceStatistics` exposes `Emitted`, `DroppedBusy`, `FormatFailures`, and `Truncated`. Oversized messages are truncated in-place and marked with `[truncated]`.

## Development check

Every new wknetlib feature must add suitable levels, components, and correlation fields. Run this before submitting changes:

```powershell
pwsh -NoLogo -NoProfile -File .\tools\check-trace-events.ps1
```

The check rejects unstable event names, caller-supplied line endings, pointer formatting, and obvious sensitive-value formatting.
