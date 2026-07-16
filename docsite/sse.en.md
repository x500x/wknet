# Server-Sent Events (SSE)

`wknet::sse` is a WHATWG `text/event-stream` **client**. API shape matches WebSocket: `Connect` / `Receive` / `Close` on an existing `http::Session`.

Full signatures: [SSE API](api/sse.md).

## Summary

| Topic | Behavior |
|-------|----------|
| Method | **GET** only |
| Content-Type | Default requires `text/event-stream` (`RequireEventStreamContentType`) |
| Parse | Partial chunks, CRLF/`\n`, comments, `id`/`event`/`data`/`retry`, multi-line data |
| Last-Event-ID | Tracked by parser; reinjected on reconnect |
| Reconnect | On by default; exponential backoff + `retry:`; **no reconnect on 4xx open** |
| Timeouts | Separate `ConnectTimeoutMs` / `IdleTimeoutMs` / `ReceiveTimeoutMs` |
| Transport | Session H1/H2/H3 paths (policy-bound) |
| Non-goals | SSE server, POST-body SSE, streaming gzip/br bodies (v1) |

## Minimal example

```cpp
#include <wknet/Wknet.h>

wknet::http::Session* session = nullptr;
wknet::http::SessionCreate(nullptr, &session);

wknet::sse::ConnectConfig cfg = wknet::sse::DefaultConnectConfig();
cfg.Url = "https://example.com/events";
cfg.UrlLength = 28;

wknet::sse::SseClient* client = nullptr;
NTSTATUS st = wknet::sse::ConnectEx(session, &cfg, &client);
if (NT_SUCCESS(st)) {
    for (;;) {
        wknet::sse::Event event = {};
        st = wknet::sse::Receive(client, &event);
        if (!NT_SUCCESS(st)) {
            break;
        }
        // event fields valid until next Receive or Close
    }
    wknet::sse::Close(client);
}
wknet::http::SessionClose(session);
```

## vs whole-message HTTP

| | `Get` / `Send` | SSE `SseClient` |
|--|----------------|-----------------|
| Completion | Full response | Long-lived stream; events incrementally |
| Body | Aggregated `Response` | Not aggregated as a full Response body |
| Timeouts | Historically whole-op oriented | Split open / idle / receive |
| Retry | One connection-level `STATUS_RETRY` for safe methods | App-level reconnect + `Last-Event-ID` |

When using `SendOptions.OnBody` for generic streaming downloads, callbacks may fire **multiple times**; `finalChunk` is true only at the real end. See [Sync HTTP](api/http-sync.md).

## Reconnect semantics

1. Stream ends or recoverable network error and `AutoReconnect` → schedule delay (`retry:` or exponential backoff).  
2. Optional `OnReconnect` reports attempt / delay / lastError / lastEventId (**not** event data).  
3. New request carries `Last-Event-ID` when known; `ForceNew` connection.  
4. Open yields **4xx** → fail, **no** reconnect loop.  
5. `Close` aborts sleep and blocked `Receive`.

## Boundaries

- Library injects `Accept` / `Cache-Control` / (when present) `Last-Event-ID`; callers must not override these controlled headers.  
- Trace never logs event bodies (see [Logging](logging.md)).  
- Single-threaded `Receive` per client; concurrent Receive is undefined.  
- Scope: [Capability matrix](capability-matrix.md).
