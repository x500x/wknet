# Async Model

Async APIs move synchronous `Send*` / WebSocket connect work onto a **fixed 4-thread** worker pool. Callers hold an opaque `AsyncOp` and finish with wait, poll, or cancel. Synchronous paths do not depend on the async runtime.

## Runtime

| Item | Value |
|------|-------|
| Workers | Fixed **4** (`AsyncWorkerCount`) |
| Queue | FIFO, max depth **256** |
| Queue full | `STATUS_INSUFFICIENT_RESOURCES` |
| Startup | CAS lazy init |

Kinds: `HttpSend`, `WebSocketConnect`. States: `Pending → Running → Completed`.

## Lifecycle

1. **Create**: `AsyncGet` / `AsyncPost` / `AsyncSend` or `wknet::websocket::ConnectAsync` → `AsyncOp*`, initially `STATUS_PENDING`, refcount 1.
2. **Enqueue**: a worker runs the op; if already canceled before run, it completes immediately with `STATUS_CANCELLED`.
3. **Wait**: `AsyncWait(op, timeoutMs)`, or poll `AsyncGetStatus` / `AsyncIsCompleted`.
4. **Take result**: HTTP via `AsyncGetResponse`; WebSocket via `wknet::websocket::AsyncGetWebSocket`.
5. **Release**: `AsyncRelease` (cleanup when the refcount hits zero).

```cpp
wknet::http::AsyncOp* op = nullptr;
NTSTATUS s = wknet::http::AsyncGetEx(session, url, urlLen, nullptr, nullptr, &op);
if (NT_SUCCESS(s) && wknet::http::AsyncWait(op, 30000) == STATUS_SUCCESS) {
    wknet::http::Response* r = nullptr;
    if (NT_SUCCESS(wknet::http::AsyncGetResponse(op, &r))) {
        // use r
        wknet::http::ResponseRelease(r);
    }
}
wknet::http::AsyncRelease(op);
```

## Reference counting and cancellation

- The user handle holds one reference; the worker holds another so the object can still observe cancellation after the user marks it closed.
- `AsyncCancel`: completes `Pending` immediately; for `Running`, forwards `Canceled` into transport waits and cancels the active IRP when supported.
- **Cancellation is cooperative**: after `AsyncCancel`, still `AsyncWait`, then `AsyncRelease`.

## Completion callbacks

`AsyncOptions.OnComplete` (and test-path completion callbacks) run when the op becomes `Completed`. Do not do heavy work or synchronously wait on the same op inside the callback; post to an upper queue instead.

## Driver unload

When async APIs were used, call `Destroy` on the unload path and wait for async work to finish before releasing WSK and other handles:

```cpp
wknet::http::Destroy();
// then release WSK / close sessions and other handles
```

Sync-only paths may skip it; calling is always safe. Sessions and related handles use reference counts and waits so a handle is not freed while an operation still uses it.

## Relation to sync APIs

| | Sync `Get*` / `Send*` | Async `Async*` |
|--|----------------------|----------------|
| Call IRQL | `PASSIVE_LEVEL` | Submit/wait at `PASSIVE_LEVEL` |
| Blocking point | Calling thread | Worker thread |
| Cancel | No public mid-flight cancel | `AsyncCancel` |
| Pool / redirect / H3 | Same session policy | Same session policy |

Async does not change protocol semantics: stale retry, redirect limits, H3 Auto, and certificate rules match the synchronous path.
