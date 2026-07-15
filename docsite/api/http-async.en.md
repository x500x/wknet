# Async HTTP

Namespace: `wknet::http`  
Headers: `HttpAsync.h` · `AsyncOp.h` · `Options.h` · `Lifecycle.h` · `Types.h`

## Role

Non-blocking send, `AsyncOp` wait/cancel/result, and pre-unload `Destroy` drain.

## AsyncOptions

```cpp
NTSTATUS AsyncOptionsCreate(_Out_ AsyncOptions** options) noexcept;
void AsyncOptionsRelease(_In_opt_ AsyncOptions* options) noexcept;

struct AsyncOptions final {
    SendOptions Send;
    CompletionCallback OnComplete;
    void* CompletionContext;
};
```

| Field | Default | Notes |
|-------|---------|-------|
| `Send` | `DefaultSendOptions()` | Embedded sync send options (Flags, TLS, cache, …) |
| `OnComplete` | `nullptr` | `void (*)(void* context, NTSTATUS status)` |
| `CompletionContext` | `nullptr` | Passed to `OnComplete` |

`SendOptions` fields: [Sync HTTP](http-sync.en.md).

## AsyncSend / method helpers

### Signatures

```cpp
NTSTATUS AsyncSend(
    _In_ Session* session,
    Method method,
    _In_z_ const char* url,
    _In_opt_ const Headers* headers,
    _In_opt_ const Body* body,
    _In_opt_ const AsyncOptions* options,
    _Out_ AsyncOp** operation) noexcept;

NTSTATUS AsyncSendEx(
    _In_ Session* session,
    Method method,
    _In_reads_bytes_(urlLength) const char* url,
    SIZE_T urlLength,
    _In_opt_ const Headers* headers,
    _In_opt_ const Body* body,
    _In_opt_ const AsyncOptions* options,
    _Out_ AsyncOp** operation) noexcept;
```

Also `Request*`-leading `AsyncSend` / `AsyncSendEx`.

| Short (Session / Request) | Ex |
|---------------------------|----|
| `AsyncGet` / `AsyncHead` / `AsyncDelete` / `AsyncTrace` | `*Ex(..., headers, options, operation)` |
| `AsyncPost` / `AsyncPut` / `AsyncPatch` | `*Ex(..., headers, body, options, operation)` |
| `AsyncOptionsRequest` | `AsyncOptionsRequestEx` (avoids clash with type `AsyncOptions`) |

### Parameters

| Param | Meaning |
|-------|---------|
| `options` | Optional; `nullptr` uses default `AsyncOptions` |
| `operation` | Out `AsyncOp*`; caller `AsyncRelease` |

### Returns

| Status | Meaning |
|--------|---------|
| `STATUS_SUCCESS` | Queued; completion tracked on `AsyncOp` |
| `STATUS_INVALID_PARAMETER` | Bad args |
| `STATUS_INVALID_DEVICE_REQUEST` | Not `PASSIVE_LEVEL` |
| `STATUS_INSUFFICIENT_RESOURCES` | Queue/alloc failure |

`Body` / `Headers` pointers must live until complete or cancel.

## AsyncOp

### Signatures

```cpp
NTSTATUS AsyncWait(_In_ AsyncOp* operation, ULONG timeoutMs) noexcept;
NTSTATUS AsyncCancel(_In_ AsyncOp* operation) noexcept;
NTSTATUS AsyncGetStatus(_In_opt_ const AsyncOp* operation) noexcept;
bool AsyncIsCompleted(_In_opt_ const AsyncOp* operation) noexcept;
bool AsyncIsCanceled(_In_opt_ const AsyncOp* operation) noexcept;
NTSTATUS AsyncGetResponse(_In_ AsyncOp* operation, _Out_ Response** response) noexcept;
void AsyncRelease(_In_opt_ AsyncOp* operation) noexcept;
```

### Parameters / returns

| API | Notes |
|-----|-------|
| `AsyncWait` | Wait up to `timeoutMs`; timeout returns a timeout status |
| `AsyncCancel` | Request cancellation |
| `AsyncGetStatus` | Last completion status |
| `AsyncIsCompleted` / `AsyncIsCanceled` | Flags; null → `false` |
| `AsyncGetResponse` | Take `Response*` ownership after successful completion |
| `AsyncRelease` | Free op; drops untaken response |

### Notes

- Completion callbacks may run on worker threads; avoid long blocks or IRQL raises.
- Call `AsyncGetResponse` once after successful completion.
- WebSocket async connect shares `AsyncOp`; see `AsyncGetWebSocket` in [WebSocket](websocket.en.md).

## Destroy

```cpp
// Lifecycle.h
void Destroy() noexcept;
```

### Notes

- Drains async workers/queues for driver unload.
- Required before unload if any `Async*` path was used.
- Sync-only paths may skip; unconditional call is fine.
- Do not submit new async work after `Destroy`.

## See also

- [Sync HTTP](http-sync.en.md)
- [Request & Response](request-response.en.md)
- [WebSocket](websocket.en.md)
- [Cookbook](../cookbook.en.md)
