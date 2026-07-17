# Async HTTP

Namespace: `wknet::http`  
Headers: `HttpAsync.h` · `AsyncOp.h` · `Options.h` · `Lifecycle.h` · `Types.h`

Non-blocking send, `AsyncOp` wait/cancel/result, and `Destroy` on the driver unload path.

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

## AsyncSend / method-specific async send

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

| Methods (Session / Request) | `*Ex` |
|-----------------------------|------|
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

- Call on the driver unload path; waits for async workers and queues to finish before resources are released.
- Call when `Async*` was used; sync-only paths may omit it.
- Do not submit new async work after `Destroy`.

## Examples

### Async GET + wait + take Response

```cpp
#include <wknet/Wknet.h>

NTSTATUS AsyncGetAndWait(wknet::http::Session* session)
{
    using namespace wknet::http;

    AsyncOp* op = nullptr;
    Response* response = nullptr;

    NTSTATUS status = AsyncGet(session, "https://example.com/", &op);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = AsyncWait(op, 30000); // milliseconds; timeout status on timeout
    if (NT_SUCCESS(status)) {
        status = AsyncGetResponse(op, &response);
    }
    if (NT_SUCCESS(status) && response != nullptr) {
        const ULONG code = ResponseStatusCode(response);
        UNREFERENCED_PARAMETER(code);
    }

    ResponseRelease(response);
    AsyncRelease(op); // also frees an untaken Response
    return status;
}
```

### Session-less async + completion callback

```cpp
static void OnComplete(void* context, NTSTATUS status)
{
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(status);
    // May run on a worker thread; avoid long blocks or IRQL raises
}

AsyncOptions* options = nullptr;
AsyncOptionsCreate(&options);
options->OnComplete = OnComplete;
options->CompletionContext = nullptr;

AsyncOp* op = nullptr;
NTSTATUS status = AsyncGetEx(
    "https://example.com/",
    sizeof("https://example.com/") - 1,
    nullptr,
    options,
    &op);
// ... AsyncWait / AsyncGetResponse ...
AsyncRelease(op);
AsyncOptionsRelease(options);
// After any Async* use, call wknet::http::Destroy() on the unload path.
```

### Cancel

```cpp
AsyncOp* op = nullptr;
NTSTATUS status = AsyncGet(session, "https://example.com/slow", &op);
if (NT_SUCCESS(status)) {
    (void)AsyncCancel(op);
    (void)AsyncWait(op, 5000); // still Wait + Release after cancel
    AsyncRelease(op);
}
```

## See also

- [Sync HTTP](http-sync.en.md)
- [Request & Response](request-response.en.md)
- [WebSocket](websocket.en.md)
- [Cookbook](../cookbook.en.md)
- [First request](../first-request.en.md)
