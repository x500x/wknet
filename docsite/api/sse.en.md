# SSE API

Namespace: `wknet::sse`  
Headers: `wknet/sse/Sse.h` · types live in `Sse.h` (alongside `wknet/http/Types.h` patterns)

`Connect` / `Receive` / `Close` on an existing `http::Session`. WHATWG `text/event-stream` client: parse events, track `Last-Event-ID`, optional auto-reconnect.

## ConnectConfig

```cpp
ConnectConfig DefaultConnectConfig() noexcept;

struct ConnectConfig final {
    const char* Url = nullptr;
    SIZE_T UrlLength = 0;
    const Header* Headers = nullptr;
    SIZE_T HeaderCount = 0;
    wknet::http::TlsConfig Tls = {};
    wknet::http::AddressFamily Family = wknet::http::AddressFamily::Any;

    const char* LastEventId = nullptr;
    SIZE_T LastEventIdLength = 0;

    bool AutoReconnect = true;
    ULONG MaxReconnectAttempts = 0;       // 0 = unlimited until Close
    ULONG InitialReconnectDelayMs = 1000;
    ULONG MaxReconnectDelayMs = 30000;

    ULONG ConnectTimeoutMs = 30000;
    ULONG IdleTimeoutMs = 0;              // 0 = no body idle limit
    ULONG ReceiveTimeoutMs = 0;           // 0 = no single Receive wait limit

    SIZE_T MaxEventBytes = 1 * 1024 * 1024;
    SIZE_T MaxParserBufferBytes = 256 * 1024;

    bool RequireEventStreamContentType = true;

    EventCallback OnEvent = nullptr;
    ReconnectCallback OnReconnect = nullptr;
    void* CallbackContext = nullptr;
};
```

| Field | Notes |
|-------|-------|
| `Url` / `UrlLength` | `http://` or `https://` stream endpoint (**GET only**) |
| `Headers` / `HeaderCount` | Caller opening headers (e.g. `Authorization`); library-controlled `Accept` / `Last-Event-ID` / `Cache-Control` conflicts are rejected |
| `Tls` / `Family` | HTTPS TLS and address family |
| `LastEventId` | Initial `Last-Event-ID` (optional) |
| `AutoReconnect` | Reconnect after disconnect; **4xx open failures never reconnect** |
| `MaxReconnectAttempts` | `0` means until `Close` |
| `InitialReconnectDelayMs` / `MaxReconnectDelayMs` | Exponential backoff; honors server `retry:` |
| `ConnectTimeoutMs` | Wait for response headers / open |
| `IdleTimeoutMs` | Idle gap between body bytes; `0` disables |
| `ReceiveTimeoutMs` | Per-`Receive` wait; `0` unlimited |
| `MaxEventBytes` / `MaxParserBufferBytes` | Per-event and parser buffer caps |
| `RequireEventStreamContentType` | Require `Content-Type` prefix `text/event-stream` |
| `OnEvent` / `OnReconnect` | Optional callbacks on the delivery path |

### Helper types

```cpp
struct Event final {
    const char* Type = nullptr; SIZE_T TypeLength = 0;  // default "message"
    const char* Data = nullptr; SIZE_T DataLength = 0;  // multi-line data joined with \n
    const char* Id   = nullptr; SIZE_T IdLength = 0;
};

struct Header final {
    const char* Name = nullptr; SIZE_T NameLength = 0;
    const char* Value = nullptr; SIZE_T ValueLength = 0;
};

typedef NTSTATUS (*EventCallback)(void* context, const Event* event);
typedef void (*ReconnectCallback)(
    void* context, ULONG attempt, ULONG delayMs, NTSTATUS lastError,
    const char* lastEventId, SIZE_T lastEventIdLength);

struct ReceiveOptions final {
    SIZE_T MaxEventBytes = 0;
    EventCallback OnEvent = nullptr;
    void* CallbackContext = nullptr;
};
```

## Connect

```cpp
NTSTATUS Connect(
    _In_ wknet::http::Session* session,
    _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength,
    _Out_ SseClient** client) noexcept;

NTSTATUS Connect(
    _In_ wknet::http::Session* session,
    _In_ const ConnectConfig* config,
    _Out_ SseClient** client) noexcept;

NTSTATUS ConnectEx(
    _In_ wknet::http::Session* session,
    _In_ const ConnectConfig* config,
    _Out_ SseClient** client) noexcept;

NTSTATUS ConnectAsync(...);           // returns AsyncOp*
NTSTATUS ConnectAsyncEx(...);
NTSTATUS AsyncGetSseClient(
    _In_ wknet::http::AsyncOp* operation,
    _Out_ SseClient** client) noexcept;
```

On success `*client` is open: 2xx received and (if required) `Content-Type` accepted. The library injects `Accept: text/event-stream` and `Cache-Control: no-cache`; injects `Last-Event-ID` when known.

| Typical failure | Meaning |
|-----------------|---------|
| `STATUS_INVALID_PARAMETER` | Illegal URL/headers/family, or caller overrode library-controlled headers |
| `STATUS_INVALID_NETWORK_RESPONSE` | Non event-stream Content-Type when required |
| `STATUS_ACCESS_DENIED` | HTTP 4xx (**no auto-reconnect**) |
| `STATUS_IO_TIMEOUT` | Open timeout |

## Receive

```cpp
NTSTATUS Receive(_In_ SseClient* client, _Out_ Event* event) noexcept;
NTSTATUS ReceiveEx(
    _In_ SseClient* client,
    _In_opt_ const ReceiveOptions* options,
    _Out_opt_ Event* event) noexcept;
```

Blocks until:

1. A full event is ready → `STATUS_SUCCESS`; `Event` fields point at **client-owned storage** (valid until next successful Receive / Close); or  
2. Stream ended and reconnect is not attempted / exhausted → disconnect or final error; or  
3. `ReceiveTimeoutMs` elapsed → `STATUS_IO_TIMEOUT`; or  
4. `Close` → `STATUS_CANCELLED`.

Default type is `"message"`. Multi-line `data:` lines are joined with `\n`. `id:` updates last-event-id (ids containing `\0` are ignored per WHATWG). `retry:` affects reconnect delay.

## Query / Close

```cpp
NTSTATUS GetLastEventId(
    _In_ SseClient* client,
    _Outptr_result_bytebuffer_(*idLength) const char** id,
    _Out_ SIZE_T* idLength) noexcept;

NTSTATUS GetReconnectAttempt(
    _In_ SseClient* client,
    _Out_ ULONG* attempt) noexcept;

NTSTATUS Close(_In_opt_ SseClient* client) noexcept;
```

`Close` accepts `nullptr` and aborts a blocked `Receive` and reconnect delay. The handle is invalid after close.

## Behavior notes

| Topic | Behavior |
|-------|----------|
| Method | **GET only** |
| Content-Encoding | First release requires **identity** |
| Protocols | Same session HTTP stack (H1 / H2 / H3 subject to Session / TLS / Alt-Svc policy) |
| Reconnect | 4xx open failures **never** reconnect; other recoverable disconnects may reconnect with `Last-Event-ID` |
| Connection policy | Each open uses `ForceNew` |
| Concurrency | Do **not** call `Receive` concurrently on the same `SseClient` |
| IRQL | All entry points at `PASSIVE_LEVEL` |

## Relation to streaming OnBody

SSE sits on true incremental response bodies: when `SendOptions.OnBody` is set, the library invokes it **multiple times** in arrival order; `finalChunk` is true only at the real end. For aggregated body only, leave `OnBody` null. See [Sync HTTP](http-sync.md).

## Related

- [Capability matrix](../capability-matrix.md)
- [Sync HTTP](http-sync.md)
- [Cookbook](../cookbook.md)
- [Logging](../logging.md)
