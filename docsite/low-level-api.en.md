# Low-Level API

### Quick Start

#### Create Session and Send GET Request

```cpp
// 1. Get WSK client instance (assume already initialized)
net::WskClient* wskClient = /* ... */;

// 2. Create session
KH_SESSION session = nullptr;
KhSessionOptions options = {};
options.Tls.MinVersion = KhTlsVersion::Tls13;
options.Tls.CertificatePolicy = KhCertificatePolicy::Verify;
NTSTATUS status = KhSessionCreate(wskClient, &options, &session);

// 3. Create request
KH_REQUEST request = nullptr;
if (NT_SUCCESS(status)) {
    status = KhHttpRequestCreate(session, &request);
}
if (NT_SUCCESS(status)) {
    status = KhHttpRequestSetUrl(request, "https://httpbin.org/get", 24);
}
if (NT_SUCCESS(status)) {
    status = KhHttpRequestSetMethod(request, KhHttpMethod::Get);
}

// 4. Send request
KH_RESPONSE response = nullptr;
if (NT_SUCCESS(status)) {
    status = KhHttpSendSync(session, request, nullptr, &response);
}

// 5. Read response
if (NT_SUCCESS(status)) {
    KhResponseView view = {};
    status = KhResponseGetView(response, &view);
    if (NT_SUCCESS(status)) {
        ULONG statusCode = view.StatusCode;
        const UCHAR* body = view.Body;
        SIZE_T bodyLength = view.BodyLength;
    }
}

// 6. Release resources
KhResponseRelease(response);
KhHttpRequestRelease(request);
KhSessionClose(session);
```

#### Send POST JSON

```cpp
KH_REQUEST request = nullptr;
KhHttpRequestCreate(session, &request);

// Set URL and method
KhHttpRequestSetUrl(request, "https://httpbin.org/post", 25);
KhHttpRequestSetMethod(request, KhHttpMethod::Post);

// Set JSON body
const char* json = "{\"key\":\"value\"}";
KhHttpRequestSetTextBody(request, json, 13, "application/json; charset=utf-8", 30);

// Send request
KH_RESPONSE response = nullptr;
KhHttpSendSync(session, request, nullptr, &response);

// Cleanup
KhResponseRelease(response);
KhHttpRequestRelease(request);
```

### Conventions

Before using the low-level API, keep these points in mind:

- **All handles are heap objects**: All low-level public handles (`KH_SESSION`, `KH_REQUEST`, `KH_RESPONSE`, `KH_WEBSOCKET`, `KH_ASYNC_OPERATION`) are opaque heap pointers. Do not declare these objects on the stack; use the corresponding `Create` functions to create them and matching `Release` / `Close` functions to release them.
- **No Default factory**: Low-level `KhSessionOptions` has no default value factory; you need to zero-initialize and set fields explicitly.
- **IRQL requirement**: All low-level HTTP/WS calls require `PASSIVE_LEVEL`.
- **Error handling**: Return values are uniformly `NTSTATUS`; use `NT_SUCCESS(status)` to check success. Return values marked with `_Must_inspect_result_` must be checked.
- **Safe release**: `Release` / `Close` functions accept `nullptr`, which means you can call them unconditionally on failure paths.
- **WSK dependency**: Low-level API requires passing `net::WskClient*`, which is one of the main differences from the high-level API.
- **Request construction pattern**: Low-level `Request` is a builder pattern, constructing requests step by step via `Set*` functions; the high-level API passes all parameters at once in `Send*` calls.

### Header File Overview

The following header files are involved in the low-level API:

| Header | Contents |
|--------|----------|
| `KernelHttp/KernelHttp.h` | Main entry; includes low-level engine API |
| `KernelHttp/engine/Engine.h` | Low-level session, request, response, async operations |
| `KernelHttp/engine/Async.h` | Async operations and runtime |
| `KernelHttp/engine/Workspace.h` | Workspace buffer management |
| `KernelHttp/engine/ConnectionPool.h` | Connection pool |
| `KernelHttp/engine/Types.h` | Low-level enums, structs, config types |

### Handle Types

The low-level API uses opaque handles to manage resources. These handles are heap-allocated objects that you obtain through creation functions and return through release functions:

| Type | Low-Level Type | Create | Release | Description |
|------|----------------|--------|---------|-------------|
| `KH_SESSION` | `KhSession*` | `KhSessionCreate` | `KhSessionClose` | HTTP/WS session. Requires passing `net::WskClient*` |
| `KH_REQUEST` | `KhRequest*` | `KhHttpRequestCreate` | `KhHttpRequestRelease` | Request builder handle; constructs requests via `Set*` functions |
| `KH_RESPONSE` | `KhResponse*` | Returned by send result | `KhResponseRelease` | Response handle; read content via `KhResponseGetView` |
| `KH_WEBSOCKET` | `KhWebSocket*` | `KhWebSocketConnectSync` / `KhWebSocketConnectAsync` | `KhWebSocketCloseSync` | WebSocket connection handle |
| `KH_ASYNC_OPERATION` | `KhAsyncOperation*` | Returned by async send | `KhAsyncRelease` | Async operation handle; can wait, cancel, get result |

### Enums

Enum types define various options and modes used in the low-level API:

```cpp
enum class KhHttpMethod        { Get, Post, Put, Patch, Delete, Head, Options, Connect };
enum class KhTlsVersion        { Tls12 = 0x0303, Tls13 = 0x0304 };
enum class KhCertificatePolicy { Verify, NoVerify };
enum class KhConnectionPolicy  { ReuseOrCreate, ForceNew, NoPool };
enum class KhAddressFamily     { Any, Ipv4 = 4, Ipv6 = 6 };
enum class KhPoolType          { NonPaged, Paged };
enum class KhRequestBodyMode   { ContentLength, Chunked };
enum class KhRequestBodyPartKind { Field, FileBytes, FilePath };
enum class KhWebSocketMessageType { Text, Binary, Close, Continuation, Ping, Pong };
enum KhHttpSendFlags { KhHttpSendFlagNone = 0,
                       KhHttpSendFlagAggregateWithCallbacks = 0x1,
                       KhHttpSendFlagDisableAutoRedirect = 0x2 };
```

Each enum's purpose:

| Enum | Description |
|------|-------------|
| `KhHttpMethod` | HTTP method. `Connect` is mainly for special scenarios or low-level capabilities |
| `KhTlsVersion` | TLS minimum/maximum version |
| `KhCertificatePolicy` | Certificate verification policy. Production should use `Verify`; only consider `NoVerify` for testing |
| `KhConnectionPolicy` | Single-send connection pool policy. `ReuseOrCreate` is the most common choice |
| `KhAddressFamily` | DNS/connection address family selection. `Any` automatically selects the appropriate family |
| `KhPoolType` | Response buffer pool type. Kernel path currently requires `NonPaged`; `Paged` is a reserved ABI value |
| `KhRequestBodyMode` | Request body framing: `ContentLength` for known-size bodies, `Chunked` for streaming data |
| `KhRequestBodyPartKind` | Multipart part type. `Field` for normal form fields, `FileBytes` and `FilePath` for file uploads |
| `KhWebSocketMessageType` | WebSocket message type |
| `KhHttpSendFlags` | Send flags. `KhHttpSendFlagAggregateWithCallbacks` invokes callbacks while retaining aggregated response; `KhHttpSendFlagDisableAutoRedirect` disables auto-redirect; `KhHttpSendFlagExpectContinue` explicitly enables `Expect: 100-continue` |

### Function Overview

The following functions are provided by the low-level API. They are grouped by functionality:

#### Session and Lifecycle

| Function | Description |
|----------|-------------|
| `KhSessionCreate` | Creates low-level session; requires passing `net::WskClient*` |
| `KhSessionClose` | Closes session |
| `KhEngineDrainAsync` | Waits for all in-flight async operations (must call before unload) |
| `KhEngineCloseActiveHandles` | Force closes all active handles |

#### Request Construction

| Function | Description |
|----------|-------------|
| `KhHttpRequestCreate` / `KhHttpRequestRelease` | Creates/releases request handle |
| `KhHttpRequestSetUrl` | Sets request URL |
| `KhHttpRequestSetMethod` | Sets HTTP method |
| `KhHttpRequestSetHeader` | Sets request header |
| `KhHttpRequestSetBody` / `KhHttpRequestSetTextBody` / `KhHttpRequestSetRawBody` | Sets request body |
| `KhHttpRequestSetUrlEncodedBody` | Sets form-urlencoded body |
| `KhHttpRequestSetMultipartFormDataBody` | Sets multipart/form-data body |
| `KhHttpRequestSetFileBody` | Sets file body |
| `KhHttpRequestSetBodySource` | Sets streaming request body read callback |
| `KhHttpRequestSetBodyMode` | Sets Content-Length or chunked framing |
| `KhHttpRequestAddTrailer` | Adds trailer for chunked body |
| `KhHttpRequestClearBody` | Clears request body |
| `KhHttpRequestSetTlsOptions` | Sets per-send TLS config |
| `KhHttpRequestSetConnectionPolicy` | Sets connection policy |
| `KhHttpRequestSetAddressFamily` | Sets address family |

#### Send

| Function | Description |
|----------|-------------|
| `KhHttpSendSync` | Synchronous HTTP send |
| `KhHttpSendAsync` | Asynchronous HTTP send |

#### Response Access

| Function | Description |
|----------|-------------|
| `KhResponseGetView` | Gets response view (status code, body) |
| `KhResponseGetHeader` / `KhResponseGetHeaderAt` | Reads response header by name or index |
| `KhResponseHeaderCount` | Reads response header count |
| `KhResponseGetTrailer` / `KhResponseGetTrailerAt` | Reads trailer by name or index |
| `KhResponseTrailerCount` | Reads trailer count |
| `KhResponseRelease` | Releases response handle |

#### WebSocket

| Function | Description |
|----------|-------------|
| `KhWebSocketConnectSync` / `KhWebSocketConnectAsync` | Sync/async WebSocket connection |
| `KhWebSocketSendTextSync` / `KhWebSocketSendBinarySync` / `KhWebSocketSendContinuationSync` | Send WebSocket frames |
| `KhWebSocketSendPingSync` / `KhWebSocketSendPongSync` | Send ping/pong |
| `KhWebSocketReceiveSync` | Receive WebSocket message |
| `KhWebSocketCloseSync` / `KhWebSocketCloseExSync` | Close WebSocket |
| `KhWebSocketSelectedSubprotocol` | Query negotiated subprotocol |

#### Async Operations

| Function | Description |
|----------|-------------|
| `KhAsyncWait` | Waits for async operation completion |
| `KhAsyncCancel` | Requests cancel of async operation |
| `KhAsyncGetHttpResponse` | Gets HTTP async response |
| `KhAsyncGetWebSocket` | Gets WebSocket async connection |
| `KhAsyncRelease` | Releases async operation |

### Detailed Function Reference

#### Session

##### `KhSessionCreate`

```cpp
NTSTATUS KhSessionCreate(
    _In_ net::WskClient* wskClient,
    _In_opt_ const KhSessionOptions* options,
    _Out_ KH_SESSION* out
) noexcept;
```

Creates a low-level HTTP/WS session. Unlike the high-level `khttp::SessionCreate`, the low-level version requires passing `net::WskClient*`.

| Parameter | Description |
|-----------|-------------|
| `wskClient` | WSK client instance; must be initialized |
| `options` | Session options; `nullptr` uses zero-initialized defaults |
| `out` | Receives `KH_SESSION` on success; set to `nullptr` on failure |

| Return Value | Meaning |
|--------------|----------|
| `STATUS_SUCCESS` | Created successfully |
| `STATUS_INVALID_PARAMETER` | `out == nullptr` or invalid config |
| `STATUS_INSUFFICIENT_RESOURCES` | Failed to allocate session or internal resources |
| Other failure | WSK initialization or engine session creation failed |

NOTE: `KhSessionOptions` / `KhTlsOptions` fields see [Configuration](configuration.md). `KhSessionOptions.Proxy` explicitly configures HTTP proxy behavior: HTTPS uses CONNECT, plaintext HTTP uses absolute-form. Must call `KhSessionClose` after success.

##### `KhSessionClose`

```cpp
void KhSessionClose(
    _In_opt_ KH_SESSION session
) noexcept;
```

Closes and releases the session. This is a safe function that accepts `nullptr`.

| Parameter | Description |
|-----------|-------------|
| `session` | Session to close; `nullptr` returns immediately |

No return value.

NOTE: Closing the session releases internal resources. If you used async APIs, you must also call `KhEngineDrainAsync()` before driver unload.

### Request Construction

Request construction is the core part of the low-level API. Unlike the high-level API, the low-level `Request` is a builder pattern, constructing requests step by step via `Set*` functions.

#### `KhHttpRequestCreate`

```cpp
NTSTATUS KhHttpRequestCreate(
    _In_ KH_SESSION session,
    _Out_ KH_REQUEST* out
) noexcept;
```

Creates a request handle bound to `Session`. The request handle is used to construct HTTP requests step by step.

| Parameter | Description |
|-----------|-------------|
| `session` | Parent session |
| `out` | Receives `KH_REQUEST` on success |

| Return Value | Meaning |
|--------------|----------|
| `STATUS_SUCCESS` | Created successfully |
| `STATUS_INVALID_PARAMETER` | Parameter is null or session invalid |
| `STATUS_INSUFFICIENT_RESOURCES` | Allocation failed |

#### `KhHttpRequestRelease`

```cpp
void KhHttpRequestRelease(
    _In_opt_ KH_REQUEST request
) noexcept;
```

Releases the request handle. This is a safe function that accepts `nullptr`.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle to release; `nullptr` returns immediately |

No return value.

#### `KhHttpRequestSetUrl`

```cpp
NTSTATUS KhHttpRequestSetUrl(
    _In_ KH_REQUEST request,
    _In_ const char* url,
    _In_ SIZE_T urlLen
) noexcept;
```

Sets the request URL.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle |
| `url` | URL string |
| `urlLen` | URL byte length |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

#### `KhHttpRequestSetMethod`

```cpp
NTSTATUS KhHttpRequestSetMethod(
    _In_ KH_REQUEST request,
    _In_ KhHttpMethod method
) noexcept;
```

Sets the HTTP method.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle |
| `method` | HTTP method enum value |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`

#### `KhHttpRequestSetHeader`

```cpp
NTSTATUS KhHttpRequestSetHeader(
    _In_ KH_REQUEST request,
    _In_ const char* name,
    _In_ SIZE_T nLen,
    _In_ const char* value,
    _In_ SIZE_T vLen
) noexcept;
```

Sets a request header. Deduplicates by case-insensitive field name; same-name fields overwrite the old value.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle |
| `name` | Header name |
| `nLen` | Header name byte length |
| `value` | Header value |
| `vLen` | Header value byte length |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

NOTE: CR/LF injection is prohibited. Library-controlled headers (like `Host`, `Content-Length`) will be rejected.

#### `KhHttpRequestSetBody` / `KhHttpRequestSetTextBody` / `KhHttpRequestSetRawBody`

```cpp
NTSTATUS KhHttpRequestSetBody(
    _In_ KH_REQUEST request,
    _In_ const UCHAR* body,
    _In_ SIZE_T len
) noexcept;

NTSTATUS KhHttpRequestSetTextBody(
    _In_ KH_REQUEST request,
    _In_ const char* text,
    _In_ SIZE_T len,
    _In_opt_ const char* contentType,
    _In_ SIZE_T ctLen
) noexcept;

NTSTATUS KhHttpRequestSetRawBody(
    _In_ KH_REQUEST request,
    _In_ const UCHAR* data,
    _In_ SIZE_T len,
    _In_opt_ const char* contentType,
    _In_ SIZE_T ctLen
) noexcept;
```

Sets the request body. `SetBody` sets raw bytes; `SetTextBody` sets text with optional Content-Type; `SetRawBody` sets raw bytes with optional Content-Type.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle |
| `body` / `text` / `data` | Request body bytes |
| `len` | Byte length |
| `contentType` | Content-Type; can be NULL |
| `ctLen` | Content-Type byte length |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

#### `KhHttpRequestSetUrlEncodedBody`

```cpp
NTSTATUS KhHttpRequestSetUrlEncodedBody(
    _In_ KH_REQUEST request,
    _In_ const KhNameValuePair* pairs,
    _In_ SIZE_T count
) noexcept;
```

Sets `application/x-www-form-urlencoded` request body.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle |
| `pairs` | Form field array |
| `count` | Field count |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

#### `KhHttpRequestSetMultipartFormDataBody`

```cpp
NTSTATUS KhHttpRequestSetMultipartFormDataBody(
    _In_ KH_REQUEST request,
    _In_ const KhMultipartFormDataPart* parts,
    _In_ SIZE_T count
) noexcept;
```

Sets `multipart/form-data` request body.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle |
| `parts` | Multipart part array |
| `count` | Part count |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

#### `KhHttpRequestSetFileBody`

```cpp
NTSTATUS KhHttpRequestSetFileBody(
    _In_ KH_REQUEST request,
    _In_ const char* path,
    _In_ SIZE_T pathLen,
    _In_opt_ const char* contentType,
    _In_ SIZE_T ctLen
) noexcept;
```

Sets file request body. Library copies file path; file content is read at send time.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle |
| `path` | File path |
| `pathLen` | File path byte length |
| `contentType` | Content-Type; can be NULL |
| `ctLen` | Content-Type byte length |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

#### `KhHttpRequestSetBodySource`

```cpp
NTSTATUS KhHttpRequestSetBodySource(
    _In_ KH_REQUEST request,
    _In_ KhRequestBodyReadCallback callback,
    _In_opt_ void* context,
    _In_ SIZE_T contentLength,
    _In_ bool contentLengthKnown
) noexcept;
```

Sets a streaming request body read callback. With `contentLengthKnown=true`, the request sends `Content-Length`; for unknown length, pair this with `KhHttpRequestSetBodyMode(request, KhRequestBodyMode::Chunked)` so the library generates chunked framing.

#### `KhHttpRequestSetBodyMode`

```cpp
NTSTATUS KhHttpRequestSetBodyMode(
    _In_ KH_REQUEST request,
    _In_ KhRequestBodyMode mode
) noexcept;
```

Sets request body framing mode. Default is `ContentLength` for known-size bodies; `Chunked` for streaming data.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle |
| `mode` | `ContentLength` or `Chunked` |

Returns: `STATUS_SUCCESS` or `STATUS_INVALID_PARAMETER`

#### `KhHttpRequestAddTrailer`

```cpp
NTSTATUS KhHttpRequestAddTrailer(
    _In_ KH_REQUEST request,
    _In_ const char* name,
    _In_ SIZE_T nLen,
    _In_ const char* value,
    _In_ SIZE_T vLen
) noexcept;
```

Adds trailer fields for chunked request body.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle |
| `name` | Trailer name |
| `nLen` | Trailer name byte length |
| `value` | Trailer value |
| `vLen` | Trailer value byte length |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_NOT_SUPPORTED`, `STATUS_INSUFFICIENT_RESOURCES`

NOTE: Trailers are only sent after `KhHttpRequestSetBodyMode(request, KhRequestBodyMode::Chunked)`. Forbidden fields and CRLF injection will be rejected.

#### `KhHttpRequestClearBody`

```cpp
NTSTATUS KhHttpRequestClearBody(
    _In_ KH_REQUEST request
) noexcept;
```

Clears the request body.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle |

Returns: `STATUS_SUCCESS` or `STATUS_INVALID_PARAMETER`

#### `KhHttpRequestSetTlsOptions`

```cpp
NTSTATUS KhHttpRequestSetTlsOptions(
    _In_ KH_REQUEST request,
    _In_ const KhTlsOptions* options
) noexcept;
```

Sets per-send TLS config, overriding session defaults.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle |
| `options` | TLS options; can be NULL |

Returns: `STATUS_SUCCESS` or `STATUS_INVALID_PARAMETER`

#### `KhHttpRequestSetConnectionPolicy`

```cpp
NTSTATUS KhHttpRequestSetConnectionPolicy(
    _In_ KH_REQUEST request,
    _In_ KhConnectionPolicy policy
) noexcept;
```

Sets the connection policy.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle |
| `policy` | Connection policy enum value |

Returns: `STATUS_SUCCESS` or `STATUS_INVALID_PARAMETER`

#### `KhHttpRequestSetAddressFamily`

```cpp
NTSTATUS KhHttpRequestSetAddressFamily(
    _In_ KH_REQUEST request,
    _In_ KhAddressFamily family
) noexcept;
```

Sets the address family.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle |
| `family` | Address family enum value |

Returns: `STATUS_SUCCESS` or `STATUS_INVALID_PARAMETER`

### Send

#### `KhHttpSendSync`

```cpp
NTSTATUS KhHttpSendSync(
    _In_ KH_SESSION session,
    _In_ KH_REQUEST request,
    _In_opt_ const KhHttpSendOptions* options,
    _Out_ KH_RESPONSE* resp
) noexcept;
```

Synchronous HTTP send. Function blocks until request completes.

| Parameter | Description |
|-----------|-------------|
| `session` | Session handle |
| `request` | Request handle |
| `options` | Send options; `nullptr` uses defaults |
| `resp` | Receives `KH_RESPONSE` on success |

| Return Value | Meaning |
|--------------|----------|
| `STATUS_SUCCESS` | Request succeeded |
| `STATUS_INVALID_PARAMETER` | Invalid parameter |
| `STATUS_INVALID_DEVICE_REQUEST` | Not called at `PASSIVE_LEVEL` |
| `STATUS_BUFFER_TOO_SMALL` | Response exceeded `MaxResponseBytes` |
| `STATUS_IO_TIMEOUT` | Timeout |
| `STATUS_CONNECTION_DISCONNECTED` | Connection disconnected |
| `STATUS_TRUST_FAILURE` | TLS certificate verification failed |
| `STATUS_INVALID_NETWORK_RESPONSE` | Response format incorrect |
| `STATUS_INSUFFICIENT_RESOURCES` | Out of memory or connection pool full |
| Other `NTSTATUS` | Transport, TLS, parse, or callback error |

NOTE: `KhHttpSendOptions` fields: `MaxResponseBytes`, `Flags`, `MaxRedirects`, `HeaderCallback`, `BodyCallback`, `CallbackContext`, `CompletionCallback`, `CompletionContext`, `Http2CleartextMode`, `AcceptEncodingPreferences`, `Http2Priority`.

#### `KhHttpSendAsync`

```cpp
NTSTATUS KhHttpSendAsync(
    _In_ KH_SESSION session,
    _In_ KH_REQUEST request,
    _In_opt_ const KhHttpSendOptions* options,
    _Out_ KH_ASYNC_OPERATION* op
) noexcept;
```

Asynchronous HTTP send. Function returns immediately, operation executes in background.

| Parameter | Description |
|-----------|-------------|
| `session` | Session handle |
| `request` | Request handle |
| `options` | Send options; `nullptr` uses defaults |
| `op` | Receives `KH_ASYNC_OPERATION` on success |

| Return Value | Meaning |
|--------------|----------|
| `STATUS_SUCCESS` | Async operation created and queued |
| `STATUS_INVALID_PARAMETER` | Invalid parameter or handle |
| `STATUS_INSUFFICIENT_RESOURCES` | Allocation failed or async queue full |
| Other failure | Send preparation failed |

NOTE: After success, caller should `KhAsyncWait` for terminal state, call `KhAsyncGetHttpResponse` to get response, then release `KH_RESPONSE` and `KH_ASYNC_OPERATION` separately.

### Response Access

These functions are used to read HTTP response content. The low-level API obtains response views via `KhResponseGetView`, then reads response headers and trailers via other functions.

#### `KhResponseGetView`

```cpp
NTSTATUS KhResponseGetView(
    _In_ KH_RESPONSE response,
    _Out_ KhResponseView* view
) noexcept;
```

Gets the response view. The view contains status code, response body pointer and length.

| Parameter | Description |
|-----------|-------------|
| `response` | Response handle |
| `view` | Receives response view on success |

| Return Value | Meaning |
|--------------|----------|
| `STATUS_SUCCESS` | Successfully got view |
| `STATUS_INVALID_PARAMETER` | Invalid parameter |

NOTE: `KhResponseView` contains `StatusCode`, `Body`, `BodyLength` fields. The `Body` pointer is valid until `KhResponseRelease`.

#### `KhResponseGetHeader`

```cpp
NTSTATUS KhResponseGetHeader(
    _In_ KH_RESPONSE response,
    _In_ const char* name,
    _In_ SIZE_T nLen,
    _Out_ const char** value,
    _Out_ SIZE_T* vLen
) noexcept;
```

Reads response header by name. Name matching is case-insensitive.

| Parameter | Description |
|-----------|-------------|
| `response` | Response handle |
| `name` | Header name |
| `nLen` | Name byte length |
| `value` | Receives header value pointer on success |
| `vLen` | Receives value length on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_NOT_FOUND`

#### `KhResponseHeaderCount`

```cpp
SIZE_T KhResponseHeaderCount(
    _In_ KH_RESPONSE response
) noexcept;
```

Reads response header count.

| Parameter | Description |
|-----------|-------------|
| `response` | Response handle; can be NULL |

Returns: Count; returns 0 for NULL or invalid handle.

#### `KhResponseGetHeaderAt`

```cpp
NTSTATUS KhResponseGetHeaderAt(
    _In_ KH_RESPONSE response,
    _In_ SIZE_T index,
    _Out_ const char** name,
    _Out_ SIZE_T* nLen,
    _Out_ const char** value,
    _Out_ SIZE_T* vLen
) noexcept;
```

Enumerates response header by index.

| Parameter | Description |
|-----------|-------------|
| `response` | Response handle |
| `index` | Header index |
| `name` | Receives header name pointer on success |
| `nLen` | Receives name length on success |
| `value` | Receives header value pointer on success |
| `vLen` | Receives value length on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_NOT_FOUND`

#### `KhResponseTrailerCount`

```cpp
SIZE_T KhResponseTrailerCount(
    _In_ KH_RESPONSE response
) noexcept;
```

Reads trailer count.

| Parameter | Description |
|-----------|-------------|
| `response` | Response handle; can be NULL |

Returns: Count; returns 0 for NULL or invalid handle.

#### `KhResponseGetTrailer` / `KhResponseGetTrailerAt`

```cpp
NTSTATUS KhResponseGetTrailer(
    _In_ KH_RESPONSE response,
    _In_ const char* name,
    _In_ SIZE_T nLen,
    _Out_ const char** value,
    _Out_ SIZE_T* vLen
) noexcept;

NTSTATUS KhResponseGetTrailerAt(
    _In_ KH_RESPONSE response,
    _In_ SIZE_T index,
    _Out_ const char** name,
    _Out_ SIZE_T* nLen,
    _Out_ const char** value,
    _Out_ SIZE_T* vLen
) noexcept;
```

Reads response trailer by name or index.

**Parameters and return values**: Same as header read functions.

#### `KhResponseRelease`

```cpp
void KhResponseRelease(
    _In_opt_ KH_RESPONSE response
) noexcept;
```

Releases response handle and its internal buffers. This is a safe function that accepts `nullptr`.

| Parameter | Description |
|-----------|-------------|
| `response` | Response handle; can be NULL |

No return value.

### WebSocket (Low-Level)

These functions are used for WebSocket connections and communication. WebSocket provides full-duplex communication capabilities, suitable for real-time data push, chat, games, etc.

#### `KhWebSocketConnectSync` / `KhWebSocketConnectAsync`

```cpp
NTSTATUS KhWebSocketConnectSync(
    _In_ KH_SESSION session,
    _In_ const KhWebSocketConnectOptions* options,
    _Out_ KH_WEBSOCKET* out
) noexcept;

NTSTATUS KhWebSocketConnectAsync(
    _In_ KH_SESSION session,
    _In_ const KhWebSocketConnectOptions* options,
    _Out_ KH_ASYNC_OPERATION* op
) noexcept;
```

Establishes WebSocket connection. `ConnectSync` blocks until handshake completes; `ConnectAsync` returns asynchronously.

| Parameter | Description |
|-----------|-------------|
| `session` | Session handle |
| `options` | Connection config |
| `out` / `op` | Receives `KH_WEBSOCKET` or `KH_ASYNC_OPERATION` on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_NOT_SUPPORTED`, network/TLS/HTTP handshake failure.

NOTE: `KhWebSocketConnectOptions.Headers/HeaderCount` can pass extra opening-handshake headers; library-controlled headers (`Host`, `Connection`, `Upgrade`, `Sec-WebSocket-*`, etc.) will be rejected. When `AllowWebSocketOverHttp2=true`, `wss` can explicitly opt-in RFC 8441; default is still HTTP/1.1 Upgrade.

#### WebSocket Send Functions

```cpp
NTSTATUS KhWebSocketSendTextSync(
    _In_ KH_WEBSOCKET ws,
    _In_ const char* text,
    _In_ SIZE_T len,
    _In_opt_ const KhWebSocketSendOptions* options
) noexcept;

NTSTATUS KhWebSocketSendBinarySync(
    _In_ KH_WEBSOCKET ws,
    _In_ const UCHAR* data,
    _In_ SIZE_T len,
    _In_opt_ const KhWebSocketSendOptions* options
) noexcept;

NTSTATUS KhWebSocketSendContinuationSync(
    _In_ KH_WEBSOCKET ws,
    _In_ const UCHAR* data,
    _In_ SIZE_T len,
    _In_opt_ const KhWebSocketSendOptions* options
) noexcept;

NTSTATUS KhWebSocketSendPingSync(
    _In_ KH_WEBSOCKET ws,
    _In_opt_ const UCHAR* payload,
    _In_ SIZE_T len
) noexcept;

NTSTATUS KhWebSocketSendPongSync(
    _In_ KH_WEBSOCKET ws,
    _In_opt_ const UCHAR* payload,
    _In_ SIZE_T len
) noexcept;
```

Sends WebSocket frames. Supports text, binary, continuation, ping, pong frame types.

| Parameter | Description |
|-----------|-------------|
| `ws` | WebSocket handle |
| `text` | Text bytes |
| `data` | Binary or continuation bytes |
| `payload` | Ping/pong payload; can be NULL when `len == 0` |
| `options` | `FinalFragment` option |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, connection closed/disconnected/timeout failure.

#### `KhWebSocketReceiveSync`

```cpp
NTSTATUS KhWebSocketReceiveSync(
    _In_ KH_WEBSOCKET ws,
    _In_opt_ const KhWebSocketReceiveOptions* options,
    _Out_ KhWebSocketMessage* msg
) noexcept;
```

Receives WebSocket message. This is a blocking call that waits until a message is received or an error occurs.

| Parameter | Description |
|-----------|-------------|
| `ws` | WebSocket handle |
| `options` | Receive options; can be NULL |
| `msg` | Receives message on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_BUFFER_TOO_SMALL`, connection closed/disconnected/timeout.

#### `KhWebSocketCloseSync` / `KhWebSocketCloseExSync`

```cpp
NTSTATUS KhWebSocketCloseSync(
    _In_opt_ KH_WEBSOCKET ws
) noexcept;

NTSTATUS KhWebSocketCloseExSync(
    _In_opt_ KH_WEBSOCKET ws,
    _In_ USHORT statusCode,
    _In_opt_ const UCHAR* reason,
    _In_ SIZE_T reasonLen
) noexcept;
```

Closes WebSocket connection. `CloseSync` is the simple version; `CloseExSync` allows specifying close status code and reason.

| Parameter | Description |
|-----------|-------------|
| `ws` | WebSocket handle; can be NULL |
| `statusCode` | Close status code |
| `reason` | Close reason; can be NULL when `reasonLen == 0` |
| `reasonLen` | Close reason byte length |

Returns: Close success or transport failure.

NOTE: Do not concurrently execute `Close` and new send/receive on the same `WebSocket`. Close should be the last operation.

#### `KhWebSocketSelectedSubprotocol`

```cpp
NTSTATUS KhWebSocketSelectedSubprotocol(
    _In_ KH_WEBSOCKET ws,
    _Out_ const char** sub,
    _Out_ SIZE_T* subLen
) noexcept;
```

Reads the WebSocket subprotocol selected by the server.

| Parameter | Description |
|-----------|-------------|
| `ws` | WebSocket handle |
| `sub` | Receives subprotocol pointer on success |
| `subLen` | Receives subprotocol length on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_NOT_FOUND`

### Async Operations

These functions are used to manage the lifecycle and status of async operations.

#### `KhAsyncWait`

```cpp
NTSTATUS KhAsyncWait(
    _In_ KH_ASYNC_OPERATION op,
    _In_ ULONG timeoutMs
) noexcept;
```

Waits for async operation to complete. This is the synchronous way to wait for async results.

| Parameter | Description |
|-----------|-------------|
| `op` | Async operation handle |
| `timeoutMs` | Wait timeout in milliseconds; pass `0xffffffffUL` for infinite wait |

Returns: Completion status, `STATUS_TIMEOUT`, `STATUS_INVALID_PARAMETER`, or failure during wait.

#### `KhAsyncCancel`

```cpp
NTSTATUS KhAsyncCancel(
    _In_ KH_ASYNC_OPERATION op
) noexcept;
```

Requests cancellation of async operation. Cancellation is cooperative, not immediate.

| Parameter | Description |
|-----------|-------------|
| `op` | Async operation handle; cannot be NULL |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, or cancellation failure.

NOTE: After canceling, still call `KhAsyncWait` to wait for terminal state before releasing. Do not assume cancellation completes immediately.

#### `KhAsyncGetHttpResponse`

```cpp
NTSTATUS KhAsyncGetHttpResponse(
    _In_ KH_ASYNC_OPERATION op,
    _Out_ KH_RESPONSE* resp
) noexcept;
```

Extracts response from completed HTTP async operation. Must be called after operation completes.

| Parameter | Description |
|-----------|-------------|
| `op` | HTTP send async operation |
| `resp` | Receives `KH_RESPONSE` on success |

| Return Value | Meaning |
|--------------|----------|
| `STATUS_SUCCESS` | Successfully extracted response |
| `STATUS_INVALID_PARAMETER` | Invalid parameter or operation type |
| `STATUS_PENDING` | Operation not yet complete; call `KhAsyncWait` first |
| Other failure | Send failed or was canceled |

#### `KhAsyncGetWebSocket`

```cpp
NTSTATUS KhAsyncGetWebSocket(
    _In_ KH_ASYNC_OPERATION op,
    _Out_ KH_WEBSOCKET* ws
) noexcept;
```

Extracts `KH_WEBSOCKET` handle from completed WebSocket connect async operation.

| Parameter | Description |
|-----------|-------------|
| `op` | WebSocket connect async operation |
| `ws` | Receives `KH_WEBSOCKET` on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_PENDING`, or connection final failure.

#### `KhAsyncRelease`

```cpp
void KhAsyncRelease(
    _In_opt_ KH_ASYNC_OPERATION op
) noexcept;
```

Releases async operation handle. This is a safe function that accepts `nullptr`.

| Parameter | Description |
|-----------|-------------|
| `op` | Async operation handle; can be NULL |

No return value.

### Engine Lifecycle

These functions are used to manage the engine lifecycle and async runtime.

#### `KhEngineDrainAsync`

```cpp
NTSTATUS KhEngineDrainAsync() noexcept;
```

Waits for all in-flight async operations to complete. Must call before driver unload.

No parameters.

Returns: `STATUS_SUCCESS` or failure during wait.

NOTE: Must call after using HTTP or WebSocket async APIs before driver unload. Safe to call unconditionally on sync-only paths.

#### `KhEngineCloseActiveHandles`

```cpp
void KhEngineCloseActiveHandles() noexcept;
```

Force closes all active handles. Used for abnormal cleanup scenarios.

No parameters.

No return value.

### Test Hooks (only `KERNEL_HTTP_USER_MODE_TEST`)

These functions are used for unit tests; not included in kernel builds:

| Function | Description |
|----------|-------------|
| `KhTestSetHttpTransport` / `KhTestSetWebSocketTransport` | Inject mock transport |
| `KhTestSetAsyncAutoRun` / `KhTestRunAsyncOperation` | Manual async driving |
| `KhTestSetCurrentIrql` / `KhTestResetCurrentIrql` | Simulate IRQL |

Used for deterministic, network-free unit tests.
