# High-Level API

### Quick Start

#### Send a GET Request

```cpp
khttp::Session* session = nullptr;
khttp::Response* response = nullptr;

// Create session
khttp::SessionCreate(&session);

// Send GET request
khttp::Get(session, "https://httpbin.org/get", &response);

// Read response
if (response) {
    ULONG statusCode = khttp::ResponseStatusCode(response);
    const UCHAR* body = khttp::ResponseBody(response);
    SIZE_T bodyLength = khttp::ResponseBodyLength(response);
}

// Release resources
khttp::ResponseRelease(response);
khttp::SessionClose(session);
```

#### Send POST JSON

```cpp
khttp::Session* session = nullptr;
khttp::Response* response = nullptr;

khttp::SessionCreate(&session);

// Create JSON body
khttp::Body* body = nullptr;
khttp::BodyCreateJsonCopy("{\"key\":\"value\"}", 13, &body);

// Send POST request
khttp::Post(session, "https://httpbin.org/post", body, &response);

khttp::BodyRelease(body);
khttp::ResponseRelease(response);
khttp::SessionClose(session);
```

#### Async Request

```cpp
khttp::AsyncOp* op = nullptr;
khttp::Response* response = nullptr;

// Async GET
khttp::AsyncGet(session, "https://httpbin.org/get", &op);

// Wait for completion
khttp::AsyncWait(op, 30000);

// Get response
khttp::AsyncGetResponse(op, &response);

khttp::ResponseRelease(response);
khttp::AsyncRelease(op);
```

### Conventions

Before using the high-level API, keep these points in mind:

- **All handles are heap objects**: All high-level public handles (`Session`, `Request`, `Response`, `AsyncOp`, `Headers`, `Body`, `kws::WebSocket`) are opaque heap pointers. Do not declare these objects on the stack; use the corresponding `Create` functions to create them and matching `Close` / `Release` functions to release them.
- **Options are also heap objects**: `SendOptions` / `AsyncOptions` must be created via `SendOptionsCreate` / `AsyncOptionsCreate` before modifying their fields.
- **IRQL requirement**: All high-level HTTP/WS calls require `PASSIVE_LEVEL`.
- **Error handling**: Return values are uniformly `NTSTATUS`; use `NT_SUCCESS(status)` to check success. Return values marked with `_Must_inspect_result_` must be checked.
- **Safe release**: `Release` / `Close` functions accept `nullptr`, which means you can call them unconditionally on failure paths.
- **Response body size**: `MaxResponseBytes = 0` means no caller-set aggregate response body limit (recommended); a non-zero value actively limits buffered response size.
- **JSON is passthrough only**: `BodyCreateJson` and similar functions only set `Content-Type: application/json; charset=utf-8` and pass bytes through. They do not parse, validate, or construct JSON. Use a dedicated JSON library if needed.

### Header File Overview

The following header files are involved in the high-level API. In most cases, you only need to include `KernelHttp/KernelHttp.h` to use all functionality:

| Header | Contents |
|--------|----------|
| `KernelHttp/KernelHttp.h` | Main entry; includes high-level HTTP, WebSocket, low-level engine, and base types |
| `KernelHttp/khttp/Types.h` | Enums, config structs, callback types, public constants |
| `KernelHttp/khttp/Session.h` | `SessionCreate` / `SessionClose` |
| `KernelHttp/khttp/Request.h` | `RequestCreate` / `RequestRelease` |
| `KernelHttp/khttp/Headers.h` | `Headers` handle creation, adding, release |
| `KernelHttp/khttp/Body.h` | `Body` handle creation, mode, trailer, release |
| `KernelHttp/khttp/Options.h` | `SendOptions` / `AsyncOptions` creation and release |
| `KernelHttp/khttp/Http.h` | Synchronous HTTP sends and convenience functions |
| `KernelHttp/khttp/HttpAsync.h` | Asynchronous HTTP sends and convenience functions |
| `KernelHttp/khttp/AsyncOp.h` | Async operation wait, cancel, get result, release |
| `KernelHttp/khttp/Response.h` | Response read-only access and release |
| `KernelHttp/khttp/Lifecycle.h` | `Destroy` async cleanup entry point |
| `KernelHttp/kws/WebSocket.h` | High-level WebSocket connection, send/receive, close |

### Types and Structs Overview

#### Opaque Handles

The high-level API uses opaque handles to manage resources. These handles are heap-allocated objects that you obtain through creation functions and return through release functions:

| Type | Namespace | Create | Release | Description |
|------|-----------|--------|---------|-------------|
| `Session` | `khttp` | `SessionCreate` | `SessionClose` | HTTP/WS session. Internally owns hidden WSK runtime and engine session |
| `Request` | `khttp` | `RequestCreate` | `RequestRelease` | Send handle bound to `Session`; does not store URL, method, header, or body |
| `Response` | `khttp` | Returned by send/async result | `ResponseRelease` | Independent response handle containing status code, body, headers, trailers |
| `AsyncOp` | `khttp` | Returned by async send or WS async connect | `AsyncRelease` | Async operation handle; can wait, cancel, get result |
| `Headers` | `khttp` | `HeadersCreate` | `HeadersRelease` | Request header collection; copies name/value on add |
| `Body` | `khttp` | `BodyCreate*` | `BodyRelease` | Request body descriptor; supports reference/copy, form, multipart, file, chunked trailer |
| `WebSocket` | `kws` | `Connect` / `ConnectEx` / `AsyncGetWebSocket` | `Close` / `CloseEx` | WebSocket connection handle |

#### Enums

Enum types define various options and modes used in the API:

```cpp
enum class Method : ULONG {
    Get, Post, Put, Patch, Delete, Head, Options, Connect, Trace
};

enum class PoolType : ULONG {
    NonPaged = 0,
    Paged = 1
};

enum class TlsVersion : ULONG {
    Tls12 = 0x0303,
    Tls13 = 0x0304
};

enum class CertPolicy : ULONG {
    Verify = 0,
    NoVerify = 1
};

enum class AddressFamily : ULONG {
    Any = 0,
    Ipv4 = 4,
    Ipv6 = 6
};

enum class ConnPolicy : ULONG {
    ReuseOrCreate = 0,
    ForceNew = 1,
    NoPool = 2
};

enum class BodyPartKind : ULONG {
    Field = 0,
    FileBytes = 1,
    FilePath = 2
};

enum class RequestBodyMode : ULONG {
    ContentLength = 0,
    Chunked = 1
};
```

| Enum | Description |
|------|-------------|
| `Method` | HTTP method. `Connect` is mainly for special scenarios or low-level capabilities |
| `PoolType` | Response buffer pool type. Kernel path currently requires `NonPaged`; `Paged` is a reserved ABI value |
| `TlsVersion` | TLS minimum/maximum version |
| `CertPolicy` | Certificate verification policy |
| `AddressFamily` | DNS/connection address family selection |
| `ConnPolicy` | Single-send connection pool policy |
| `BodyPartKind` | Multipart part type |
| `RequestBodyMode` | Request body framing: `ContentLength` or `Chunked` |

#### Send Flags

```cpp
enum SendFlags : ULONG {
    SendFlagNone = 0,
    SendFlagAggregateWithCallbacks = 0x00000001,
    SendFlagDisableAutoRedirect = 0x00000002,
    SendFlagExpectContinue = 0x00000004,
    SendFlagAllowTrace = 0x00000008,
    SendFlagBypassCache = 0x00000010,
    SendFlagNoCacheStore = 0x00000020,
    SendFlagOnlyIfCached = 0x00000040
};
```

| Flag | Description |
|------|-------------|
| `SendFlagNone` | Default behavior |
| `SendFlagAggregateWithCallbacks` | Invoke header/body callbacks while retaining aggregated response |
| `SendFlagDisableAutoRedirect` | Disable auto-redirect; return 3xx response directly |
| `SendFlagExpectContinue` | Explicitly enable `Expect: 100-continue` for HTTP/1.1 requests with a body; default is off |
| `SendFlagAllowTrace` | Explicitly allow TRACE; bodies, trailers, and sensitive headers are still rejected |
| `SendFlagBypassCache` | Skip cache lookup while still allowing the response to be stored by RFC 9111 rules |
| `SendFlagNoCacheStore` | Do not store this response in the cache |
| `SendFlagOnlyIfCached` | Use only cached responses; miss or required network validation returns `STATUS_NOT_FOUND` |

#### Callback Types

```cpp
typedef NTSTATUS (*HeaderCallback)(
    void* context,
    const char* name,
    SIZE_T nameLength,
    const char* value,
    SIZE_T valueLength);

typedef NTSTATUS (*BodyCallback)(
    void* context,
    const UCHAR* data,
    SIZE_T dataLength,
    bool finalChunk);

typedef NTSTATUS (*RequestBodyReadCallback)(
    void* context,
    _Out_writes_bytes_(bufferCapacity) UCHAR* buffer,
    SIZE_T bufferCapacity,
    _Out_ SIZE_T* bytesRead,
    _Out_ bool* endOfBody);

typedef void (*CompletionCallback)(
    void* context,
    NTSTATUS status);
```

| Callback | Trigger | Return Value |
|----------|---------|--------------|
| `HeaderCallback` | Called per response header received | Returning failure aborts send and propagates the status |
| `BodyCallback` | Called per response body chunk | Returning failure aborts send and propagates the status; `finalChunk` is `true` for the last chunk |
| `RequestBodyReadCallback` | Called by the library while sending a streaming request body | Returning failure aborts send; `endOfBody=true` ends the body |
| `CompletionCallback` | Called when async operation completes | `void`; does not affect operation result |

`context` comes from `SendOptions::CallbackContext` or `AsyncOptions::CompletionContext`.

### Struct Field Reference

#### `TlsConfig`

The `TlsConfig` struct configures TLS connection security parameters. You can use it in two places: as `SessionConfig::Tls` to set session defaults, or as `SendOptions::Tls` to override for a single send.

```cpp
struct TlsConfig final {
    TlsVersion MinVersion;
    TlsVersion MaxVersion;
    CertPolicy Certificate;
    const KernelHttp::tls::CertificateStore* Store;
    const char* ServerName;
    SIZE_T ServerNameLength;
    const char* Alpn;
    SIZE_T AlpnLength;
    bool PreferHttp2;
    KernelHttp::tls::TlsPolicy Policy;
    const KernelHttp::tls::TlsClientCredential* ClientCredential;
    ULONG HandshakeTimeoutMs;
    ULONG MaxTls12Renegotiations;
};
```

| Field | Default | Description |
|-------|---------|-------------|
| `MinVersion` | `Tls12` | Minimum allowed TLS version |
| `MaxVersion` | `Tls13` | Maximum allowed TLS version |
| `Certificate` | `Verify` | Whether to verify certificate chain, hostname, policy |
| `Store` | `nullptr` | Custom certificate store; `nullptr` uses library default trust source |
| `ServerName` / `ServerNameLength` | `nullptr` / `0` | SNI and certificate hostname; derived from URL host when empty |
| `Alpn` / `AlpnLength` | `nullptr` / `0` | Explicit ALPN; auto-provided based on `PreferHttp2` when empty |
| `PreferHttp2` | `true` | Prefer HTTP/2 when auto-providing ALPN |
| `Policy` | `{}` | TLS security policy; see TLS documentation |
| `ClientCredential` | `nullptr` | mTLS client credential |
| `HandshakeTimeoutMs` | `DefaultTlsHandshakeTimeoutMs` | TLS handshake timeout |
| `MaxTls12Renegotiations` | `DefaultMaxTls12Renegotiations` | TLS 1.2 full-renegotiation attempt limit; meaningful only when policy explicitly enables renegotiation |

#### `ProxyConfig`

The `ProxyConfig` struct configures HTTP proxy behavior. For `https://` targets the library establishes a CONNECT tunnel; for `http://` targets it sends an absolute-form request target without CONNECT.

```cpp
struct ProxyConfig final {
    bool Enabled;
    SOCKADDR_STORAGE Address;
    const char* Authority;
    SIZE_T AuthorityLength;
    const char* AuthHeader;
    SIZE_T AuthHeaderLength;
};
```

| Field | Default | Description |
|-------|---------|-------------|
| `Enabled` | `false` | Whether to enable proxy |
| `Address` | `{}` | Proxy socket address |
| `Authority` / `AuthorityLength` | `nullptr` / `0` | Proxy authority, e.g. `proxy.example:8080`; used as CONNECT authority for HTTPS and as proxy identity for plaintext HTTP |
| `AuthHeader` / `AuthHeaderLength` | `nullptr` / `0` | Optional `Proxy-Authorization` value, sent only to proxy |

#### `SessionConfig`

The `SessionConfig` struct configures session-level parameters when creating a `Session`.

```cpp
struct SessionConfig final {
    PoolType ResponsePool;
    SIZE_T RequestBufferBytes;
    SIZE_T MaxResponseBytes;
    ULONG PoolCapacity;
    ULONG MaxConnsPerHost;
    ULONG IdleTimeoutMs;
    bool EnableHttp11Pipeline;
    ULONG Http11PipelineMaxDepth;
    ULONG Http11PipelineMethodMask;
    Http2KeepAliveConfig Http2KeepAlive;
    TlsConfig Tls;
    ProxyConfig Proxy;
    Cache* Cache;
};
```

| Field | Default | Description |
|-------|---------|-------------|
| `ResponsePool` | `NonPaged` | Response buffer pool type; kernel path requires `NonPaged` |
| `RequestBufferBytes` | `16 KiB` | HTTP/1.1 request line, headers, and body construction buffer |
| `MaxResponseBytes` | `0` | 0 means no caller-set aggregate response body limit |
| `PoolCapacity` | `8` | Connection pool total capacity |
| `MaxConnsPerHost` | `2` | Maximum connections per host |
| `IdleTimeoutMs` | `30000` | Idle connection回收 time (ms) |
| `EnableHttp11Pipeline` | `false` | Explicit HTTP/1.1 pipeline switch; off by default |
| `Http11PipelineMaxDepth` | `DefaultHttp11PipelineMaxDepth` | Max in-flight depth for one HTTP/1.1 pipeline; default 4, hard max 64 |
| `Http11PipelineMethodMask` | `DefaultHttp11PipelineMethodMask` | Allowed method mask for pipelining; defaults to `GET` / `HEAD` / `OPTIONS` |
| `Http2KeepAlive` | disabled | HTTP/2 pooled-connection background PING keepalive; set `Enabled=true` and tune `IdleMs` / `IntervalMs` / `AckTimeoutMs` |
| `Tls` | `DefaultTlsConfig()` | Session default TLS config |
| `Proxy` | disabled | HTTP proxy config; HTTPS uses CONNECT, plaintext HTTP uses absolute-form |
| `Cache` | `nullptr` | Session default RFC 9111 in-memory cache; `nullptr` disables automatic caching |

#### `SendOptions`

The `SendOptions` struct controls single synchronous send behavior. Must be created via `SendOptionsCreate`.

```cpp
struct SendOptions final {
    SIZE_T MaxResponseBytes;
    ULONG Flags;
    ULONG MaxRedirects;
    ULONG ExpectContinueTimeoutMs;
    HeaderCallback OnHeader;
    BodyCallback OnBody;
    void* CallbackContext;
    TlsConfig Tls;
    bool HasTlsOverride;
    ConnPolicy ConnectionPolicy;
    AddressFamily Family;
    Http2CleartextMode Http2CleartextMode;
    const ::KernelHttp::http2::Http2Priority* Http2Priority;
    Cache* Cache;
};
```

| Field | Default | Description |
|-------|---------|-------------|
| `MaxResponseBytes` | `0` | 0 means no per-send response body limit |
| `Flags` | `SendFlagNone` | Send flags |
| `MaxRedirects` | `0` | 0 uses engine default redirect limit |
| `ExpectContinueTimeoutMs` | `1000` | Wait time for `100 Continue` after `SendFlagExpectContinue`; timeout sends the body per RFC timing |
| `OnHeader` | `nullptr` | Response header callback |
| `OnBody` | `nullptr` | Response body chunk callback |
| `CallbackContext` | `nullptr` | Context passed to `OnHeader` / `OnBody` |
| `Tls` | `DefaultTlsConfig()` | Per-send TLS config |
| `HasTlsOverride` | `false` | When `true`, use `Tls` to override session TLS config |
| `ConnectionPolicy` | `ReuseOrCreate` | Per-send connection policy |
| `Cache` | `nullptr` | Per-send RFC 9111 cache; non-null overrides the session default cache |
| `Family` | `Any` | Per-send address family |
| `Http2CleartextMode` | `Disabled` | Explicit high-level h2c entry: `Disabled` / `PriorKnowledge` / `Upgrade`, only for `http://` |
| `Http2Priority` | `nullptr` | HTTP/2 per-request priority; when non-null, the first HEADERS frame carries the priority field. Ignored on HTTP/1.1 paths |

#### `AsyncOptions`

The `AsyncOptions` struct controls single asynchronous HTTP send behavior.

```cpp
struct AsyncOptions final {
    SendOptions Send;
    CompletionCallback OnComplete;
    void* CompletionContext;
};
```

| Field | Default | Description |
|-------|---------|-------------|
| `Send` | `DefaultSendOptions()` | Sync send options used for async send |
| `OnComplete` | `nullptr` | Async completion callback |
| `CompletionContext` | `nullptr` | Context passed to `OnComplete` |

#### `NameValuePair`

The `NameValuePair` struct describes form-url-encoded fields for `BodyCreateForm`.

```cpp
struct NameValuePair final {
    const char* Name;
    SIZE_T NameLength;
    const char* Value;
    SIZE_T ValueLength;
};
```

**NOTE**: `BodyCreateForm` copies the `NameValuePair` descriptor array, but the name/value bytes pointed to by the fields are used by reference and must remain valid until the send completes.

#### `MultipartPart`

The `MultipartPart` struct describes multipart/form-data parts for `BodyCreateMultipart`.

```cpp
struct MultipartPart final {
    BodyPartKind Kind;
    const char* Name;
    SIZE_T NameLength;
    const char* Value;
    SIZE_T ValueLength;
    const UCHAR* Data;
    SIZE_T DataLength;
    const char* FilePath;
    SIZE_T FilePathLength;
    const char* FileName;
    SIZE_T FileNameLength;
    const char* ContentType;
    SIZE_T ContentTypeLength;
};
```

| Field | Description |
|-------|-------------|
| `Kind` | `Field` for normal field; `FileBytes` for in-memory file; `FilePath` for file from path |
| `Name` / `NameLength` | Form field name |
| `Value` / `ValueLength` | Field value for `Field` kind |
| `Data` / `DataLength` | File content bytes for `FileBytes` kind |
| `FilePath` / `FilePathLength` | File path for `FilePath` kind |
| `FileName` / `FileNameLength` | Multipart filename |
| `ContentType` / `ContentTypeLength` | Part Content-Type; CR/LF injection prohibited |

**NOTE**: `BodyCreateMultipart` copies the part descriptor array, but the pointers within parts are used by reference and must remain valid until the send completes.

#### `kws` WebSocket Structs

##### `kws::Header`

The `Header` struct is used to add extra HTTP headers during WebSocket connection.

```cpp
struct Header final {
    const char* Name;
    SIZE_T NameLength;
    const char* Value;
    SIZE_T ValueLength;
};
```

Headers that can be added include `Origin`, `Authorization`, `Cookie`, etc. Library-controlled headers like `Host`, `Connection`, `Upgrade`, `Sec-WebSocket-*` will be rejected.

##### `kws::ConnectConfig`

The `ConnectConfig` struct configures WebSocket connection parameters.

```cpp
struct ConnectConfig final {
    const char* Url;
    SIZE_T UrlLength;
    const char* Subprotocol;
    SIZE_T SubprotocolLength;
    const Header* Headers;
    SIZE_T HeaderCount;
    khttp::TlsConfig Tls;
    khttp::AddressFamily Family;
    SIZE_T MaxMessageBytes;
    bool AutoReplyPing;
    bool AllowWebSocketOverHttp2;
};
```

| Field | Default | Description |
|-------|---------|-------------|
| `Url` / `UrlLength` | `nullptr` / `0` | `ws://` or `wss://` URL; required |
| `Subprotocol` / `SubprotocolLength` | `nullptr` / `0` | Optional `Sec-WebSocket-Protocol` |
| `Headers` / `HeaderCount` | `nullptr` / `0` | Extra headers for opening handshake |
| `Tls` | `DefaultTlsConfig()` | TLS config for `wss://` |
| `Family` | `Any` | Address family |
| `MaxMessageBytes` | `DefaultMaxWebSocketMessageBytes` | Default per-message limit |
| `AutoReplyPing` | `true` | Auto-reply pong on ping |
| `AllowWebSocketOverHttp2` | `false` | Explicit opt-in for RFC 8441 WebSocket over HTTP/2 |

##### `kws::SendOptions`

The `SendOptions` struct controls WebSocket message send behavior.

```cpp
struct SendOptions final {
    bool FinalFragment;
};
```

`FinalFragment=false` is used for non-final frames of fragmented messages; subsequent frames use `SendContinuation` / `SendContinuationEx`.

##### `kws::ReceiveOptions`

The `ReceiveOptions` struct controls WebSocket message receive behavior.

```cpp
struct ReceiveOptions final {
    SIZE_T MaxMessageBytes;
    bool AutoAllocate;
    MessageCallback OnMessage;
    void* CallbackContext;
};
```

| Field | Default | Description |
|-------|---------|-------------|
| `MaxMessageBytes` | `0` | 0 uses connection default message limit |
| `AutoAllocate` | `true` | Whether library auto-allocates message buffer |
| `OnMessage` | `nullptr` | Callback on message/chunk received |
| `CallbackContext` | `nullptr` | Context passed to `OnMessage` |

##### `kws::Message`

The `Message` struct represents a received WebSocket message.

```cpp
struct Message final {
    MsgType Type;
    const UCHAR* Data;
    SIZE_T DataLength;
    bool Final;
    bool FinalFragment;
};
```

**NOTE**: `Data` points to library internal buffer; valid until next receive or close.

### Function Overview

The following functions are provided by the high-level API. They are grouped by functionality:

#### Default Config Functions

These functions return default values for various config structs:

| Function | Description |
|----------|-------------|
| `DefaultTlsConfig` | Returns default TLS config value |
| `DefaultSessionConfig` | Returns default session config value |
| `DefaultSendOptions` | Returns default send options value; prefer `SendOptionsCreate` for actual use |
| `kws::DefaultConnectConfig` | Returns default WebSocket connection config value |

#### HTTP Lifecycle and Handles

These functions manage HTTP session and request handle creation and destruction:

| Function | Description |
|----------|-------------|
| `SessionCreate` | Creates high-level session; internally initializes hidden WSK runtime |
| `SessionClose` | Closes session; releases hidden WSK runtime |
| `RequestCreate` | Creates send handle bound to session |
| `RequestRelease` | Releases send handle |
| `Destroy` | Waits/cleans up library-level async runtime |
| `CacheCreate` / `CacheRelease` / `CacheClear` / `CacheGetStats` | Create, release, clear, and inspect the RFC 9111 in-memory cache |

#### Headers / Body / Options

These functions build request headers, request body, and send options:

| Function | Description |
|----------|-------------|
| `HeadersCreate` / `HeadersAdd` / `HeadersAddEx` / `HeadersRelease` | Create, add, release request header collection |
| `BodyCreateBytes*` | Create raw bytes request body |
| `BodyCreateText*` | Create text request body with optional Content-Type |
| `BodyCreateJson*` | Create JSON bytes request body; does not parse JSON |
| `BodyCreateForm` | Create `application/x-www-form-urlencoded` request body |
| `BodyCreateMultipart` | Create `multipart/form-data` request body |
| `BodyCreateFile*` | Create file request body |
| `BodyCreateStream` | Create streaming request body read callback |
| `BodySetMode` | Set Content-Length or chunked framing |
| `BodyAddTrailer*` | Add trailer for chunked body |
| `BodyRelease` | Release request body handle |
| `SendOptionsCreate` / `SendOptionsRelease` | Create/release sync send options |
| `AsyncOptionsCreate` / `AsyncOptionsRelease` | Create/release async send options |

#### Synchronous HTTP

These functions send synchronous HTTP requests:

| Function | Description |
|----------|-------------|
| `Send` / `SendEx` | Generic sync send entry; explicitly pass method, URL, headers, body, options |
| `Get` / `GetEx` | Send GET |
| `Post` / `PostEx` | Send POST |
| `Put` / `PutEx` | Send PUT |
| `Patch` / `PatchEx` | Send PATCH |
| `Delete` / `DeleteEx` | Send DELETE |
| `Head` / `HeadEx` | Send HEAD |
| `Options` / `OptionsEx` | Send HTTP OPTIONS |

#### Asynchronous HTTP and Async Operations

These functions send asynchronous HTTP requests and manage async operations:

| Function | Description |
|----------|-------------|
| `AsyncSend` / `AsyncSendEx` | Generic async send entry |
| `AsyncGet*` / `AsyncPost*` / `AsyncPut*` / `AsyncPatch*` / `AsyncDelete*` / `AsyncHead*` | Async convenience functions |
| `AsyncOptionsRequest*` | Async HTTP OPTIONS function |
| `AsyncWait` | Wait for async operation completion |
| `AsyncCancel` | Request cancel of async operation |
| `AsyncGetStatus` | Read async operation status |
| `AsyncIsCompleted` | Check if completed |
| `AsyncIsCanceled` | Check if canceled |
| `AsyncGetResponse` | Get HTTP async response |
| `AsyncRelease` | Release async operation |

#### Response

These functions read HTTP responses:

| Function | Description |
|----------|-------------|
| `ResponseStatusCode` | Read HTTP status code |
| `ResponseBody` / `ResponseBodyLength` | Read aggregated response body pointer and length |
| `ResponseHeaderCount` / `ResponseTrailerCount` | Read response header/trailer count |
| `ResponseGetHeader` / `ResponseGetHeaderAt` | Read response header by name or index |
| `ResponseGetTrailer` / `ResponseGetTrailerAt` | Read response trailer by name or index |
| `ResponseRelease` | Release response handle |

#### WebSocket

These functions handle WebSocket connections and communication:

| Function | Description |
|----------|-------------|
| `kws::Connect` / `ConnectEx` | Synchronous WebSocket connection |
| `kws::ConnectAsync` / `ConnectAsyncEx` | Asynchronous WebSocket connection |
| `kws::AsyncGetWebSocket` | Get WebSocket handle from async operation |
| `kws::SendText*` / `SendBinary*` / `SendContinuation*` / `SendPing` / `SendPong` | Send WebSocket frames |
| `kws::Receive` / `ReceiveEx` | Receive WebSocket messages |
| `kws::Close` / `CloseEx` | Close WebSocket |
| `kws::SelectedSubprotocol` | Query negotiated subprotocol |

### Detailed Function Reference

#### Default Config Functions

##### `DefaultTlsConfig`

```cpp
TlsConfig DefaultTlsConfig() noexcept;
```

Returns default TLS config value. This is a convenience function so you don't need to manually initialize each field.

No parameters.

Returns: `TlsConfig` value with default TLS config fields.

##### `DefaultSessionConfig`

```cpp
SessionConfig DefaultSessionConfig() noexcept;
```

Returns default session config value. This config works for most scenarios.

No parameters.

Returns: `SessionConfig` value.

##### `DefaultSendOptions`

```cpp
SendOptions DefaultSendOptions() noexcept;
```

Returns default send options value. For actual high-level calls, prefer `SendOptionsCreate` to create a heap object
and modify fields; this function is mainly for internal and compatibility scenarios.

No parameters.

Returns: `SendOptions` value.

#### Lifecycle Functions

##### `SessionCreate`

```cpp
NTSTATUS SessionCreate(
    _Out_ Session** session
) noexcept;

NTSTATUS SessionCreate(
    _In_opt_ const SessionConfig* config,
    _Out_ Session** session
) noexcept;
```

Creates a high-level HTTP/WS session. The session internally initializes the hidden WSK runtime and creates engine
session, connection pool, workspace, TLS provider cache, etc. This is the first step in using the high-level API.

| Parameter | Description |
|-----------|-------------|
| `config` | Session config; `nullptr` uses `DefaultSessionConfig()` |
| `session` | Receives `Session*` on success; set to `nullptr` on failure |

| Return Value | Meaning |
|--------------|---------|
| `STATUS_SUCCESS` | Created successfully |
| `STATUS_INVALID_PARAMETER` | `session == nullptr` or invalid config |
| `STATUS_INSUFFICIENT_RESOURCES` | Failed to allocate session, WSK runtime, or internal resources |
| Other failure | WSK initialization or engine session creation failed |

NOTE: Must call `SessionClose` after success. High-level `SessionCreate` does not accept `net::WskClient*`; this is an
internal implementation detail. You can still release `Request` objects created by this session before `SessionClose`,
but do not continue using old `Request` for sends after session close.

##### `SessionClose`

```cpp
void SessionClose(
    _In_opt_ Session* session
) noexcept;
```

Closes and releases the session. This is a safe function that accepts `nullptr`.

| Parameter | Description |
|-----------|-------------|
| `session` | Session to close; `nullptr` returns immediately |

No return value.

NOTE: Closing the session closes the internal engine session and the hidden WSK runtime. If you used async APIs, you
must also call `Destroy()` before driver unload.

##### `RequestCreate`

```cpp
NTSTATUS RequestCreate(
    _In_ Session* session,
    _Out_ Request** out
) noexcept;
```

Creates a send handle bound to `Session`. `Request` can be used as the first parameter of `Send*` / `AsyncSend*`,
equivalent to `Session*`.

| Parameter | Description |
|-----------|-------------|
| `session` | Parent session |
| `out` | Receives `Request*` on success |

| Return Value | Meaning |
|--------------|---------|
| `STATUS_SUCCESS` | Created successfully |
| `STATUS_INVALID_PARAMETER` | Parameter is null, session invalid, or session closed |
| `STATUS_INSUFFICIENT_RESOURCES` | Allocation failed |

NOTE: `Request` is no longer a builder. method, URL, headers, body, options are all passed in `Send*` / `AsyncSend*`
calls. This design allows the same `Request` to be used for multiple sends.

##### `RequestRelease`

```cpp
void RequestRelease(
    _In_opt_ Request* request
) noexcept;
```

Releases the `Request` send handle. This is a safe function that accepts `nullptr`.

| Parameter | Description |
|-----------|-------------|
| `request` | Request handle to release |

No return value.

##### `Destroy`

```cpp
void Destroy() noexcept;
```

Library-level async cleanup entry point. This function cleans up async runtime resources.

No parameters.

No return value.

NOTE: Must call after using HTTP or WebSocket async APIs before driver unload. Safe to call unconditionally on
sync-only paths.

#### Headers Functions

##### `HeadersCreate`

```cpp
NTSTATUS HeadersCreate(
    _Out_ Headers** headers
) noexcept;
```

Creates an empty request header collection. This is the first step in building request headers.

| Parameter | Description |
|-----------|-------------|
| `headers` | Receives `Headers*` on success; set to `nullptr` on failure |

| Return Value | Meaning |
|--------------|---------|
| `STATUS_SUCCESS` | Created successfully |
| `STATUS_INVALID_PARAMETER` | `headers == nullptr` |
| `STATUS_INSUFFICIENT_RESOURCES` | Allocation failed |

##### `HeadersAdd` / `HeadersAddEx`

```cpp
NTSTATUS HeadersAdd(
    _Inout_ Headers* headers,
    _In_ const char* name,
    _In_ const char* value
) noexcept;

NTSTATUS HeadersAddEx(
    _Inout_ Headers* headers,
    _In_ const char* name,
    _In_ SIZE_T nameLength,
    _In_ const char* value,
    _In_ SIZE_T valueLength
) noexcept;
```

Adds or overwrites a request header in `Headers`. Deduplicates by case-insensitive field name; same-name fields
overwrite the old value. `HeadersAdd` is the convenience version requiring NUL-terminated strings; `Allows` specifying
length for non-NUL-terminated strings.

| Parameter | Description |
|-----------|-------------|
| `headers` | Handle returned by `HeadersCreate` |
| `name` | Header name; `HeadersAdd` requires NUL-terminated |
| `nameLength` | Header name byte length, excluding NUL |
| `value` | Header value; `HeadersAdd` requires NUL-terminated |
| `valueLength` | Header value byte length, excluding NUL |

| Return Value | Meaning |
|--------------|---------|
| `STATUS_SUCCESS` | Added or overwritten successfully |
| `STATUS_INVALID_PARAMETER` | Invalid handle, illegal name, CR/LF in value, or attempted to add library-controlled
header |
| `STATUS_INSUFFICIENT_RESOURCES` | Exceeded header count limit or failed to copy name/value |

**Ownership and restrictions**: name/value are always copied to heap; source buffer can be modified or freed after
call returns. CR/LF injection is prohibited. Library-controlled headers like `Host`, `Content-Length`, connection
framing fields are synthesized or rejected by the library.

##### `HeadersRelease`

```cpp
void HeadersRelease(
    _In_opt_ Headers* headers
) noexcept;
```

Releases the request header collection and its copied name/value. This is a safe function that accepts `nullptr`.

| Parameter | Description |
|-----------|-------------|
| `headers` | Header collection to release |

No return value.

#### Body Functions

##### Body Reference vs Copy Rules

Understanding Body memory management rules is important:

| Function Family | Data Ownership | Lifetime Requirement |
|-----------------|----------------|---------------------|
| `BodyCreateBytes` / `BodyCreateText` / `BodyCreateJson` | References caller bytes | Valid until sync send returns or
async send completes/cancels |
| `BodyCreateBytesCopy` / `BodyCreateTextCopy` / `BodyCreateJsonCopy` | Copies bytes to heap on creation | Source
buffer can be freed after creation |
| `BodyCreateForm` | Copies pair descriptor array; pair pointers used by reference | name/value bytes must remain
valid until send completes |
| `BodyCreateMultipart` | Copies part descriptor array; part pointers used by reference | bytes pointed to by parts
must remain valid until send completes |
| `BodyCreateFile` / `BodyCreateFileEx` | Copies file path and Content-Type | File content read at send time |

**Simple rule**: If unsure, prefer functions with `Copy` suffix so you don't need to worry about data lifetime.

##### `BodyCreateBytes` / `BodyCreateBytesEx`

```cpp
NTSTATUS BodyCreateBytes(
    _In_opt_ const UCHAR* data,
    _In_ SIZE_T dataLength,
    _Out_ Body** body
) noexcept;

NTSTATUS BodyCreateBytesEx(
    _In_opt_ const UCHAR* data,
    _In_ SIZE_T dataLength,
    _Out_ Body** body
) noexcept;
```

Creates a raw bytes body referencing caller memory, without setting Content-Type. This is the most basic body creation
function.

| Parameter | Description |
|-----------|-------------|
| `data` | Request body bytes; can be NULL when `dataLength == 0` |
| `dataLength` | Byte length |
| `body` | Receives `Body*` on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

##### `BodyCreateBytesCopy` / `BodyCreateBytesCopyEx`

```cpp
NTSTATUS BodyCreateBytesCopy(
    _In_opt_ const UCHAR* data,
    _In_ SIZE_T dataLength,
    _Out_ Body** body
) noexcept;

NTSTATUS BodyCreateBytesCopyEx(
    _In_opt_ const UCHAR* data,
    _In_ SIZE_T dataLength,
    _Out_ Body** body
) noexcept;
```

Creates a raw bytes body and copies caller bytes on creation. After success, `data` can be immediately freed or
modified. This is the safer version.

Parameters and return values: Same as `BodyCreateBytes`

##### `BodyCreateText` / `BodyCreateTextEx`

```cpp
NTSTATUS BodyCreateText(
    _In_opt_ const char* text,
    _In_ SIZE_T textLength,
    _In_opt_ const char* contentType,
    _Out_ Body** body
) noexcept;

NTSTATUS BodyCreateTextEx(
    _In_opt_ const char* text,
    _In_ SIZE_T textLength,
    _In_opt_ const char* contentType,
    _In_ SIZE_T contentTypeLength,
    _Out_ Body** body
) noexcept;
```

Creates a text body referencing caller text bytes, with optional Content-Type. Suitable for sending plain text, HTML,
XML, etc.

| Parameter | Description |
|-----------|-------------|
| `text` | Text bytes; not required to be NUL-terminated; can be NULL when `textLength == 0` |
| `textLength` | Text byte length |
| `contentType` | Content-Type; `BodyCreateText` requires NUL-terminated |
| `contentTypeLength` | Content-Type byte length, excluding NUL |
| `body` | Receives `Body*` on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

##### `BodyCreateTextCopy` / `BodyCreateTextCopyEx`

```cpp
NTSTATUS BodyCreateTextCopy(
    _In_opt_ const char* text,
    _In_ SIZE_T textLength,
    _In_opt_ const char* contentType,
    _Out_ Body** body
) noexcept;

NTSTATUS BodyCreateTextCopyEx(
    _In_opt_ const char* text,
    _In_ SIZE_T textLength,
    _In_opt_ const char* contentType,
    _In_ SIZE_T contentTypeLength,
    _Out_ Body** body
) noexcept;
```

Creates a text body and copies text and Content-Type. After success, source buffers can be immediately freed or
modified. Safer version.

Parameters and return values: Same as `BodyCreateText`

##### `BodyCreateJson` / `BodyCreateJsonEx`

```cpp
NTSTATUS BodyCreateJson(
    _In_opt_ const char* json,
    _In_ SIZE_T jsonLength,
    _Out_ Body** body
) noexcept;

NTSTATUS BodyCreateJsonEx(
    _In_opt_ const char* json,
    _In_ SIZE_T jsonLength,
    _Out_ Body** body
) noexcept;
```

Creates a body referencing caller JSON bytes and sets `Content-Type: application/json; charset=utf-8`. Note: library
does not parse or validate JSON.

| Parameter | Description |
|-----------|-------------|
| `json` | JSON bytes; library does not parse or validate; can be NULL when `jsonLength == 0` |
| `jsonLength` | JSON byte length |
| `body` | Receives `Body*` on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

##### `BodyCreateJsonCopy` / `BodyCreateJsonCopyEx`

```cpp
NTSTATUS BodyCreateJsonCopy(
    _In_opt_ const char* json,
    _In_ SIZE_T jsonLength,
    _Out_ Body** body
) noexcept;

NTSTATUS BodyCreateJsonCopyEx(
    _In_opt_ const char* json,
    _In_ SIZE_T jsonLength,
    _Out_ Body** body
) noexcept;
```

Creates a JSON body and copies JSON bytes. After success, `json` source buffer can be immediately freed or modified.
Safer version.

Parameters and return values: Same as `BodyCreateJson`

##### `BodyCreateForm`

```cpp
NTSTATUS BodyCreateForm(
    _In_ const NameValuePair* pairs,
    _In_ SIZE_T pairCount,
    _Out_ Body** body
) noexcept;
```

Creates an `application/x-www-form-urlencoded` body. Suitable for submitting form data.

| Parameter | Description |
|-----------|-------------|
| `pairs` | Form field array |
| `pairCount` | Field count; must be > 0 and not exceed per-request field limit |
| `body` | Receives `Body*` on success |

| Return Value | Meaning |
|--------------|---------|
| `STATUS_SUCCESS` | Created successfully |
| `STATUS_INVALID_PARAMETER` | `pairs` is null, count invalid, or fields invalid |
| `STATUS_INSUFFICIENT_RESOURCES` | Allocation failed |

##### `BodyCreateMultipart`

```cpp
NTSTATUS BodyCreateMultipart(
    _In_ const MultipartPart* parts,
    _In_ SIZE_T partCount,
    _Out_ Body** body
) noexcept;
```

Creates a `multipart/form-data` body. Suitable for file uploads and complex form submissions.

| Parameter | Description |
|-----------|-------------|
| `parts` | Multipart part array |
| `partCount` | Part count; must be > 0 and not exceed per-request field limit |
| `body` | Receives `Body*` on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

##### `BodyCreateFile` / `BodyCreateFileEx`

```cpp
NTSTATUS BodyCreateFile(
    _In_ const char* filePath,
    _In_opt_ const char* contentType,
    _Out_ Body** body
) noexcept;

NTSTATUS BodyCreateFileEx(
    _In_ const char* filePath,
    _In_ SIZE_T filePathLength,
    _In_opt_ const char* contentType,
    _In_ SIZE_T contentTypeLength,
    _Out_ Body** body
) noexcept;
```

Creates a file request body. Library copies file path and Content-Type; file content is read at send time. Suitable
for uploading local files.

| Parameter | Description |
|-----------|-------------|
| `filePath` | File path; `BodyCreateFile` requires NUL-terminated |
| `filePathLength` | File path byte length |
| `contentType` | Content-Type; NULL means don't explicitly set |
| `contentTypeLength` | Content-Type byte length |
| `body` | Receives `Body*` on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

##### `BodyCreateStream`

```cpp
NTSTATUS BodyCreateStream(
    _In_ RequestBodyReadCallback callback,
    _In_opt_ void* context,
    SIZE_T contentLength,
    bool contentLengthKnown,
    _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
    SIZE_T contentTypeLength,
    _Out_ Body** body
) noexcept;
```

Creates a streaming request body. With `contentLengthKnown=true`, the request sends `Content-Length`; for unknown length, usually pair it with `BodySetMode(body, RequestBodyMode::Chunked)` so the library generates chunked framing. The callback context must remain valid for the whole send.

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

##### `BodySetMode`

```cpp
NTSTATUS BodySetMode(
    _Inout_ Body* body,
    _In_ RequestBodyMode mode
) noexcept;
```

Sets request body framing mode. Default is `ContentLength` for known-size bodies; `Chunked` for streaming data.

| Parameter | Description |
|-----------|-------------|
| `body` | Body handle |
| `mode` | `ContentLength` or `Chunked` |

Returns: `STATUS_SUCCESS` or `STATUS_INVALID_PARAMETER`

##### `BodyAddTrailer` / `BodyAddTrailerEx`

```cpp
NTSTATUS BodyAddTrailer(
    _Inout_ Body* body,
    _In_ const char* name,
    _In_ const char* value
) noexcept;

NTSTATUS BodyAddTrailerEx(
    _Inout_ Body* body,
    _In_ const char* name,
    _In_ SIZE_T nameLength,
    _In_ const char* value,
    _In_ SIZE_T valueLength
) noexcept;
```

Adds trailer fields for chunked request body. Trailers are extra header fields sent after the request body, commonly
used for signatures or checksums.

| Parameter | Description |
|-----------|-------------|
| `body` | Body handle |
| `name` | Trailer name |
| `nameLength` | Trailer name byte length |
| `value` | Trailer value |
| `valueLength` | Trailer value byte length |

| Return Value | Meaning |
|--------------|---------|
| `STATUS_SUCCESS` | Added successfully |
| `STATUS_INVALID_PARAMETER` | Invalid parameter, illegal name, CR/LF in value |
| `STATUS_NOT_SUPPORTED` | Trailer field prohibited, e.g. `Content-Length`, `Transfer-Encoding`, `Host`, auth or
cookie fields |
| `STATUS_INSUFFICIENT_RESOURCES` | Exceeded count limit or copy failed |

NOTE: Trailers are only sent after `BodySetMode(body, RequestBodyMode::Chunked)`.

##### `BodyRelease`

```cpp
void BodyRelease(
    _In_opt_ Body* body
) noexcept;
```

Releases body handle and its owned heap memory. Safe function, accepts `nullptr`.

| Parameter | Description |
|-----------|-------------|
| `body` | Body handle; can be NULL |

No return value.

#### Options Functions

##### `SendOptionsCreate`

```cpp
NTSTATUS SendOptionsCreate(
    _Out_ SendOptions** options
) noexcept;
```

Creates `SendOptions` on heap with default values. Recommended way to create send options.

| Parameter | Description |
|-----------|-------------|
| `options` | Receives `SendOptions*` on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

##### `SendOptionsRelease`

```cpp
void SendOptionsRelease(
    _In_opt_ SendOptions* options
) noexcept;
```

Releases `SendOptions`. Safe function, accepts `nullptr`.

| Parameter | Description |
|-----------|-------------|
| `options` | Send options handle; can be NULL |

No return value.

##### `AsyncOptionsCreate`

```cpp
NTSTATUS AsyncOptionsCreate(
    _Out_ AsyncOptions** options
) noexcept;
```

Creates `AsyncOptions` on heap with default values. Recommended way to create async send options.

| Parameter | Description |
|-----------|-------------|
| `options` | Receives `AsyncOptions*` on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`

##### `AsyncOptionsRelease`

```cpp
void AsyncOptionsRelease(
    _In_opt_ AsyncOptions* options
) noexcept;
```

Releases `AsyncOptions`. Safe function, accepts `nullptr`.

| Parameter | Description |
|-----------|-------------|
| `options` | Async options handle; can be NULL |

No return value.

#### Synchronous HTTP Functions

##### `Send` / `SendEx` and Convenience Functions

There are two ways to send HTTP requests:

```cpp
// Generic: need to manually pass Method
NTSTATUS Send(Session* session, Method method, const char* url,
              const Headers* headers, const Body* body,
              const SendOptions* options, Response** response);
NTSTATUS SendEx(Session* session, Method method, const char* url, SIZE_T urlLength, ...);

// Convenience: function name is the HTTP method
NTSTATUS Get(Session* session, const char* url, Response** response);
NTSTATUS GetEx(Session* session, const char* url, SIZE_T urlLength,
               const Headers* headers, const SendOptions* options, Response** response);

NTSTATUS Post(Session* session, const char* url, const Body* body, Response** response);
NTSTATUS PostEx(Session* session, const char* url, SIZE_T urlLength,
                const Headers* headers, const Body* body,
                const SendOptions* options, Response** response);

// ... Put, Patch, Delete, Head, Options similar
```

`Send` / `SendEx` are generic entry points suitable for all scenarios. Convenience functions (`Get`, `Post`, etc.) are
syntactic sugar that save you from manually constructing `Method` enum. Both approaches are completely equivalent at
the implementation level.

**NOTE**: `Request*` can also be used as the first parameter, equivalent to `Session*`.

| Parameter | Description |
|-----------|-------------|
| `session` / `request` | Session or request handle |
| `method` | HTTP method; only needed for `Send` / `SendEx` |
| `url` | Request URL; non-`Ex` versions require NUL-terminated |
| `urlLength` | URL byte length; only for `Ex` versions |
| `headers` | Request header collection; `nullptr` uses library default headers only |
| `body` | Request body; `nullptr` means no body. `Get`/`Delete`/`Head`/`Options` don't have this parameter |
| `options` | Send options; `nullptr` uses defaults |
| `response` | Receives `Response*` on success; remember to release with `ResponseRelease` |

| Return Value | Meaning |
|--------------|---------|
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

NOTE: Library automatically synthesizes `Host`, `Content-Length` and other protocol-required headers. Your `headers`
will override library defaults (where allowed). Do not manually set library-controlled headers; they will be rejected
or ignored.

#### Asynchronous HTTP Functions

##### `AsyncSend` / `AsyncSendEx` and Convenience Functions

Like sync functions, async also has generic entry and convenience functions:

```cpp
// Generic
NTSTATUS AsyncSend(Session* session, Method method, const char* url,
                   const Headers* headers, const Body* body,
                   const AsyncOptions* options, AsyncOp** operation);
NTSTATUS AsyncSendEx(Session* session, Method method, const char* url, SIZE_T urlLength, ...);

// Convenience functions
NTSTATUS AsyncGet(Session* session, const char* url, AsyncOp** operation);
NTSTATUS AsyncGetEx(Session* session, const char* url, SIZE_T urlLength,
                    const Headers* headers, const AsyncOptions* options, AsyncOp** operation);

NTSTATUS AsyncPost(Session* session, const char* url, const Body* body, AsyncOp** operation);
NTSTATUS AsyncPostEx(Session* session, const char* url, SIZE_T urlLength,
                     const Headers* headers, const Body* body,
                     const AsyncOptions* options, AsyncOp** operation);

// ... AsyncPut, AsyncPatch, AsyncDelete, AsyncHead similar
// Note: Async HTTP OPTIONS is called AsyncOptionsRequest, not AsyncOptions (to avoid name collision)
```

| Parameter | Description |
|-----------|-------------|
| `session` / `request` | Session or request handle |
| `method` | HTTP method; only for `AsyncSend` / `AsyncSendEx` |
| `url` / `urlLength` | URL and length |
| `headers` | Request header collection |
| `body` | Request body. `AsyncGet`/`AsyncDelete`/`AsyncHead` don't have this |
| `options` | Async send options; `nullptr` uses defaults |
| `operation` | Receives `AsyncOp*` on success |

| Return Value | Meaning |
|--------------|---------|
| `STATUS_SUCCESS` | Async operation created and queued |
| `STATUS_INVALID_PARAMETER` | Invalid parameter or handle |
| `STATUS_INSUFFICIENT_RESOURCES` | Allocation failed or async queue full |
| Other failure | Send preparation failed |

**Lifecycle notes**:
- Reference-type `Body` source buffers must remain valid until async operation completes or cancels
- After completion, call `AsyncGetResponse` to get response, then `ResponseRelease`
- Finally call `AsyncRelease`

| Function | HTTP Method | Request Body |
|----------|-------------|--------------|
| `AsyncGet` / `AsyncGetEx` | `GET` | None |
| `AsyncPost` / `AsyncPostEx` | `POST` | Optional |
| `AsyncPut` / `AsyncPutEx` | `PUT` | Optional |
| `AsyncPatch` / `AsyncPatchEx` | `PATCH` | Optional |
| `AsyncDelete` / `AsyncDeleteEx` | `DELETE` | None |
| `AsyncHead` / `AsyncHeadEx` | `HEAD` | None |
| `AsyncOptionsRequest` / `AsyncOptionsRequestEx` | `OPTIONS` | None |

NOTE: `AsyncOptionsRequest` is named this way to avoid collision with `AsyncOptions` type. `AsyncGet`, `AsyncDelete`,
`AsyncHead`, `AsyncOptionsRequest` have no `Body*` parameter; use generic `AsyncSend` for non-typical requests with
body.

#### Async Operation Functions

##### `AsyncWait`

```cpp
NTSTATUS AsyncWait(
    _In_ AsyncOp* operation,
    _In_ ULONG timeoutMs
) noexcept;
```

Waits for async operation to complete. This is the synchronous way to wait for async results.

| Parameter | Description |
|-----------|-------------|
| `operation` | Async operation handle |
| `timeoutMs` | Wait timeout in milliseconds; pass `0xffffffffUL` for infinite wait |

Returns: Completion status, `STATUS_TIMEOUT`, `STATUS_INVALID_PARAMETER`, or failure during wait.

##### `AsyncCancel`

```cpp
NTSTATUS AsyncCancel(
    _In_ AsyncOp* operation
) noexcept;
```

Requests cancellation of async operation. Cancellation is cooperative, not immediate.

| Parameter | Description |
|-----------|-------------|
| `operation` | Async operation handle; cannot be NULL |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, or cancellation failure.

NOTE: After canceling, still call `AsyncWait` to wait for terminal state before releasing.

##### `AsyncGetStatus`

```cpp
NTSTATUS AsyncGetStatus(
    _In_opt_ const AsyncOp* operation
) noexcept;
```

Reads current/final status of async operation. Suitable for non-blocking checks.

| Parameter | Description |
|-----------|-------------|
| `operation` | Async operation handle; can be NULL; returns failure for NULL or invalid handle |

Returns: Current `NTSTATUS`

##### `AsyncIsCompleted`

```cpp
bool AsyncIsCompleted(
    _In_opt_ const AsyncOp* operation
) noexcept;
```

Checks if async operation has completed. Lightweight check, does not block.

| Parameter | Description |
|-----------|-------------|
| `operation` | Async operation handle; can be NULL |

Returns: `true` if completed, `false` if not or handle is NULL

##### `AsyncIsCanceled`

```cpp
bool AsyncIsCanceled(
    _In_opt_ const AsyncOp* operation
) noexcept;
```

Checks if async operation was requested to cancel.

| Parameter | Description |
|-----------|-------------|
| `operation` | Async operation handle; can be NULL |

Returns: `true` if canceled, `false` otherwise

##### `AsyncGetResponse`

```cpp
NTSTATUS AsyncGetResponse(
    _In_ AsyncOp* operation,
    _Out_ Response** response
) noexcept;
```

Extracts response from completed HTTP async operation. Must be called after operation completes.

| Parameter | Description |
|-----------|-------------|
| `operation` | HTTP send async operation |
| `response` | Receives `Response*` on success |

| Return Value | Meaning |
|--------------|---------|
| `STATUS_SUCCESS` | Successfully extracted response |
| `STATUS_INVALID_PARAMETER` | Invalid parameter or operation type |
| `STATUS_PENDING` | Operation not yet complete; call `AsyncWait` first |
| Other failure | Send failed or was canceled |

##### `AsyncRelease`

```cpp
void AsyncRelease(
    _In_opt_ AsyncOp* operation
) noexcept;
```

Releases async operation handle. Safe function, accepts `nullptr`.

| Parameter | Description |
|-----------|-------------|
| `operation` | Async operation handle; can be NULL |

No return value.

#### Response Functions

##### `ResponseStatusCode`

```cpp
ULONG ResponseStatusCode(
    _In_opt_ const Response* response
) noexcept;
```

Reads HTTP status code. This is the first step in checking if a request succeeded.

| Parameter | Description |
|-----------|-------------|
| `response` | Response handle; can be NULL |

Returns: Status code (e.g. 200, 404, 500); returns 0 for NULL or invalid handle.

##### `ResponseBody` / `ResponseBodyLength`

```cpp
const UCHAR* ResponseBody(
    _In_opt_ const Response* response
) noexcept;

SIZE_T ResponseBodyLength(
    _In_opt_ const Response* response
) noexcept;
```

Reads aggregated response body pointer and length. Response body is the complete content automatically aggregated by
the library.

| Parameter | Description |
|-----------|-------------|
| `response` | Response handle; can be NULL |

Returns: `ResponseBody` returns library internal buffer pointer; `ResponseBodyLength` returns byte length. Pointer
valid until `ResponseRelease`.

NOTE: If you set callbacks (`OnBody`), response body may be empty because data was already streamed through callbacks.

##### `ResponseHeaderCount` / `ResponseTrailerCount`

```cpp
SIZE_T ResponseHeaderCount(
    _In_opt_ const Response* response
) noexcept;

SIZE_T ResponseTrailerCount(
    _In_opt_ const Response* response
) noexcept;
```

Reads response header or trailer count. Used for iterating all header fields.

| Parameter | Description |
|-----------|-------------|
| `response` | Response handle; can be NULL |

Returns: Count; returns 0 for NULL or invalid handle.

##### `ResponseGetHeader`

```cpp
NTSTATUS ResponseGetHeader(
    _In_ const Response* response,
    _In_ const char* name,
    _In_ SIZE_T nameLength,
    _Out_ const char** value,
    _Out_ SIZE_T* valueLength
) noexcept;
```

Reads response header by name. Name matching is case-insensitive.

| Parameter | Description |
|-----------|-------------|
| `response` | Response handle |
| `name` | Header name |
| `nameLength` | Name byte length |
| `value` | Receives header value pointer on success |
| `valueLength` | Receives value length on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_NOT_FOUND`

##### `ResponseGetHeaderAt`

```cpp
NTSTATUS ResponseGetHeaderAt(
    _In_ const Response* response,
    _In_ SIZE_T index,
    _Out_ const char** name,
    _Out_ SIZE_T* nameLength,
    _Out_ const char** value,
    _Out_ SIZE_T* valueLength
) noexcept;
```

Enumerates response header by index. Suitable for iterating all headers.

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_NOT_FOUND`

##### `ResponseGetTrailer` / `ResponseGetTrailerAt`

```cpp
NTSTATUS ResponseGetTrailer(
    _In_ const Response* response,
    _In_ const char* name,
    _In_ SIZE_T nameLength,
    _Out_ const char** value,
    _Out_ SIZE_T* valueLength
) noexcept;

NTSTATUS ResponseGetTrailerAt(
    _In_ const Response* response,
    _In_ SIZE_T index,
    _Out_ const char** name,
    _Out_ SIZE_T* nameLength,
    _Out_ const char** value,
    _Out_ SIZE_T* valueLength
) noexcept;
```

Reads response trailer by name or index. Trailers are header fields sent after the response body, commonly used with
chunked transfer.

Parameters and return values: Same as header read functions.

##### `ResponseRelease`

```cpp
void ResponseRelease(
    _In_opt_ Response* response
) noexcept;
```

Releases response handle and its internal buffers. Safe function, accepts `nullptr`.

| Parameter | Description |
|-----------|-------------|
| `response` | Response handle; can be NULL |

No return value.

#### WebSocket Functions

##### `kws::DefaultConnectConfig`

```cpp
kws::ConnectConfig DefaultConnectConfig() noexcept;
```

Returns default WebSocket connection config.

No parameters.

Returns: `ConnectConfig` value.

##### `kws::Connect` / `kws::ConnectEx`

```cpp
NTSTATUS Connect(
    _In_ khttp::Session* session,
    _In_ const char* url,
    _In_ SIZE_T urlLength,
    _Out_ WebSocket** websocket
) noexcept;

NTSTATUS Connect(
    _In_ khttp::Session* session,
    _In_ const ConnectConfig* config,
    _Out_ WebSocket** websocket
) noexcept;

NTSTATUS ConnectEx(
    _In_ khttp::Session* session,
    _In_ const ConnectConfig* config,
    _Out_ WebSocket** websocket
) noexcept;
```

Synchronous WebSocket connection. Function blocks until handshake completes.

| Parameter | Description |
|-----------|-------------|
| `session` | High-level session |
| `url` / `urlLength` | `ws://` or `wss://` URL |
| `config` | Connection config |
| `websocket` | Receives `WebSocket*` on success |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_NOT_SUPPORTED`, network/TLS/HTTP handshake failure.

##### `kws::ConnectAsync` / `kws::ConnectAsyncEx`

```cpp
NTSTATUS ConnectAsync(
    _In_ khttp::Session* session,
    _In_ const char* url,
    _In_ SIZE_T urlLength,
    _Out_ khttp::AsyncOp** operation
) noexcept;

NTSTATUS ConnectAsync(
    _In_ khttp::Session* session,
    _In_ const ConnectConfig* config,
    _Out_ khttp::AsyncOp** operation
) noexcept;

NTSTATUS ConnectAsyncEx(
    _In_ khttp::Session* session,
    _In_ const ConnectConfig* config,
    _Out_ khttp::AsyncOp** operation
) noexcept;
```

Asynchronous WebSocket connection. Parameters similar to `Connect`, but output is `AsyncOp**`. Use `AsyncWait` after
success, then `kws::AsyncGetWebSocket` to get connection.

##### `kws::AsyncGetWebSocket`

```cpp
NTSTATUS AsyncGetWebSocket(
    _In_ khttp::AsyncOp* operation,
    _Out_ WebSocket** websocket
) noexcept;
```

Extracts `WebSocket` handle from completed WebSocket connect async operation.

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_PENDING`, or connection final failure.

##### WebSocket Send Functions

```cpp
NTSTATUS SendText(
    _In_ WebSocket* websocket,
    _In_ const char* text,
    _In_ SIZE_T textLength
) noexcept;

NTSTATUS SendTextEx(
    _In_ WebSocket* websocket,
    _In_ const char* text,
    _In_ SIZE_T textLength,
    _In_opt_ const SendOptions* options
) noexcept;

NTSTATUS SendBinary(
    _In_ WebSocket* websocket,
    _In_ const UCHAR* data,
    _In_ SIZE_T dataLength
) noexcept;

NTSTATUS SendBinaryEx(
    _In_ WebSocket* websocket,
    _In_ const UCHAR* data,
    _In_ SIZE_T dataLength,
    _In_opt_ const SendOptions* options
) noexcept;

NTSTATUS SendContinuation(
    _In_ WebSocket* websocket,
    _In_ const UCHAR* data,
    _In_ SIZE_T dataLength
) noexcept;

NTSTATUS SendContinuationEx(
    _In_ WebSocket* websocket,
    _In_ const UCHAR* data,
    _In_ SIZE_T dataLength,
    _In_opt_ const SendOptions* options
) noexcept;

NTSTATUS SendPing(
    _In_ WebSocket* websocket,
    _In_opt_ const UCHAR* payload,
    _In_ SIZE_T payloadLength
) noexcept;

NTSTATUS SendPong(
    _In_ WebSocket* websocket,
    _In_opt_ const UCHAR* payload,
    _In_ SIZE_T payloadLength
) noexcept;
```

| Parameter | Description |
|-----------|-------------|
| `websocket` | WebSocket handle |
| `text` | Text bytes |
| `data` | Binary or continuation bytes |
| `payload` | Ping/pong payload; can be NULL when `payloadLength == 0` |
| `options` | `FinalFragment` option |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, connection closed/disconnected/timeout failure.

##### `kws::Receive` / `kws::ReceiveEx`

```cpp
NTSTATUS Receive(
    _In_ WebSocket* websocket,
    _Out_ Message* message
) noexcept;

NTSTATUS ReceiveEx(
    _In_ WebSocket* websocket,
    _In_opt_ const ReceiveOptions* options,
    _Out_opt_ Message* message
) noexcept;
```

Receives WebSocket message. Blocking call, waits until message received or error.

| Parameter | Description |
|-----------|-------------|
| `websocket` | WebSocket handle |
| `options` | Receive options |
| `message` | Receives message view on success; can be NULL in `ReceiveEx` |

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_BUFFER_TOO_SMALL`, connection
closed/disconnected/timeout.

##### `kws::Close` / `kws::CloseEx`

```cpp
NTSTATUS Close(
    _In_opt_ WebSocket* websocket
) noexcept;

NTSTATUS CloseEx(
    _In_opt_ WebSocket* websocket,
    _In_ USHORT statusCode,
    _In_opt_ const UCHAR* reason,
    _In_ SIZE_T reasonLength
) noexcept;
```

Closes WebSocket connection. `Close` is simple version; `CloseEx` allows specifying close status code and reason.

| Parameter | Description |
|-----------|-------------|
| `websocket` | WebSocket handle; can be NULL |
| `statusCode` | Close status code |
| `reason` | Close reason; can be NULL when `reasonLength == 0` |
| `reasonLength` | Close reason byte length |

Returns: Close success or transport failure.

NOTE: Do not concurrently execute `Close` and new send/receive on the same `WebSocket`. Close should be the last
operation.

##### `kws::SelectedSubprotocol`

```cpp
NTSTATUS SelectedSubprotocol(
    _In_ WebSocket* websocket,
    _Out_ const char** subprotocol,
    _Out_ SIZE_T* subprotocolLength
) noexcept;
```

Reads the WebSocket subprotocol selected by the server. Call after connection established.

Returns: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_NOT_FOUND`



