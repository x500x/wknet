# Sync HTTP

Namespace: `wknet::http`  
Headers: `wknet/http/Http.h` · `wknet/http/Options.h` · `wknet/http/Types.h`

## Role

Blocking HTTP send: general `Send` / `SendEx`, method helpers, and full `SendOptions` fields.

## Send / SendEx

### Signatures (Session)

```cpp
NTSTATUS Send(
    _In_ Session* session,
    Method method,
    _In_z_ const char* url,
    _In_opt_ const Headers* headers,
    _In_opt_ const Body* body,
    _In_opt_ const SendOptions* options,
    _Out_ Response** response) noexcept;

NTSTATUS SendEx(
    _In_ Session* session,
    Method method,
    _In_reads_bytes_(urlLength) const char* url,
    SIZE_T urlLength,
    _In_opt_ const Headers* headers,
    _In_opt_ const Body* body,
    _In_opt_ const SendOptions* options,
    _Out_ Response** response) noexcept;
```

### Signatures (Request)

Same shape with leading `Request*` overloads of `Send` / `SendEx`.

### Parameters

| Param | Meaning |
|-------|---------|
| `session` / `request` | Session or existing request |
| `method` | `Method::Get` … `Trace` |
| `url` / `urlLength` | Target URL; `Send` requires NUL-terminated |
| `headers` | Optional request headers |
| `body` | Optional body |
| `options` | Optional; `nullptr` uses defaults |
| `response` | Out on success; caller `ResponseRelease` |

### Returns

| Status | Meaning |
|--------|---------|
| `STATUS_SUCCESS` | Completed; `*response` valid (including HTTP 4xx/5xx) |
| `STATUS_INVALID_PARAMETER` | Bad args |
| `STATUS_INVALID_DEVICE_REQUEST` | Not `PASSIVE_LEVEL` |
| Other | Network / TLS / protocol failure |

HTTP status codes are read via `ResponseStatusCode`; they are not mapped to `NTSTATUS` failure unless the transport fails.

## Method helpers

Each method has `Session*` and `Request*` forms:

| Short | Ex form | Body |
|-------|---------|------|
| `Get` / `Head` / `Options` / `Trace` / `Delete` | `*Ex(..., headers, options, response)` | No |
| `Post` / `Put` / `Patch` | `*Ex(..., headers, body, options, response)` | Yes |

Length-based URL overloads (no `Headers`/`SendOptions`), e.g.:

```cpp
NTSTATUS Get(_In_ Session* session,
    _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength,
    _Out_ Response** response) noexcept;
NTSTATUS Post(_In_ Session* session,
    _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength,
    _In_reads_bytes_opt_(bodyLength) const UCHAR* body, SIZE_T bodyLength,
    _Out_ Response** response) noexcept;
// Put / Patch / Delete / Head / Options / Trace similarly
```

`Trace` requires `SendFlagAllowTrace` (via `*Ex` options).

## SendOptionsCreate / Release

```cpp
NTSTATUS SendOptionsCreate(_Out_ SendOptions** options) noexcept;
void SendOptionsRelease(_In_opt_ SendOptions* options) noexcept;
SendOptions DefaultSendOptions() noexcept; // Types.h, value form
```

`SendOptions` constructor is private: heap via `SendOptionsCreate`, value via `DefaultSendOptions()`.

## SendOptions fields

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
    const AcceptEncodingPreference* AcceptEncodingPreferences;
    SIZE_T AcceptEncodingPreferenceCount;
    const CodingDecodeMaterials* ContentCodingMaterials;
    const Http2Priority* Http2Priority;
    Cache* Cache;
    // WKNET_USER_MODE_TEST: OnComplete, CompletionContext
};
```

| Field | Default (Create / Default) | Notes |
|-------|----------------------------|-------|
| `MaxResponseBytes` | `0` | `0` = no caller aggregate cap for this send |
| `Flags` | `SendFlagNone` | See below |
| `MaxRedirects` | `0` | **`0` → `DefaultMaxRedirects` (10)**; when exhausted, **returns the 3xx response** (not an error) |
| `ExpectContinueTimeoutMs` | `0` (Create) | Wait for `100 Continue` when `SendFlagExpectContinue`; constant `DefaultExpectContinueTimeoutMs` (1000) |
| `OnHeader` | `nullptr` | Header callback; failure aborts |
| `OnBody` | `nullptr` | Body chunk callback; `finalChunk` ends |
| `CallbackContext` | `nullptr` | Passed to callbacks |
| `Tls` / `HasTlsOverride` | default TLS / `false` | Override session TLS when `HasTlsOverride` |
| `ConnectionPolicy` | `ReuseOrCreate` | `ReuseOrCreate` / `ForceNew` / `NoPool` |
| `Family` | `Any` | `Any` / `Ipv4` / `Ipv6` |
| `Http2CleartextMode` | `Disabled` | `http://` only: `Disabled` / `PriorKnowledge` / `Upgrade` |
| `AcceptEncodingPreferences` / `Count` | `nullptr` / `0` | `Accept-Encoding` negotiation |
| `ContentCodingMaterials` | `nullptr` | Decode dictionary / AES-GCM material |
| `Http2Priority` | `nullptr` | H2 first HEADERS priority; ignored on H1 |
| `Cache` | `nullptr` | Per-send cache override |

### SendFlags

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

| Flag | Notes |
|------|-------|
| `AggregateWithCallbacks` | Callbacks plus aggregated response |
| `DisableAutoRedirect` | Return 3xx without following |
| `ExpectContinue` | Send `Expect: 100-continue` for bodied HTTP/1.1 |
| `AllowTrace` | Permit TRACE |
| `BypassCache` | Skip cache read; may still store |
| `NoCacheStore` | Do not store response |
| `OnlyIfCached` | Cache hit only; else `STATUS_NOT_FOUND` |

### Accept-Encoding / Http2Priority

```cpp
struct AcceptEncodingPreference final {
    AcceptCoding Coding = AcceptCoding::Identity;
    USHORT QValue = AcceptEncodingQValueMax; // 1000
};

struct Http2Priority final {
    ULONG StreamDependency = 0;
    USHORT Weight = 16;
    bool Exclusive = false;
};

struct CodingDecodeMaterials final {
    const CodingExternalMaterial* Items = nullptr;
    SIZE_T ItemCount = 0;
    CodingMaterialCallback Callback = nullptr;
    void* CallbackContext = nullptr;
};
```

`AcceptCoding` / `ContentCoding` enums are in `Types.h` (Identity, Gzip, Deflate, Brotli, Compress, Zstd, dictionary variants, Aes128Gcm, Exi, Pack200Gzip, Any, Extension).

### Callback types

```cpp
typedef NTSTATUS (*HeaderCallback)(void* context,
    const char* name, SIZE_T nameLength,
    const char* value, SIZE_T valueLength);
typedef NTSTATUS (*BodyCallback)(void* context,
    const UCHAR* data, SIZE_T dataLength, bool finalChunk);
typedef NTSTATUS (*RequestBodyReadCallback)(void* context,
    UCHAR* buffer, SIZE_T bufferCapacity,
    SIZE_T* bytesRead, bool* endOfBody);
```

## Method enum

```cpp
enum class Method : ULONG {
    Get = 0, Post = 1, Put = 2, Patch = 3, Delete = 4,
    Head = 5, Options = 6, Connect = 7, Trace = 8
};
```

## See also

- [Request & Response](request-response.en.md)
- [Async HTTP](http-async.en.md)
- [Session & Config](session-config.en.md)
- [TLS options](tls-options.en.md)
- [Cookbook](../cookbook.en.md)
