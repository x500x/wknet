# Request & Response

Namespace: `wknet::http`  
Headers: `Request.h` · `Headers.h` · `Body.h` · `Response.h` · `Types.h`

`Request` / `Headers` / `Body` and read-only `Response`. Send entry points: [Sync HTTP](http-sync.md) / [Async HTTP](http-async.md).

## Request

### Signatures

```cpp
NTSTATUS RequestCreate(_In_ Session* session, _Out_ Request** out) noexcept;
void RequestRelease(_In_opt_ Request* request) noexcept;
```

### Parameters

| Param | Meaning |
|-------|---------|
| `session` | Owning session; request must not outlive it |
| `out` | Out `Request*` |

### Returns

`STATUS_SUCCESS` / `STATUS_INVALID_PARAMETER` / `STATUS_INSUFFICIENT_RESOURCES`, etc.

### Notes

- Typical usage is `Send(session, method, url, headers, body, options, &response)` without holding a `Request`.
- `Send` / `AsyncSend` overloads that take `Request*` are also available.

## Headers

### Signatures

```cpp
NTSTATUS HeadersCreate(_Out_ Headers** headers) noexcept;
NTSTATUS HeadersAdd(
    _In_ Headers* headers,
    _In_z_ const char* name,
    _In_z_ const char* value) noexcept;
NTSTATUS HeadersAddEx(
    _In_ Headers* headers,
    _In_reads_bytes_(nameLength) const char* name,
    SIZE_T nameLength,
    _In_reads_bytes_(valueLength) const char* value,
    SIZE_T valueLength) noexcept;
void HeadersRelease(_In_opt_ Headers* headers) noexcept;
```

### Notes

- Library-controlled headers (e.g. `Host`, `Content-Length`) may be overridden or rejected.
- `HeadersAdd` requires NUL-terminated strings; `HeadersAddEx` uses explicit lengths.
- Safe to `HeadersRelease` after the send path has consumed the handle.

## Body

### Bytes / text / JSON

```cpp
NTSTATUS BodyCreateBytes(
    _In_reads_bytes_opt_(dataLength) const UCHAR* data, SIZE_T dataLength,
    _Out_ Body** body) noexcept;
NTSTATUS BodyCreateBytesEx(/* same */);
NTSTATUS BodyCreateBytesCopy(/* copies bytes */);
NTSTATUS BodyCreateBytesCopyEx(/* copies bytes */);

NTSTATUS BodyCreateText(
    _In_reads_bytes_opt_(textLength) const char* text, SIZE_T textLength,
    _In_opt_ const char* contentType, _Out_ Body** body) noexcept;
NTSTATUS BodyCreateTextEx(..., contentType, contentTypeLength, ...);
NTSTATUS BodyCreateTextCopy(...);
NTSTATUS BodyCreateTextCopyEx(...);

NTSTATUS BodyCreateJson(
    _In_reads_bytes_opt_(jsonLength) const char* json, SIZE_T jsonLength,
    _Out_ Body** body) noexcept;
NTSTATUS BodyCreateJsonEx(...);
NTSTATUS BodyCreateJsonCopy(...);
NTSTATUS BodyCreateJsonCopyEx(...);
```

`*Copy*` variants copy caller buffers; non-copy variants hold pointers **until sync return or async complete/cancel**.

`BodyCreateJson*` only sets `Content-Type: application/json; charset=utf-8` and passes bytes through — **no JSON parsing**.

### Form / multipart / file / stream

```cpp
NTSTATUS BodyCreateForm(
    _In_reads_(pairCount) const NameValuePair* pairs, SIZE_T pairCount,
    _Out_ Body** body) noexcept;

NTSTATUS BodyCreateMultipart(
    _In_reads_(partCount) const MultipartPart* parts, SIZE_T partCount,
    _Out_ Body** body) noexcept;

NTSTATUS BodyCreateFile(
    _In_z_ const char* filePath,
    _In_opt_ const char* contentType,
    _Out_ Body** body) noexcept;
NTSTATUS BodyCreateFileEx(
    _In_reads_bytes_(filePathLength) const char* filePath, SIZE_T filePathLength,
    _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
    SIZE_T contentTypeLength, _Out_ Body** body) noexcept;

NTSTATUS BodyCreateStream(
    _In_ RequestBodyReadCallback callback,
    _In_opt_ void* context,
    SIZE_T contentLength,
    bool contentLengthKnown,
    _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
    SIZE_T contentTypeLength,
    _Out_ Body** body) noexcept;
```

### Mode and trailers

```cpp
NTSTATUS BodySetMode(_In_ Body* body, RequestBodyMode mode) noexcept;
// RequestBodyMode::ContentLength | Chunked

NTSTATUS BodyAddTrailer(_In_ Body* body, _In_z_ const char* name, _In_z_ const char* value) noexcept;
NTSTATUS BodyAddTrailerEx(_In_ Body* body, name, nameLength, value, valueLength) noexcept;

void BodyRelease(_In_opt_ Body* body) noexcept;
```

Notes: trailers bind to the chunked path; HTTP/2 rejects chunked request bodies.

## NameValuePair / MultipartPart

```cpp
struct NameValuePair final {
    const char* Name = nullptr;
    SIZE_T NameLength = 0;
    const char* Value = nullptr;
    SIZE_T ValueLength = 0;
};

enum class BodyPartKind : ULONG { Field = 0, FileBytes = 1, FilePath = 2 };

struct MultipartPart final {
    BodyPartKind Kind = BodyPartKind::Field;
    const char* Name = nullptr;
    SIZE_T NameLength = 0;
    const char* Value = nullptr;      // Field
    SIZE_T ValueLength = 0;
    const UCHAR* Data = nullptr;      // FileBytes
    SIZE_T DataLength = 0;
    const char* FilePath = nullptr;   // FilePath
    SIZE_T FilePathLength = 0;
    const char* FileName = nullptr;
    SIZE_T FileNameLength = 0;
    const char* ContentType = nullptr;
    SIZE_T ContentTypeLength = 0;
};
```

`BodyCreateForm` / `BodyCreateMultipart` copy the descriptor array; **inner pointers are by reference** until send finishes. `ContentType` must not contain CR/LF.

## Response (read-only)

### Signatures

```cpp
ULONG ResponseStatusCode(_In_opt_ const Response* response) noexcept;
const UCHAR* ResponseBody(_In_opt_ const Response* response) noexcept;
SIZE_T ResponseBodyLength(_In_opt_ const Response* response) noexcept;
SIZE_T ResponseHeaderCount(_In_opt_ const Response* response) noexcept;
SIZE_T ResponseTrailerCount(_In_opt_ const Response* response) noexcept;

NTSTATUS ResponseGetHeader(
    _In_ const Response* response,
    _In_reads_bytes_(nameLength) const char* name, SIZE_T nameLength,
    _Outptr_result_bytebuffer_(*valueLength) const char** value,
    _Out_ SIZE_T* valueLength) noexcept;

NTSTATUS ResponseGetHeaderAt(
    _In_ const Response* response, SIZE_T index,
    _Outptr_result_bytebuffer_(*nameLength) const char** name, _Out_ SIZE_T* nameLength,
    _Outptr_result_bytebuffer_(*valueLength) const char** value, _Out_ SIZE_T* valueLength) noexcept;

NTSTATUS ResponseGetTrailer(/* same shape as GetHeader */);
NTSTATUS ResponseGetTrailerAt(/* same shape as GetHeaderAt */);

void ResponseRelease(_In_opt_ Response* response) noexcept;
```

### Returns (lookup APIs)

| Status | Meaning |
|--------|---------|
| `STATUS_SUCCESS` | Found; pointers into response storage |
| `STATUS_NOT_FOUND` | Missing |
| `STATUS_INVALID_PARAMETER` | Null or OOB |

### Notes

- Null response returns 0 / `nullptr` from accessors.
- Body/header pointers valid until `ResponseRelease`.
- With streaming callbacks and without `SendFlagAggregateWithCallbacks`, aggregated body may be empty.

## See also

- [Sync HTTP](http-sync.en.md)
- [Async HTTP](http-async.en.md)
- [Session & Config](session-config.en.md)
- [Cookbook](../cookbook.en.md)
