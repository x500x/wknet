# 请求与响应

命名空间：`wknet::http`  
头文件：`Request.h` · `Headers.h` · `Body.h` · `Response.h` · `Types.h`

`Request` / `Headers` / `Body` 与只读 `Response`。发送入口见 [同步 HTTP](http-sync.md) / [异步 HTTP](http-async.md)。

## Request

### 签名

```cpp
NTSTATUS RequestCreate(_In_ Session* session, _Out_ Request** out) noexcept;
void RequestRelease(_In_opt_ Request* request) noexcept;
```

### 参数

| 参数 | 说明 |
|------|------|
| `session` | 所属会话；请求生命周期不得越过会话 |
| `out` | 输出 `Request*` |

### 返回

`STATUS_SUCCESS` / `STATUS_INVALID_PARAMETER` / `STATUS_INSUFFICIENT_RESOURCES` 等。

### 备注

- 常见用法是 `Send(session, method, url, headers, body, options, &response)`，无需单独持有 `Request`。
- 也提供以 `Request*` 为首参的 `Send` / `AsyncSend` 重载。

## Headers

### 签名

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

### 备注

- 库控制的头（如 `Host`、`Content-Length`）可能被发送路径覆盖或拒收。
- `HeadersAdd` 要求 NUL 结尾；`HeadersAddEx` 使用显式长度。
- 发送完成后即可 `HeadersRelease`；同步发送返回或异步完成后指针无需再保持（值已拷入请求路径）。

## Body

### 创建（字节 / 文本 / JSON）

```cpp
NTSTATUS BodyCreateBytes(
    _In_reads_bytes_opt_(dataLength) const UCHAR* data, SIZE_T dataLength,
    _Out_ Body** body) noexcept;
NTSTATUS BodyCreateBytesEx(/* 同参数 */);
NTSTATUS BodyCreateBytesCopy(/* 拷贝字节 */);
NTSTATUS BodyCreateBytesCopyEx(/* 拷贝字节 */);

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

`*Copy*` 变体拷贝调用方缓冲；非 `Copy` 变体按引用持有指针，**必须保持到同步返回或异步完成/取消**。

`BodyCreateJson*` **只**设置 `Content-Type: application/json; charset=utf-8` 并透传字节，不解析 JSON。

### 表单 / multipart / 文件 / 流

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

### 模式与 trailer

```cpp
NTSTATUS BodySetMode(_In_ Body* body, RequestBodyMode mode) noexcept;
// RequestBodyMode::ContentLength | Chunked

NTSTATUS BodyAddTrailer(_In_ Body* body, _In_z_ const char* name, _In_z_ const char* value) noexcept;
NTSTATUS BodyAddTrailerEx(_In_ Body* body, name, nameLength, value, valueLength) noexcept;

void BodyRelease(_In_opt_ Body* body) noexcept;
```

备注：trailer 绑定 chunked 路径；HTTP/2 请求体为 chunked 时会拒绝。

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

`BodyCreateForm` / `BodyCreateMultipart` 拷贝描述数组，**part 内指针按引用**，须保持到发送结束。`ContentType` 禁止 CR/LF。

## Response（只读）

### 签名

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

NTSTATUS ResponseGetTrailer(/* 同 GetHeader 形参 */);
NTSTATUS ResponseGetTrailerAt(/* 同 GetHeaderAt 形参 */);

void ResponseRelease(_In_opt_ Response* response) noexcept;
```

### 返回（查找 API）

| 状态 | 含义 |
|------|------|
| `STATUS_SUCCESS` | 找到；`value`/`name` 指向响应内部存储 |
| `STATUS_NOT_FOUND` | 无此头/trailer |
| `STATUS_INVALID_PARAMETER` | 空指针或越界 |

### 备注

- `ResponseStatusCode(nullptr)` 等对空句柄返回 0 / `nullptr`。
- body / header 指针在 `ResponseRelease` 前有效。
- 流式 `OnHeader`/`OnBody`：`OnBody` 可被调用**多次**；`finalChunk` 仅在结束时为 true。未设 `SendFlagAggregateWithCallbacks` 时，聚合 body 可能为空。

## 相关链接

- [同步 HTTP](http-sync.md)
- [异步 HTTP](http-async.md)
- [会话与配置](session-config.md)
- [Cookbook](../cookbook.md)
