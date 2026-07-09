# 底层 API

### 快速开始

#### 创建会话并发送 GET 请求

```cpp
// 1. 获取 WSK 客户端实例（假设已初始化）
net::WskClient* wskClient = /* ... */;

// 2. 创建会话
KH_SESSION session = nullptr;
KhSessionOptions options = {};
options.Tls.MinVersion = KhTlsVersion::Tls13;
options.Tls.CertificatePolicy = KhCertificatePolicy::Verify;
NTSTATUS status = KhSessionCreate(wskClient, &options, &session);

// 3. 创建请求
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

// 4. 发送请求
KH_RESPONSE response = nullptr;
if (NT_SUCCESS(status)) {
    status = KhHttpSendSync(session, request, nullptr, &response);
}

// 5. 读取响应
if (NT_SUCCESS(status)) {
    KhResponseView view = {};
    status = KhResponseGetView(response, &view);
    if (NT_SUCCESS(status)) {
        ULONG statusCode = view.StatusCode;
        const UCHAR* body = view.Body;
        SIZE_T bodyLength = view.BodyLength;
    }
}

// 6. 释放资源
KhResponseRelease(response);
KhHttpRequestRelease(request);
KhSessionClose(session);
```

#### 发送 POST JSON

```cpp
KH_REQUEST request = nullptr;
KhHttpRequestCreate(session, &request);

// 设置 URL 和方法
KhHttpRequestSetUrl(request, "https://httpbin.org/post", 25);
KhHttpRequestSetMethod(request, KhHttpMethod::Post);

// 设置 JSON 请求体
const char* json = "{\"key\":\"value\"}";
KhHttpRequestSetTextBody(request, json, 13, "application/json; charset=utf-8", 30);

// 发送请求
KH_RESPONSE response = nullptr;
KhHttpSendSync(session, request, nullptr, &response);

// 清理
KhResponseRelease(response);
KhHttpRequestRelease(request);
```

### 阅读约定

在使用底层 API 前，请记住以下几点：

- **句柄都是堆对象**：所有底层公开句柄（`KH_SESSION`、`KH_REQUEST`、`KH_RESPONSE`、`KH_WEBSOCKET`、`KH_ASYNC_OPERATION`）都是不透明的堆指针。不要在栈上声明这些对象，使用对应的 `Create` 函数创建，用匹配的 `Release` / `Close` 函数释放。
- **无 Default 工厂**：底层 `KhSessionOptions` 没有默认值工厂函数，需要零初始化后显式设置字段。
- **调用级别**：所有底层 HTTP/WS 调用必须在 `PASSIVE_LEVEL` 执行。
- **错误处理**：返回值统一为 `NTSTATUS`，用 `NT_SUCCESS(status)` 判断成功。标记 `_Must_inspect_result_` 的返回值必须检查。
- **安全释放**：`Release` / `Close` 函数接受 `nullptr`，这意味着你可以在失败路径中无条件调用它们，简化清理逻辑。
- **WSK 依赖**：底层 API 需要传入 `net::WskClient*`，这是与高层 API 的主要区别之一。
- **请求构造模式**：底层 `Request` 是 builder 模式，通过 `Set*` 函数逐步构造请求；高层 API 则在 `Send*` 调用中一次性传入所有参数。

### 头文件总览

以下是底层 API 涉及的主要头文件：

| 头文件 | 内容 |
|--------|------|
| `KernelHttp/KernelHttp.h` | 总入口，包含底层 engine API |
| `KernelHttp/engine/Engine.h` | 底层会话、请求、响应、异步操作 |
| `KernelHttp/engine/Async.h` | 异步操作与运行时 |
| `KernelHttp/engine/Workspace.h` | Workspace 缓冲管理 |
| `KernelHttp/engine/ConnectionPool.h` | 连接池 |
| `KernelHttp/engine/Types.h` | 底层枚举、结构体、配置类型 |

## 句柄类型

底层 API 使用不透明句柄来管理资源。这些句柄都是堆分配的对象，你需要通过对应的创建函数获取，用完后通过释放函数归还。

| 类型 | 底层类型 | 创建函数 | 释放函数 | 说明 |
|------|----------|----------|----------|------|
| `KH_SESSION` | `KhSession*` | `KhSessionCreate` | `KhSessionClose` | HTTP/WS 会话。需要传入 `net::WskClient*` |
| `KH_REQUEST` | `KhRequest*` | `KhHttpRequestCreate` | `KhHttpRequestRelease` | 请求 builder 句柄；通过 `Set*` 函数构造请求 |
| `KH_RESPONSE` | `KhResponse*` | 由发送结果返回 | `KhResponseRelease` | 响应句柄，通过 `KhResponseGetView` 读取内容 |
| `KH_HTTP_CACHE` | `KhHttpCache*` | `KhHttpCacheCreate` | `KhHttpCacheClose` | RFC 9111 内存内缓存句柄，可绑定到会话或单次发送 |
| `KH_WEBSOCKET` | `KhWebSocket*` | `KhWebSocketConnectSync` / `KhWebSocketConnectAsync` | `KhWebSocketCloseSync` | WebSocket 连接句柄 |
| `KH_ASYNC_OPERATION` | `KhAsyncOperation*` | 异步发送返回 | `KhAsyncRelease` | 异步操作句柄，可等待、取消、取结果 |

## 枚举

枚举类型定义了底层 API 中使用的各种选项和模式：

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

每个枚举的用途如下：

| 枚举 | 说明 |
|------|------|
| `KhHttpMethod` | HTTP 方法。`Connect` 主要供特殊场景或底层能力使用 |
| `KhTlsVersion` | TLS 最小/最大版本。推荐使用 `Tls12` 或更高版本 |
| `KhCertificatePolicy` | 证书校验策略。生产环境应该使用 `Verify`，仅在测试时考虑 `NoVerify` |
| `KhConnectionPolicy` | 单次发送连接池策略。`ReuseOrCreate` 是最常用的选择 |
| `KhAddressFamily` | DNS/连接地址族选择。`Any` 会自动选择合适的地址族 |
| `KhPoolType` | 响应缓冲池类型。内核路径当前要求 `NonPaged`；`Paged` 是保留 ABI 值，暂时不要使用 |
| `KhRequestBodyMode` | 请求体 framing：`ContentLength` 用于已知大小的请求体，`Chunked` 用于流式数据 |
| `KhRequestBodyPartKind` | multipart part 类型。`Field` 用于普通表单字段，`FileBytes` 和 `FilePath` 用于文件上传 |
| `KhWebSocketMessageType` | WebSocket 消息类型 |
| `KhHttpSendFlags` | 发送标志。`KhHttpSendFlagAggregateWithCallbacks` 调用回调同时保留聚合响应；`KhHttpSendFlagDisableAutoRedirect` 禁用自动重定向；`KhHttpSendFlagExpectContinue` 显式开启 `Expect: 100-continue` |

## 函数总览

以下是底层 API 提供的所有函数。为了方便查阅，我们按功能分组列出：

### 会话与生命周期

| 函数 | 功能 |
|------|------|
| `KhSessionCreate` | 创建底层会话，需要传入 `net::WskClient*` |
| `KhSessionClose` | 关闭会话 |
| `KhHttpCacheCreate` / `KhHttpCacheClose` / `KhHttpCacheClear` / `KhHttpCacheGetStats` | 管理 RFC 9111 内存内缓存 |
| `KhEngineDrainAsync` | 等待所有在飞异步操作（卸载前必调） |
| `KhEngineCloseActiveHandles` | 强制关闭所有活跃句柄 |

### 请求构造

| 函数 | 功能 |
|------|------|
| `KhHttpRequestCreate` / `KhHttpRequestRelease` | 创建/释放请求句柄 |
| `KhHttpRequestSetUrl` | 设置请求 URL |
| `KhHttpRequestSetMethod` | 设置 HTTP 方法 |
| `KhHttpRequestSetHeader` | 设置请求头 |
| `KhHttpRequestSetBody` / `KhHttpRequestSetTextBody` / `KhHttpRequestSetRawBody` | 设置请求体 |
| `KhHttpRequestSetUrlEncodedBody` | 设置 form-urlencoded 请求体 |
| `KhHttpRequestSetMultipartFormDataBody` | 设置 multipart/form-data 请求体 |
| `KhHttpRequestSetFileBody` | 设置文件请求体 |
| `KhHttpRequestSetBodySource` | 设置流式请求体读取回调 |
| `KhHttpRequestSetBodyMode` | 设置 Content-Length 或 chunked framing |
| `KhHttpRequestAddTrailer` | 为 chunked body 添加 trailer |
| `KhHttpRequestClearBody` | 清除请求体 |
| `KhHttpRequestSetTlsOptions` | 设置单次 TLS 配置 |
| `KhHttpRequestSetConnectionPolicy` | 设置连接策略 |
| `KhHttpRequestSetAddressFamily` | 设置地址族 |

### 发送

| 函数 | 功能 |
|------|------|
| `KhHttpSendSync` | 同步发送 HTTP 请求 |
| `KhHttpSendAsync` | 异步发送 HTTP 请求 |

### 响应访问

| 函数 | 功能 |
|------|------|
| `KhResponseGetView` | 获取响应视图（状态码、响应体） |
| `KhResponseGetHeader` / `KhResponseGetHeaderAt` | 按名称或索引读取响应头 |
| `KhResponseHeaderCount` | 读取响应头数量 |
| `KhResponseGetTrailer` / `KhResponseGetTrailerAt` | 按名称或索引读取 trailer |
| `KhResponseTrailerCount` | 读取 trailer 数量 |
| `KhResponseRelease` | 释放响应句柄 |

### WebSocket

| 函数 | 功能 |
|------|------|
| `KhWebSocketConnectSync` / `KhWebSocketConnectAsync` | 同步/异步建立 WebSocket 连接 |
| `KhWebSocketSendTextSync` / `KhWebSocketSendBinarySync` / `KhWebSocketSendContinuationSync` | 发送 WebSocket 帧 |
| `KhWebSocketSendPingSync` / `KhWebSocketSendPongSync` | 发送 ping/pong |
| `KhWebSocketReceiveSync` | 接收 WebSocket 消息 |
| `KhWebSocketCloseSync` / `KhWebSocketCloseExSync` | 关闭 WebSocket |
| `KhWebSocketSelectedSubprotocol` | 查询协商子协议 |

### 异步操作

| 函数 | 功能 |
|------|------|
| `KhAsyncWait` | 等待异步操作完成 |
| `KhAsyncCancel` | 请求取消异步操作 |
| `KhAsyncGetHttpResponse` | 取 HTTP 异步响应 |
| `KhAsyncGetWebSocket` | 取 WebSocket 异步连接 |
| `KhAsyncRelease` | 释放异步操作 |

## 函数详细参考

### 会话

#### `KhSessionCreate`

```cpp
NTSTATUS KhSessionCreate(
    _In_ net::WskClient* wskClient,
    _In_opt_ const KhSessionOptions* options,
    _Out_ KH_SESSION* out
) noexcept;
```

创建底层 HTTP/WS 会话。与高层 `khttp::SessionCreate` 不同，底层版本需要传入 `net::WskClient*`。

| 参数 | 说明 |
|------|------|
| `wskClient` | WSK 客户端实例；必须已初始化 |
| `options` | 会话选项；`nullptr` 表示使用零初始化默认值 |
| `out` | 成功时接收 `KH_SESSION`；失败时置为 `nullptr` |

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 创建成功 |
| `STATUS_INVALID_PARAMETER` | `out == nullptr` 或配置非法 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配会话或内部资源失败 |
| 其他失败状态 | WSK 初始化或 engine session 创建失败 |

NOTE: `KhSessionOptions` / `KhTlsOptions` 字段见 [配置项](configuration.md)。`KhSessionOptions.Proxy` 可显式配置 HTTP 代理；HTTPS 走 CONNECT，明文 HTTP 走 absolute-form。成功后必须调用 `KhSessionClose` 释放会话。

#### `KhSessionClose`

```cpp
void KhSessionClose(
    _In_opt_ KH_SESSION session
) noexcept;
```

关闭并释放会话。这是一个安全的函数，接受 `nullptr` 参数。

| 参数 | 说明 |
|------|------|
| `session` | 要关闭的会话；`nullptr` 直接返回 |

无返回值。

NOTE: 关闭会话会释放内部资源。使用过异步 API 时，驱动卸载前还必须调用 `KhEngineDrainAsync()`。

### 请求构造

请求构造是底层 API 的核心部分。与高层 API 不同，底层 `Request` 是 builder 模式，通过 `Set*` 函数逐步构造请求。

#### `KhHttpRequestCreate`

```cpp
NTSTATUS KhHttpRequestCreate(
    _In_ KH_SESSION session,
    _Out_ KH_REQUEST* out
) noexcept;
```

创建绑定到 `Session` 的请求句柄。请求句柄用于逐步构造 HTTP 请求。

| 参数 | 说明 |
|------|------|
| `session` | 父会话 |
| `out` | 成功时接收 `KH_REQUEST` |

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 创建成功 |
| `STATUS_INVALID_PARAMETER` | 参数为空或会话无效 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败 |

#### `KhHttpRequestRelease`

```cpp
void KhHttpRequestRelease(
    _In_opt_ KH_REQUEST request
) noexcept;
```

释放请求句柄。这是一个安全的函数，接受 `nullptr` 参数。

| 参数 | 说明 |
|------|------|
| `request` | 要释放的请求句柄；`nullptr` 直接返回 |

无返回值。

#### `KhHttpRequestSetUrl`

```cpp
NTSTATUS KhHttpRequestSetUrl(
    _In_ KH_REQUEST request,
    _In_ const char* url,
    _In_ SIZE_T urlLen
) noexcept;
```

设置请求 URL。

| 参数 | 说明 |
|------|------|
| `request` | 请求句柄 |
| `url` | URL 字符串 |
| `urlLen` | URL 字节长度 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`

#### `KhHttpRequestSetMethod`

```cpp
NTSTATUS KhHttpRequestSetMethod(
    _In_ KH_REQUEST request,
    _In_ KhHttpMethod method
) noexcept;
```

设置 HTTP 方法。

| 参数 | 说明 |
|------|------|
| `request` | 请求句柄 |
| `method` | HTTP 方法枚举值 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`

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

设置请求头。按大小写不敏感字段名查重；同名字段会覆盖旧值。

| 参数 | 说明 |
|------|------|
| `request` | 请求句柄 |
| `name` | header 名称 |
| `nLen` | header 名称字节长度 |
| `value` | header 值 |
| `vLen` | header 值字节长度 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`

NOTE: 禁止 CR/LF 注入。库受控 header（如 `Host`、`Content-Length`）会被拒绝。

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

设置请求体。`SetBody` 设置原始字节；`SetTextBody` 设置文本并可指定 Content-Type；`SetRawBody` 设置原始字节并可指定 Content-Type。

| 参数 | 说明 |
|------|------|
| `request` | 请求句柄 |
| `body` / `text` / `data` | 请求体字节 |
| `len` | 字节长度 |
| `contentType` | Content-Type；可为空 |
| `ctLen` | Content-Type 字节长度 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`

#### `KhHttpRequestSetUrlEncodedBody`

```cpp
NTSTATUS KhHttpRequestSetUrlEncodedBody(
    _In_ KH_REQUEST request,
    _In_ const KhNameValuePair* pairs,
    _In_ SIZE_T count
) noexcept;
```

设置 `application/x-www-form-urlencoded` 请求体。

| 参数 | 说明 |
|------|------|
| `request` | 请求句柄 |
| `pairs` | form 字段数组 |
| `count` | 字段数量 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`

#### `KhHttpRequestSetMultipartFormDataBody`

```cpp
NTSTATUS KhHttpRequestSetMultipartFormDataBody(
    _In_ KH_REQUEST request,
    _In_ const KhMultipartFormDataPart* parts,
    _In_ SIZE_T count
) noexcept;
```

设置 `multipart/form-data` 请求体。

| 参数 | 说明 |
|------|------|
| `request` | 请求句柄 |
| `parts` | multipart part 数组 |
| `count` | part 数量 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`

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

设置文件请求体。库复制文件路径，发送时读取文件内容。

| 参数 | 说明 |
|------|------|
| `request` | 请求句柄 |
| `path` | 文件路径 |
| `pathLen` | 文件路径字节长度 |
| `contentType` | Content-Type；可为空 |
| `ctLen` | Content-Type 字节长度 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`

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

设置流式请求体读取回调。`contentLengthKnown=true` 时发送 `Content-Length`；未知长度通常配合 `KhHttpRequestSetBodyMode(request, KhRequestBodyMode::Chunked)` 由库生成 chunked framing。

#### `KhHttpRequestSetBodyMode`

```cpp
NTSTATUS KhHttpRequestSetBodyMode(
    _In_ KH_REQUEST request,
    _In_ KhRequestBodyMode mode
) noexcept;
```

设置请求体 framing 模式。默认是 `ContentLength`，适用于已知大小的请求体；`Chunked` 适用于流式数据。

| 参数 | 说明 |
|------|------|
| `request` | 请求句柄 |
| `mode` | `ContentLength` 或 `Chunked` |

返回值：`STATUS_SUCCESS` 或 `STATUS_INVALID_PARAMETER`

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

为 chunked 请求体添加 trailer 字段。

| 参数 | 说明 |
|------|------|
| `request` | 请求句柄 |
| `name` | trailer 名称 |
| `nLen` | trailer 名称字节长度 |
| `value` | trailer 值 |
| `vLen` | trailer 值字节长度 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_NOT_SUPPORTED`、`STATUS_INSUFFICIENT_RESOURCES`

NOTE: trailer 只在 `KhHttpRequestSetBodyMode(request, KhRequestBodyMode::Chunked)` 后发送。禁止字段与 CRLF 注入会被拒绝。

#### `KhHttpRequestClearBody`

```cpp
NTSTATUS KhHttpRequestClearBody(
    _In_ KH_REQUEST request
) noexcept;
```

清除请求体。

| 参数 | 说明 |
|------|------|
| `request` | 请求句柄 |

返回值：`STATUS_SUCCESS` 或 `STATUS_INVALID_PARAMETER`

#### `KhHttpRequestSetTlsOptions`

```cpp
NTSTATUS KhHttpRequestSetTlsOptions(
    _In_ KH_REQUEST request,
    _In_ const KhTlsOptions* options
) noexcept;
```

设置单次 TLS 配置，覆盖会话默认值。

| 参数 | 说明 |
|------|------|
| `request` | 请求句柄 |
| `options` | TLS 选项；可为空 |

返回值：`STATUS_SUCCESS` 或 `STATUS_INVALID_PARAMETER`

#### `KhHttpRequestSetConnectionPolicy`

```cpp
NTSTATUS KhHttpRequestSetConnectionPolicy(
    _In_ KH_REQUEST request,
    _In_ KhConnectionPolicy policy
) noexcept;
```

设置连接策略。

| 参数 | 说明 |
|------|------|
| `request` | 请求句柄 |
| `policy` | 连接策略枚举值 |

返回值：`STATUS_SUCCESS` 或 `STATUS_INVALID_PARAMETER`

#### `KhHttpRequestSetAddressFamily`

```cpp
NTSTATUS KhHttpRequestSetAddressFamily(
    _In_ KH_REQUEST request,
    _In_ KhAddressFamily family
) noexcept;
```

设置地址族。

| 参数 | 说明 |
|------|------|
| `request` | 请求句柄 |
| `family` | 地址族枚举值 |

返回值：`STATUS_SUCCESS` 或 `STATUS_INVALID_PARAMETER`

### 发送

#### `KhHttpSendSync`

```cpp
NTSTATUS KhHttpSendSync(
    _In_ KH_SESSION session,
    _In_ KH_REQUEST request,
    _In_opt_ const KhHttpSendOptions* options,
    _Out_ KH_RESPONSE* resp
) noexcept;
```

同步发送 HTTP 请求。函数会阻塞直到请求完成。

| 参数 | 说明 |
|------|------|
| `session` | 会话句柄 |
| `request` | 请求句柄 |
| `options` | 发送选项；`nullptr` 表示使用默认值 |
| `resp` | 成功时接收 `KH_RESPONSE` |

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 请求成功 |
| `STATUS_INVALID_PARAMETER` | 参数不合法 |
| `STATUS_INVALID_DEVICE_REQUEST` | 不在 `PASSIVE_LEVEL` 调用 |
| `STATUS_BUFFER_TOO_SMALL` | 响应超出了 `MaxResponseBytes` |
| `STATUS_IO_TIMEOUT` | 超时 |
| `STATUS_CONNECTION_DISCONNECTED` | 连接断开 |
| `STATUS_TRUST_FAILURE` | TLS 证书校验失败 |
| `STATUS_INVALID_NETWORK_RESPONSE` | 响应格式不对 |
| `STATUS_INSUFFICIENT_RESOURCES` | 内存不足或连接池满了 |
| 其他 `NTSTATUS` | 传输、TLS、解析或回调返回的错误 |

NOTE: `KhSessionOptions::Cache` 设置会话默认 RFC 9111 缓存；`KhHttpSendOptions::Cache` 可为单次发送覆盖。`KhHttpSendOptions` 字段：`MaxResponseBytes`、`Flags`、`MaxRedirects`、`HeaderCallback`、`BodyCallback`、`CallbackContext`、`CompletionCallback`、`CompletionContext`、`Http2CleartextMode`、`AcceptEncodingPreferences`、`Http2Priority`、`Cache`。

#### `KhHttpSendAsync`

```cpp
NTSTATUS KhHttpSendAsync(
    _In_ KH_SESSION session,
    _In_ KH_REQUEST request,
    _In_opt_ const KhHttpSendOptions* options,
    _Out_ KH_ASYNC_OPERATION* op
) noexcept;
```

异步发送 HTTP 请求。函数立即返回，操作在后台执行。

| 参数 | 说明 |
|------|------|
| `session` | 会话句柄 |
| `request` | 请求句柄 |
| `options` | 发送选项；`nullptr` 表示使用默认值 |
| `op` | 成功时接收 `KH_ASYNC_OPERATION` |

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 异步操作创建并排队成功 |
| `STATUS_INVALID_PARAMETER` | 参数或句柄非法 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败或异步队列满 |
| 其他失败状态 | 发送准备阶段失败 |

NOTE: 成功创建操作后，调用方应 `KhAsyncWait` 等待终态，调用 `KhAsyncGetHttpResponse` 取得响应，再分别释放 `KH_RESPONSE` 和 `KH_ASYNC_OPERATION`。

### 响应访问

这些函数用于读取 HTTP 响应的内容。底层 API 通过 `KhResponseGetView` 获取响应视图，然后通过其他函数读取响应头和 trailer。

#### `KhResponseGetView`

```cpp
NTSTATUS KhResponseGetView(
    _In_ KH_RESPONSE response,
    _Out_ KhResponseView* view
) noexcept;
```

获取响应视图。视图包含状态码、响应体指针和长度。

| 参数 | 说明 |
|------|------|
| `response` | 响应句柄 |
| `view` | 成功时接收响应视图 |

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 成功获取视图 |
| `STATUS_INVALID_PARAMETER` | 参数非法 |

NOTE: `KhResponseView` 包含 `StatusCode`、`Body`、`BodyLength` 字段。`Body` 指针在 `KhResponseRelease` 前有效。

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

按名称读取响应头。名称匹配大小写不敏感。

| 参数 | 说明 |
|------|------|
| `response` | 响应句柄 |
| `name` | header 名称 |
| `nLen` | 名称字节长度 |
| `value` | 成功时接收 header 值指针 |
| `vLen` | 成功时接收值长度 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_NOT_FOUND`

#### `KhResponseHeaderCount`

```cpp
SIZE_T KhResponseHeaderCount(
    _In_ KH_RESPONSE response
) noexcept;
```

读取响应头数量。

| 参数 | 说明 |
|------|------|
| `response` | 响应句柄；可为空 |

返回值：数量；空或无效句柄返回 `0`

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

按索引枚举响应头。

| 参数 | 说明 |
|------|------|
| `response` | 响应句柄 |
| `index` | 头索引 |
| `name` | 成功时接收 header 名称指针 |
| `nLen` | 成功时接收名称长度 |
| `value` | 成功时接收 header 值指针 |
| `vLen` | 成功时接收值长度 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_NOT_FOUND`

#### `KhResponseTrailerCount`

```cpp
SIZE_T KhResponseTrailerCount(
    _In_ KH_RESPONSE response
) noexcept;
```

读取 trailer 数量。

| 参数 | 说明 |
|------|------|
| `response` | 响应句柄；可为空 |

返回值：数量；空或无效句柄返回 `0`

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

按名称或索引读取响应 trailer。

**参数与返回值**：同 header 读取函数

#### `KhResponseRelease`

```cpp
void KhResponseRelease(
    _In_opt_ KH_RESPONSE response
) noexcept;
```

释放响应句柄及其内部缓冲。这是一个安全的函数，接受 `nullptr` 参数。

| 参数 | 说明 |
|------|------|
| `response` | 响应句柄；可为空 |

无返回值。

### WebSocket（底层）

这些函数用于 WebSocket 连接和通信。WebSocket 提供全双工通信能力，适合实时数据推送、聊天、游戏等场景。

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

建立 WebSocket 连接。`ConnectSync` 同步阻塞直到握手完成；`ConnectAsync` 异步返回。

| 参数 | 说明 |
|------|------|
| `session` | 会话句柄 |
| `options` | 连接配置 |
| `out` / `op` | 成功时接收 `KH_WEBSOCKET` 或 `KH_ASYNC_OPERATION` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_NOT_SUPPORTED`、网络/TLS/HTTP 握手失败状态

NOTE: `KhWebSocketConnectOptions.Headers/HeaderCount` 可传 opening-handshake 额外头；库受控头（`Host`、`Connection`、`Upgrade`、`Sec-WebSocket-*` 等）会被拒绝。`KhWebSocketTransportMode::Auto` 的 ABI 零值默认会让 `wss` 自动选择 RFC 8441；需要强制 HTTP/1.1 时使用 `Http11Only`。

#### WebSocket 发送函数

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

发送 WebSocket 帧。支持文本、二进制、续帧、ping、pong 等帧类型。

| 参数 | 说明 |
|------|------|
| `ws` | WebSocket 句柄 |
| `text` | 文本字节 |
| `data` | 二进制或续帧字节 |
| `payload` | ping/pong payload；`len == 0` 时可空 |
| `options` | `FinalFragment` 选项 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、连接关闭/断开/超时等传输失败状态

#### `KhWebSocketReceiveSync`

```cpp
NTSTATUS KhWebSocketReceiveSync(
    _In_ KH_WEBSOCKET ws,
    _In_opt_ const KhWebSocketReceiveOptions* options,
    _Out_ KhWebSocketMessage* msg
) noexcept;
```

接收 WebSocket 消息。这是一个阻塞调用，会等待直到收到消息或出错。

| 参数 | 说明 |
|------|------|
| `ws` | WebSocket 句柄 |
| `options` | 接收选项；可为空 |
| `msg` | 成功时接收消息 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_BUFFER_TOO_SMALL`、连接关闭/断开/超时等状态

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

关闭 WebSocket 连接。`CloseSync` 是简单版本；`CloseExSync` 允许指定关闭状态码和原因。

| 参数 | 说明 |
|------|------|
| `ws` | WebSocket 句柄；可为空 |
| `statusCode` | 关闭状态码 |
| `reason` | 关闭原因；`reasonLen == 0` 时可为空 |
| `reasonLen` | 关闭原因字节长度 |

返回值：关闭成功或传输失败状态

NOTE: 不要在同一 `WebSocket` 上并发执行 `Close` 和新的发送/接收。关闭操作应该是最后的操作。

#### `KhWebSocketSelectedSubprotocol`

```cpp
NTSTATUS KhWebSocketSelectedSubprotocol(
    _In_ KH_WEBSOCKET ws,
    _Out_ const char** sub,
    _Out_ SIZE_T* subLen
) noexcept;
```

读取服务端选择的 WebSocket 子协议。

| 参数 | 说明 |
|------|------|
| `ws` | WebSocket 句柄 |
| `sub` | 成功时接收子协议指针 |
| `subLen` | 成功时接收子协议长度 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_NOT_FOUND`

### 异步操作

这些函数用于管理异步操作的生命周期和状态。

#### `KhAsyncWait`

```cpp
NTSTATUS KhAsyncWait(
    _In_ KH_ASYNC_OPERATION op,
    _In_ ULONG timeoutMs
) noexcept;
```

等待异步操作完成。这是同步等待异步结果的方式。

| 参数 | 说明 |
|------|------|
| `op` | 异步操作句柄 |
| `timeoutMs` | 等待超时毫秒；传 `0xffffffffUL` 表示无限等待 |

返回值：完成状态、`STATUS_TIMEOUT`、`STATUS_INVALID_PARAMETER` 或等待过程中的失败状态

#### `KhAsyncCancel`

```cpp
NTSTATUS KhAsyncCancel(
    _In_ KH_ASYNC_OPERATION op
) noexcept;
```

请求取消异步操作。取消是协作式的，不是立即生效的。

| 参数 | 说明 |
|------|------|
| `op` | 异步操作句柄；不可为空 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER` 或取消过程失败状态

NOTE: 取消后仍应调用 `KhAsyncWait` 等待终态，再释放操作。不要假设取消后操作立即完成。

#### `KhAsyncGetHttpResponse`

```cpp
NTSTATUS KhAsyncGetHttpResponse(
    _In_ KH_ASYNC_OPERATION op,
    _Out_ KH_RESPONSE* resp
) noexcept;
```

从已完成 HTTP 异步操作中取出响应。必须在操作完成后调用。

| 参数 | 说明 |
|------|------|
| `op` | HTTP send 异步操作 |
| `resp` | 成功时接收 `KH_RESPONSE` |

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 成功取出响应 |
| `STATUS_INVALID_PARAMETER` | 参数或操作类型非法 |
| `STATUS_PENDING` | 操作尚未完成，先调用 `KhAsyncWait` |
| 其他失败状态 | 发送失败或被取消 |

#### `KhAsyncGetWebSocket`

```cpp
NTSTATUS KhAsyncGetWebSocket(
    _In_ KH_ASYNC_OPERATION op,
    _Out_ KH_WEBSOCKET* ws
) noexcept;
```

从已完成 WebSocket connect 异步操作中取出 `KH_WEBSOCKET` 句柄。

| 参数 | 说明 |
|------|------|
| `op` | WebSocket connect 异步操作 |
| `ws` | 成功时接收 `KH_WEBSOCKET` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_PENDING` 或连接最终失败状态

#### `KhAsyncRelease`

```cpp
void KhAsyncRelease(
    _In_opt_ KH_ASYNC_OPERATION op
) noexcept;
```

释放异步操作句柄。这是一个安全的函数，接受 `nullptr` 参数。

| 参数 | 说明 |
|------|------|
| `op` | 异步操作句柄；可为空 |

无返回值。

### 引擎生命周期

这些函数用于管理引擎的生命周期和异步运行时。

#### `KhEngineDrainAsync`

```cpp
NTSTATUS KhEngineDrainAsync() noexcept;
```

等待所有在飞异步操作结束。驱动卸载前必须调用。

无参数。

返回值：`STATUS_SUCCESS` 或等待过程中的失败状态

NOTE: 用过 HTTP 或 WebSocket 异步 API 后，驱动卸载前必须调用。同步-only 路径可以无条件调用，不会有副作用。

#### `KhEngineCloseActiveHandles`

```cpp
void KhEngineCloseActiveHandles() noexcept;
```

强制关闭所有活跃句柄。用于异常清理场景。

无参数。

无返回值。

### 测试钩子（仅 `KERNEL_HTTP_USER_MODE_TEST`）

这些函数用于单元测试，不进内核构建：

| 函数 | 功能 |
|------|------|
| `KhTestSetHttpTransport` / `KhTestSetWebSocketTransport` | 注入 mock 传输 |
| `KhTestSetAsyncAutoRun` / `KhTestRunAsyncOperation` | 手动驱动异步 |
| `KhTestSetCurrentIrql` / `KhTestResetCurrentIrql` | 模拟 IRQL |

用于确定性、无真实网络的单元测试。
