# 底层 API 开发文档（`KernelHttp::engine`）

本文档面向需要更精细控制 KernelHttp 内部机制的开发者。所有接口都位于命名空间 `KernelHttp::engine`，头文件位于 `include/KernelHttp/engine/Engine.h`。底层 API 提供了对会话管理、连接池、TLS 配置、异步操作等底层组件的直接访问。

> 工程约束（来自 `AGENTS.md`）：内核驱动；传输层使用 WSK，密码学使用 CNG/BCrypt；C++ 受 `/kernel` 限制：无异常、无 RTTI、显式 `new/delete`。本 API 全部满足这些约束。

## 1. 模块组成与依赖关系

| 头文件 | 主要内容 |
|---|---|
| `engine/Engine.h` | 核心 API：会话、请求、响应、WebSocket、异步操作的完整接口定义 |

底层 API 依赖以下模块：
- `net/WskClient.h`：WSK 客户端，提供网络传输
- `tls/TlsConnection.h`：TLS 连接，提供加密通信
- `crypto/CngProviderCache.h`：CNG 提供者缓存，提供密码学操作
- `http/HttpParser.h`：HTTP 解析器
- `http2/Http2Connection.h`：HTTP/2 连接
- `websocket/WebSocketFrame.h`：WebSocket 帧处理

> **注意**：内部实现细节（如 `engine/EngineInternal.h`、`engine/ConnectionPool.h`、`engine/Workspace.h`、`engine/Async.h` 等）不属于公共 API，不应直接使用。

## 2. 核心概念与句柄类型

底层 API 使用不透明句柄类型，所有句柄都以 `KH_` 为前缀：

| 句柄类型 | 描述 | 创建函数 | 释放函数 |
|---|---|---|---|
| `KH_SESSION` | 会话句柄，包含连接池、工作空间等全局状态 | `KhSessionCreate` | `KhSessionClose` |
| `KH_REQUEST` | 请求句柄，包含 URL、方法、头部、正文等 | `KhHttpRequestCreate` | `KhHttpRequestRelease` |
| `KH_RESPONSE` | 响应句柄，包含状态码、头部、正文等 | `KhHttpSendSync`/`KhHttpSendAsync` | `KhResponseRelease` |
| `KH_WEBSOCKET` | WebSocket 句柄，包含连接状态、收发缓冲等 | `KhWebSocketConnectSync`/`KhWebSocketConnectAsync` | `KhWebSocketCloseSync` |
| `KH_ASYNC_OPERATION` | 异步操作句柄，包含任务状态、回调等 | `KhHttpSendAsync`/`KhWebSocketConnectAsync` | `KhAsyncRelease` |

## 3. 资源生命周期与所有权

调用方负责在每个对象上配对调用创建/释放函数：

```cpp
// 创建会话
KH_SESSION session = nullptr;
NTSTATUS status = KhSessionCreate(&wskClient, &sessionOptions, &session);
if (!NT_SUCCESS(status)) {
    // 处理错误
}

// 创建请求
KH_REQUEST request = nullptr;
status = KhHttpRequestCreate(session, &request);
if (!NT_SUCCESS(status)) {
    KhSessionClose(session);
    return status;
}

// 构造请求
KhHttpRequestSetUrl(request, url, urlLength);
KhHttpRequestSetMethod(request, KhHttpMethod::Get);

// 发送请求
KH_RESPONSE response = nullptr;
status = KhHttpSendSync(session, request, nullptr, &response);
if (NT_SUCCESS(status)) {
    // 使用响应
    KhResponseView view = {};
    KhResponseGetView(response, &view);
    // ...
    KhResponseRelease(response);
}

// 释放资源
KhHttpRequestRelease(request);
KhSessionClose(session);
```

调用规则：
- 所有释放函数都接受 `nullptr`，可以无条件调用。
- `KhHttpRequestRelease` 在请求被 `KhHttpSendSync`/`KhHttpSendAsync` 消费后仍需调用。
- `KhResponseRelease` 必须在使用完响应后调用，即使请求失败也可能返回非空响应。
- `KhAsyncRelease` 必须在异步操作完成后调用，即使操作被取消。
- `KhWebSocketCloseSync` 必须在 WebSocket 使用完成后调用。

## 4. 会话管理（`KhSession*`）

会话是底层 API 的核心容器，管理连接池、工作空间、TLS 配置等全局状态。

### 4.1 创建会话

```cpp
NTSTATUS KhSessionCreate(
    _In_ net::WskClient* wskClient,      // WSK 客户端，必须已初始化
    _In_opt_ const KhSessionOptions* options,  // 会话选项，可空使用默认
    _Out_ KH_SESSION* session) noexcept;       // 输出会话句柄
```

`KhSessionOptions` 结构体：

```cpp
struct KhSessionOptions final {
    KhPoolType ResponsePoolType = KhPoolType::NonPaged;  // 响应缓冲池类型
    SIZE_T MaxResponseBytes = KhDefaultMaxResponseBytes;  // 0 表示不限制
    ULONG ConnectionPoolCapacity = KhDefaultConnectionPoolCapacity;  // 连接池容量 (8)
    ULONG MaxConnectionsPerHost = KhDefaultConnectionsPerHost;  // 每主机最大连接数 (2)
    ULONG IdleTimeoutMilliseconds = KhDefaultIdleTimeoutMilliseconds;  // 空闲超时 (30000ms)
    KhTlsOptions Tls = {};  // 默认 TLS 配置
};
```

### 4.2 关闭会话

```cpp
void KhSessionClose(_In_opt_ KH_SESSION session) noexcept;
```

关闭会话会：
- 释放连接池中的所有连接
- 释放工作空间和缓冲区
- 释放 CNG 提供者缓存
- 释放会话句柄本身

### 4.3 TLS 配置

`KhTlsOptions` 结构体用于配置 TLS 连接：

```cpp
struct KhTlsOptions final {
    KhTlsVersion MinVersion = KhTlsVersion::Tls12;  // 最小 TLS 版本
    KhTlsVersion MaxVersion = KhTlsVersion::Tls13;  // 最大 TLS 版本
    KhCertificatePolicy CertificatePolicy = KhCertificatePolicy::Verify;  // 证书策略
    const tls::CertificateStore* CertificateStore = nullptr;  // 证书存储
    const char* ServerName = nullptr;  // SNI 服务器名称
    SIZE_T ServerNameLength = 0;
    const char* Alpn = nullptr;  // ALPN 协议，如 "h2"、"http/1.1"
    SIZE_T AlpnLength = 0;
    ULONG HandshakeReceiveTimeoutMilliseconds = KhDefaultTlsHandshakeReceiveTimeoutMilliseconds;  // 握手超时
};
```

## 5. 请求构建（`KhRequest*`）

请求句柄用于构建 HTTP 请求，包括 URL、方法、头部、正文等。

### 5.1 创建请求

```cpp
NTSTATUS KhHttpRequestCreate(
    _In_ KH_SESSION session,     // 会话句柄
    _Out_ KH_REQUEST* request) noexcept;  // 输出请求句柄
```

### 5.2 设置请求属性

| 函数 | 描述 |
|---|---|
| `KhHttpRequestSetUrl` | 设置请求 URL（必填） |
| `KhHttpRequestSetMethod` | 设置 HTTP 方法（默认 GET） |
| `KhHttpRequestSetHeader` | 添加请求头 |
| `KhHttpRequestSetBody` | 设置通用字节正文 |
| `KhHttpRequestSetTextBody` | 设置文本正文 |
| `KhHttpRequestSetRawBody` | 设置自定义 Content-Type 的字节正文 |
| `KhHttpRequestSetUrlEncodedBody` | 设置表单编码正文 |
| `KhHttpRequestSetMultipartFormDataBody` | 设置 multipart/form-data 正文 |
| `KhHttpRequestSetFileBody` | 设置文件路径作为正文 |
| `KhHttpRequestClearBody` | 清除已设置的正文 |
| `KhHttpRequestSetTlsOptions` | 覆盖会话默认 TLS 配置 |
| `KhHttpRequestSetConnectionPolicy` | 设置连接策略 |
| `KhHttpRequestSetAddressFamily` | 设置地址族 |

### 5.3 HTTP 方法枚举

```cpp
enum class KhHttpMethod : ULONG {
    Get = 0,
    Post = 1,
    Put = 2,
    Patch = 3,
    Delete = 4,
    Head = 5,
    Options = 6
};
```

### 5.4 连接策略

```cpp
enum class KhConnectionPolicy : ULONG {
    ReuseOrCreate = 0,  // 复用现有连接或创建新连接
    ForceNew = 1,       // 强制创建新连接
    NoPool = 2          // 不进入连接池
};
```

### 5.5 地址族

```cpp
enum class KhAddressFamily : ULONG {
    Any = 0,   // 系统默认
    Ipv4 = 4,  // 仅 IPv4
    Ipv6 = 6   // 仅 IPv6
};
```

### 5.6 请求正文类型

#### 通用字节正文
```cpp
NTSTATUS KhHttpRequestSetBody(
    _In_ KH_REQUEST request,
    _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
    SIZE_T bodyLength) noexcept;
```

#### 文本正文
```cpp
NTSTATUS KhHttpRequestSetTextBody(
    _In_ KH_REQUEST request,
    _In_reads_bytes_opt_(textLength) const char* text,
    SIZE_T textLength,
    _In_reads_bytes_opt_(contentTypeLength) const char* contentType,  // 可空，默认 text/plain; charset=utf-8
    SIZE_T contentTypeLength) noexcept;
```

#### 表单编码正文
```cpp
NTSTATUS KhHttpRequestSetUrlEncodedBody(
    _In_ KH_REQUEST request,
    _In_reads_(pairCount) const KhNameValuePair* pairs,
    SIZE_T pairCount) noexcept;
```

`KhNameValuePair` 结构体：
```cpp
struct KhNameValuePair final {
    const char* Name = nullptr;
    SIZE_T NameLength = 0;
    const char* Value = nullptr;
    SIZE_T ValueLength = 0;
};
```

#### Multipart 表单正文
```cpp
NTSTATUS KhHttpRequestSetMultipartFormDataBody(
    _In_ KH_REQUEST request,
    _In_reads_(partCount) const KhMultipartFormDataPart* parts,
    SIZE_T partCount) noexcept;
```

`KhMultipartFormDataPart` 结构体：
```cpp
struct KhMultipartFormDataPart final {
    KhRequestBodyPartKind Kind = KhRequestBodyPartKind::Field;
    const char* Name = nullptr;
    SIZE_T NameLength = 0;
    const char* Value = nullptr;
    SIZE_T ValueLength = 0;
    const UCHAR* Data = nullptr;
    SIZE_T DataLength = 0;
    const char* FilePath = nullptr;
    SIZE_T FilePathLength = 0;
    const char* FileName = nullptr;
    SIZE_T FileNameLength = 0;
    const char* ContentType = nullptr;
    SIZE_T ContentTypeLength = 0;
};
```

`KhRequestBodyPartKind` 枚举：
```cpp
enum class KhRequestBodyPartKind : ULONG {
    Field = 0,      // 普通字段
    FileBytes = 1,  // 文件字节
    FilePath = 2    // 文件路径
};
```

#### 文件正文
```cpp
NTSTATUS KhHttpRequestSetFileBody(
    _In_ KH_REQUEST request,
    _In_reads_bytes_(filePathLength) const char* filePath,  // 内核态使用 NT 路径
    SIZE_T filePathLength,
    _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
    SIZE_T contentTypeLength) noexcept;
```

## 6. 发送请求

### 6.1 同步发送

```cpp
NTSTATUS KhHttpSendSync(
    _In_ KH_SESSION session,
    _In_ KH_REQUEST request,
    _In_opt_ const KhHttpSendOptions* options,
    _Out_opt_ KH_RESPONSE* response) noexcept;
```

`KhHttpSendOptions` 结构体：
```cpp
struct KhHttpSendOptions final {
    SIZE_T MaxResponseBytes = 0;  // 0 表示不限制；options == nullptr 时也不限制
    ULONG Flags = KhHttpSendFlagNone;  // 发送标志
    KhHeaderCallback HeaderCallback = nullptr;  // 响应头回调
    KhBodyCallback BodyCallback = nullptr;  // 响应体回调
    void* CallbackContext = nullptr;  // 回调上下文
    KhAsyncCompletionCallback CompletionCallback = nullptr;  // 完成回调（仅异步）
    void* CompletionContext = nullptr;  // 完成回调上下文
};
```

发送标志：
```cpp
enum KhHttpSendFlags : ULONG {
    KhHttpSendFlagNone = 0,
    KhHttpSendFlagAggregateWithCallbacks = 0x00000001  // 使用回调时仍聚合响应
};
```

### 6.2 异步发送

```cpp
NTSTATUS KhHttpSendAsync(
    _In_ KH_SESSION session,
    _In_ KH_REQUEST request,
    _In_opt_ const KhHttpSendOptions* options,
    _Out_ KH_ASYNC_OPERATION* operation) noexcept;
```

### 6.3 回调函数类型

```cpp
// 响应头回调
typedef NTSTATUS (*KhHeaderCallback)(
    void* context,
    const char* name,
    SIZE_T nameLength,
    const char* value,
    SIZE_T valueLength);

// 响应体回调
typedef NTSTATUS (*KhBodyCallback)(
    void* context,
    const UCHAR* data,
    SIZE_T dataLength,
    bool finalChunk);

// 异步完成回调
typedef void (*KhAsyncCompletionCallback)(
    void* context,
    NTSTATUS status);
```

## 7. 响应处理（`KhResponse*`）

### 7.1 获取响应视图

```cpp
NTSTATUS KhResponseGetView(
    _In_ KH_RESPONSE response,
    _Out_ KhResponseView* view) noexcept;
```

`KhResponseView` 结构体：
```cpp
struct KhResponseView final {
    ULONG StatusCode = 0;       // HTTP 状态码
    const UCHAR* Body = nullptr;  // 响应体指针
    SIZE_T BodyLength = 0;      // 响应体长度
};
```

### 7.2 获取响应头

```cpp
// 按名称获取响应头（大小写不敏感）
NTSTATUS KhResponseGetHeader(
    _In_ KH_RESPONSE response,
    _In_reads_bytes_(nameLength) const char* name,
    SIZE_T nameLength,
    _Outptr_result_bytebuffer_(*valueLength) const char** value,
    _Out_ SIZE_T* valueLength) noexcept;

// 获取响应头数量
SIZE_T KhResponseHeaderCount(_In_opt_ KH_RESPONSE response) noexcept;

// 按索引获取响应头
NTSTATUS KhResponseGetHeaderAt(
    _In_ KH_RESPONSE response,
    SIZE_T index,
    _Outptr_result_bytebuffer_(*nameLength) const char** name,
    _Out_ SIZE_T* nameLength,
    _Outptr_result_bytebuffer_(*valueLength) const char** value,
    _Out_ SIZE_T* valueLength) noexcept;
```

### 7.3 释放响应

```cpp
void KhResponseRelease(_In_opt_ KH_RESPONSE response) noexcept;
```

## 8. 异步操作（`KhAsyncOperation*`）

### 8.1 异步操作管理

```cpp
// 取消异步操作
NTSTATUS KhAsyncCancel(_In_ KH_ASYNC_OPERATION operation) noexcept;

// 等待异步操作完成
NTSTATUS KhAsyncWait(
    _In_ KH_ASYNC_OPERATION operation,
    ULONG timeoutMilliseconds) noexcept;

// 获取异步操作的 HTTP 响应
NTSTATUS KhAsyncGetHttpResponse(
    _In_ KH_ASYNC_OPERATION operation,
    _Out_ KH_RESPONSE* response) noexcept;

// 获取异步操作的 WebSocket 连接
NTSTATUS KhAsyncGetWebSocket(
    _In_ KH_ASYNC_OPERATION operation,
    _Out_ KH_WEBSOCKET* websocket) noexcept;

// 释放异步操作
void KhAsyncRelease(_In_opt_ KH_ASYNC_OPERATION operation) noexcept;
```



## 9. WebSocket 支持

### 9.1 连接 WebSocket

```cpp
// 同步连接
NTSTATUS KhWebSocketConnectSync(
    _In_ KH_SESSION session,
    _In_ const KhWebSocketConnectOptions* options,
    _Out_ KH_WEBSOCKET* websocket) noexcept;

// 异步连接
NTSTATUS KhWebSocketConnectAsync(
    _In_ KH_SESSION session,
    _In_ const KhWebSocketConnectOptions* options,
    _Out_ KH_ASYNC_OPERATION* operation) noexcept;
```

`KhWebSocketConnectOptions` 结构体：
```cpp
struct KhWebSocketConnectOptions final {
    const char* Url = nullptr;
    SIZE_T UrlLength = 0;
    const char* Subprotocol = nullptr;
    SIZE_T SubprotocolLength = 0;
    KhTlsOptions Tls = {};
    KhAddressFamily AddressFamily = KhAddressFamily::Any;
    SIZE_T MaxMessageBytes = KhDefaultMaxResponseBytes;
    bool AutoReplyPing = true;
};
```

### 9.2 发送消息

```cpp
// 发送文本消息
NTSTATUS KhWebSocketSendTextSync(
    _In_ KH_WEBSOCKET websocket,
    _In_reads_bytes_(textLength) const char* text,
    SIZE_T textLength,
    _In_opt_ const KhWebSocketSendOptions* options) noexcept;

// 发送二进制消息
NTSTATUS KhWebSocketSendBinarySync(
    _In_ KH_WEBSOCKET websocket,
    _In_reads_bytes_(dataLength) const UCHAR* data,
    SIZE_T dataLength,
    _In_opt_ const KhWebSocketSendOptions* options) noexcept;
```

`KhWebSocketSendOptions` 结构体：
```cpp
struct KhWebSocketSendOptions final {
    bool FinalFragment = true;  // 是否为最后一个分片
};
```

### 9.3 接收消息

```cpp
NTSTATUS KhWebSocketReceiveSync(
    _In_ KH_WEBSOCKET websocket,
    _In_opt_ const KhWebSocketReceiveOptions* options,
    _Out_opt_ KhWebSocketMessage* message) noexcept;
```

`KhWebSocketReceiveOptions` 结构体：
```cpp
struct KhWebSocketReceiveOptions final {
    SIZE_T MaxMessageBytes = 0;  // 最大消息字节数，0 表示使用默认
    bool AutoAllocate = true;   // 是否自动分配存储
    KhWebSocketMessageCallback MessageCallback = nullptr;  // 消息回调
    void* CallbackContext = nullptr;  // 回调上下文
};
```

`KhWebSocketMessage` 结构体：
```cpp
struct KhWebSocketMessage final {
    KhWebSocketMessageType Type = KhWebSocketMessageType::Binary;  // 消息类型
    const UCHAR* Data = nullptr;  // 消息数据
    SIZE_T DataLength = 0;       // 消息长度
    bool FinalFragment = true;   // 是否为最后一个分片
};
```

`KhWebSocketMessageType` 枚举：
```cpp
enum class KhWebSocketMessageType : ULONG {
    Text = 0,    // 文本消息
    Binary = 1,  // 二进制消息
    Close = 2    // 关闭消息
};
```

### 9.4 关闭 WebSocket

```cpp
NTSTATUS KhWebSocketCloseSync(_In_opt_ KH_WEBSOCKET websocket) noexcept;
```

## 10. 测试辅助函数

底层 API 提供了一系列测试辅助函数，用于单元测试和调试。这些函数仅在定义了 `KERNEL_HTTP_USER_MODE_TEST` 宏时可用。

### 10.1 HTTP 传输测试钩子

```cpp
// 设置 HTTP 传输测试回调
void KhTestSetHttpTransport(
    KhTestHttpTransportCallback callback,
    void* context) noexcept;
```

### 10.2 WebSocket 传输测试钩子

```cpp
// 设置 WebSocket 传输测试回调
void KhTestSetWebSocketTransport(
    KhTestWebSocketConnectCallback connectCallback,
    KhTestWebSocketSendCallback sendCallback,
    KhTestWebSocketReceiveCallback receiveCallback,
    KhTestWebSocketCloseCallback closeCallback,
    void* context) noexcept;
```

### 10.3 异步操作测试辅助

```cpp
// 设置异步操作自动运行
void KhTestSetAsyncAutoRun(bool enabled) noexcept;

// 手动运行异步操作
NTSTATUS KhTestRunAsyncOperation(_In_ KH_ASYNC_OPERATION operation) noexcept;

// 查询异步操作状态
NTSTATUS KhTestAsyncStatus(_In_ KH_ASYNC_OPERATION operation) noexcept;

// 检查异步操作是否已完成
bool KhTestAsyncIsCompleted(_In_ KH_ASYNC_OPERATION operation) noexcept;

// 检查异步操作是否已取消
bool KhTestAsyncIsCanceled(_In_ KH_ASYNC_OPERATION operation) noexcept;
```

### 10.4 会话状态查询

```cpp
// 检查会话是否有工作空间
bool KhTestSessionHasWorkspace(KH_SESSION session) noexcept;

// 检查会话是否有提供者缓存
bool KhTestSessionHasProviderCache(KH_SESSION session) noexcept;
```

## 11. 最佳实践

### 11.1 资源管理

- 始终检查 `NTSTATUS` 返回值
- 使用 RAII 模式或确保在所有代码路径上释放资源
- 避免在异步操作完成前释放相关资源

### 11.2 连接复用

- 使用 `KhConnectionPolicy::ReuseOrCreate` 以获得最佳性能
- 避免频繁创建新连接（`KhConnectionPolicy::ForceNew`）
- 对于一次性请求，使用 `KhConnectionPolicy::NoPool`

### 11.3 TLS 配置

- 在会话级别设置默认 TLS 配置
- 在请求级别覆盖特定请求的 TLS 配置
- 使用 `CertificateStore` 进行证书锁定

### 11.4 异步操作

- 使用 `KhAsyncWait` 等待异步操作完成
- 使用 `KhAsyncCancel` 取消长时间运行的操作
- 始终调用 `KhAsyncRelease` 释放异步操作句柄

### 11.5 WebSocket

- 使用 `AutoReplyPing = true` 自动响应 Ping 消息
- 设置合理的 `MaxMessageBytes` 防止内存耗尽
- 始终调用 `KhWebSocketCloseSync` 关闭连接

## 12. 错误处理

### 12.1 常见错误码

| NTSTATUS | 描述 |
|---|---|
| `STATUS_SUCCESS` | 操作成功 |
| `STATUS_INVALID_PARAMETER` | 参数无效 |
| `STATUS_INSUFFICIENT_RESOURCES` | 资源不足 |
| `STATUS_IO_TIMEOUT` | 操作超时 |
| `STATUS_CONNECTION_DISCONNECTED` | 连接断开 |
| `STATUS_TRUST_FAILURE` | 证书信任失败 |
| `STATUS_NOT_SUPPORTED` | 操作不支持 |
| `STATUS_CANCELLED` | 操作被取消 |

### 12.2 错误处理策略

```cpp
NTSTATUS status = KhHttpSendSync(session, request, nullptr, &response);
if (!NT_SUCCESS(status)) {
    // 处理错误
    switch (status) {
    case STATUS_IO_TIMEOUT:
        // 超时处理
        break;
    case STATUS_CONNECTION_DISCONNECTED:
        // 连接断开处理
        break;
    case STATUS_TRUST_FAILURE:
        // 证书错误处理
        break;
    default:
        // 其他错误处理
        break;
    }
}
```

## 13. 性能考虑

### 13.1 连接池优化

- 根据应用需求调整 `ConnectionPoolCapacity`
- 监控 `ActiveCount` 避免连接池耗尽
- 使用 `IdleTimeoutMilliseconds` 及时释放空闲连接

### 13.2 内存管理

- 使用 `KhPoolType::Paged` 用于大响应，避免非分页池耗尽
- 合理设置 `MaxResponseBytes` 防止内存耗尽；0 表示不限制
- 及时释放不再需要的响应和请求

### 13.3 异步操作

- 使用异步操作避免阻塞线程
- 合理设置超时时间
- 使用回调函数处理完成事件

## 14. 示例代码

### 14.1 完整的 HTTP GET 请求

```cpp
#include <KernelHttp/engine/Engine.h>

NTSTATUS PerformHttpGet(net::WskClient& wskClient) {
    // 创建会话
    KH_SESSION session = nullptr;
    KhSessionOptions sessionOptions = {};
    NTSTATUS status = KhSessionCreate(&wskClient, &sessionOptions, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 创建请求
    KH_REQUEST request = nullptr;
    status = KhHttpRequestCreate(session, &request);
    if (!NT_SUCCESS(status)) {
        KhSessionClose(session);
        return status;
    }

    // 设置请求属性
    const char* url = "http://example.com/api/data";
    KhHttpRequestSetUrl(request, url, strlen(url));
    KhHttpRequestSetMethod(request, KhHttpMethod::Get);
    KhHttpRequestSetHeader(request, "User-Agent", 10, "KernelHttp/1.0", 14);

    // 发送请求
    KH_RESPONSE response = nullptr;
    KhHttpSendOptions sendOptions = {};
    sendOptions.MaxResponseBytes = 1024 * 1024;  // 显式限制为 1 MiB；0 表示不限制
    status = KhHttpSendSync(session, request, &sendOptions, &response);

    if (NT_SUCCESS(status)) {
        // 获取响应
        KhResponseView view = {};
        KhResponseGetView(response, &view);
        
        // 处理响应
        if (view.StatusCode == 200) {
            // 处理成功响应
            // ...
        }
        
        KhResponseRelease(response);
    }

    // 清理资源
    KhHttpRequestRelease(request);
    KhSessionClose(session);
    
    return status;
}
```

### 14.2 带 TLS 的 HTTPS 请求

```cpp
NTSTATUS PerformHttpsRequest(net::WskClient& wskClient) {
    // 创建会话
    KH_SESSION session = nullptr;
    KhSessionOptions sessionOptions = {};
    
    // 配置 TLS
    sessionOptions.Tls.MinVersion = KhTlsVersion::Tls12;
    sessionOptions.Tls.MaxVersion = KhTlsVersion::Tls13;
    sessionOptions.Tls.CertificatePolicy = KhCertificatePolicy::Verify;
    // sessionOptions.Tls.CertificateStore = &trustStore;  // 设置证书存储
    
    NTSTATUS status = KhSessionCreate(&wskClient, &sessionOptions, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 创建请求
    KH_REQUEST request = nullptr;
    status = KhHttpRequestCreate(session, &request);
    if (!NT_SUCCESS(status)) {
        KhSessionClose(session);
        return status;
    }

    // 设置请求
    const char* url = "https://example.com/secure";
    KhHttpRequestSetUrl(request, url, strlen(url));
    KhHttpRequestSetMethod(request, KhHttpMethod::Get);
    
    // 覆盖请求级 TLS 配置
    KhTlsOptions requestTls = {};
    requestTls.CertificatePolicy = KhCertificatePolicy::NoVerify;  // 不校验证书
    KhHttpRequestSetTlsOptions(request, &requestTls);

    // 发送请求
    KH_RESPONSE response = nullptr;
    status = KhHttpSendSync(session, request, nullptr, &response);
    
    if (NT_SUCCESS(status)) {
        KhResponseView view = {};
        KhResponseGetView(response, &view);
        // 处理响应...
        KhResponseRelease(response);
    }

    KhHttpRequestRelease(request);
    KhSessionClose(session);
    
    return status;
}
```

### 14.3 异步请求

```cpp
NTSTATUS PerformAsyncRequest(net::WskClient& wskClient) {
    KH_SESSION session = nullptr;
    NTSTATUS status = KhSessionCreate(&wskClient, nullptr, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KH_REQUEST request = nullptr;
    status = KhHttpRequestCreate(session, &request);
    if (!NT_SUCCESS(status)) {
        KhSessionClose(session);
        return status;
    }

    const char* url = "http://example.com/api/data";
    KhHttpRequestSetUrl(request, url, strlen(url));
    KhHttpRequestSetMethod(request, KhHttpMethod::Get);

    // 异步发送
    KH_ASYNC_OPERATION operation = nullptr;
    KhHttpSendOptions sendOptions = {};
    sendOptions.CompletionCallback = [](void* context, NTSTATUS status) {
        // 完成回调
        printf("Async operation completed with status: 0x%08X\n", status);
    };
    
    status = KhHttpSendAsync(session, request, &sendOptions, &operation);
    if (!NT_SUCCESS(status)) {
        KhHttpRequestRelease(request);
        KhSessionClose(session);
        return status;
    }

    // 等待完成
    status = KhAsyncWait(operation, 30000);  // 30 秒超时
    
    if (NT_SUCCESS(status)) {
        KH_RESPONSE response = nullptr;
        status = KhAsyncGetHttpResponse(operation, &response);
        if (NT_SUCCESS(status)) {
            KhResponseView view = {};
            KhResponseGetView(response, &view);
            // 处理响应...
            KhResponseRelease(response);
        }
    }

    // 清理
    KhAsyncRelease(operation);
    KhHttpRequestRelease(request);
    KhSessionClose(session);
    
    return status;
}
```

### 14.4 WebSocket 连接

```cpp
NTSTATUS PerformWebSocketConnection(net::WskClient& wskClient) {
    KH_SESSION session = nullptr;
    NTSTATUS status = KhSessionCreate(&wskClient, nullptr, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 配置 WebSocket 连接
    KhWebSocketConnectOptions wsOptions = {};
    wsOptions.Url = "wss://example.com/ws";
    wsOptions.UrlLength = strlen(wsOptions.Url);
    wsOptions.MaxMessageBytes = 64 * 1024;
    wsOptions.AutoReplyPing = true;
    
    // 配置 TLS
    wsOptions.Tls.CertificatePolicy = KhCertificatePolicy::NoVerify;

    // 连接 WebSocket
    KH_WEBSOCKET websocket = nullptr;
    status = KhWebSocketConnectSync(session, &wsOptions, &websocket);
    if (!NT_SUCCESS(status)) {
        KhSessionClose(session);
        return status;
    }

    // 发送消息
    const char* message = "Hello, WebSocket!";
    status = KhWebSocketSendTextSync(websocket, message, strlen(message), nullptr);
    if (!NT_SUCCESS(status)) {
        KhWebSocketCloseSync(websocket);
        KhSessionClose(session);
        return status;
    }

    // 接收消息
    KhWebSocketMessage receivedMessage = {};
    status = KhWebSocketReceiveSync(websocket, nullptr, &receivedMessage);
    if (NT_SUCCESS(status)) {
        // 处理接收到的消息
        if (receivedMessage.Type == KhWebSocketMessageType::Text) {
            // 处理文本消息
            // ...
        }
    }

    // 关闭连接
    KhWebSocketCloseSync(websocket);
    KhSessionClose(session);
    
    return status;
}
```

## 15. 与高层 API 的关系

底层 API 是高层 API 的基础实现。高层 API（`KernelHttp::khttp`）在底层 API 之上提供了更简洁的接口，隐藏了底层细节。选择使用哪个 API 取决于具体需求：

- **高层 API**：适合大多数应用场景，提供简洁的接口和自动资源管理
- **底层 API**：适合需要精细控制、性能优化或特殊定制的场景

底层 API 的优势：
- 更精细的控制连接池、TLS 配置
- 直接访问内部组件和缓冲区
- 更好的性能优化机会
- 支持自定义测试钩子

高层 API 的优势：
- 更简洁的接口
- 自动资源管理
- 更少的样板代码
- 更好的易用性

## 16. 注意事项

1. **线程安全**：底层 API 不是线程安全的，多线程访问需要外部同步
2. **IRQL 要求**：所有 API 必须在 `PASSIVE_LEVEL` 调用
3. **内存管理**：调用方负责管理所有分配的内存
4. **错误处理**：必须检查所有 `NTSTATUS` 返回值
5. **资源释放**：确保在所有代码路径上释放资源
6. **版本兼容性**：内部结构可能随版本变化，避免直接访问内部字段

## 17. 调试技巧

1. **启用测试钩子**：使用 `KhTestSetHttpTransport` 等函数注入测试回调
2. **监控连接池**：检查连接池容量和活跃连接数
3. **跟踪异步操作**：使用 `KhAsyncWait` 等待完成，或使用测试辅助函数 `KhTestAsyncStatus` 监控状态
4. **验证 TLS 配置**：确保 TLS 版本和证书策略正确
5. **检查缓冲区**：验证缓冲区大小和内容

## 18. 版本历史

- v1.0：初始版本，包含完整的底层 API 定义
- 测试辅助函数：支持用户模式测试和内核模式调试
- 异步操作：支持后台任务执行和取消
- WebSocket：支持全双工通信

## 19. 相关文档

- [高层 API 文档](high-level-api.md)：高层 API 的详细使用说明，适合大多数应用场景
- [API 概述](api-overview.md)：高层 API 和底层 API 的对比和选择指南
- [项目说明](../README.md)：项目概述和构建说明
- [AGENTS.md](../AGENTS.md)：工程约束和开发规范
