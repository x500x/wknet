# 高层 API / High-Level API

本页是 `khttp` / `kws` 高层 API 的结构体与函数参考。HTTP 在命名空间 `khttp`，WebSocket 在命名空间 `kws`。高层 HTTP API 隐藏 WSK 运行时：调用方创建 `Session` 后即可发送请求，不向高层 `SessionCreate` 传入 `net::WskClient`。

[English](#english) | 简体中文

---

## 简体中文

### 快速开始

#### 发送一个 GET 请求

```cpp
khttp::Session* session = nullptr;
khttp::Response* response = nullptr;

// 创建会话
khttp::SessionCreate(&session);

// 发送 GET 请求
khttp::Get(session, "https://httpbin.org/get", &response);

// 读取响应
if (response) {
    ULONG statusCode = khttp::ResponseStatusCode(response);
    const UCHAR* body = khttp::ResponseBody(response);
    SIZE_T bodyLength = khttp::ResponseBodyLength(response);
}

// 释放资源
khttp::ResponseRelease(response);
khttp::SessionClose(session);
```

#### 发送 POST JSON

```cpp
khttp::Session* session = nullptr;
khttp::Response* response = nullptr;

khttp::SessionCreate(&session);

// 创建 JSON 请求体
khttp::Body* body = nullptr;
khttp::BodyCreateJsonCopy("{\"key\":\"value\"}", 13, &body);

// 发送 POST 请求
khttp::Post(session, "https://httpbin.org/post", body, &response);

khttp::BodyRelease(body);
khttp::ResponseRelease(response);
khttp::SessionClose(session);
```

#### 异步请求

```cpp
khttp::AsyncOp* op = nullptr;
khttp::Response* response = nullptr;

// 异步发送 GET
khttp::AsyncGet(session, "https://httpbin.org/get", &op);

// 等待完成
khttp::AsyncWait(op, 30000);

// 获取响应
khttp::AsyncGetResponse(op, &response);

khttp::ResponseRelease(response);
khttp::AsyncRelease(op);
```

### 阅读约定

在使用高层 API 前，请记住以下几点：

- **句柄都是堆对象**：所有高层公开句柄（`Session`、`Request`、`Response`、`AsyncOp`、`Headers`、`Body`、`kws::WebSocket`）都是不透明的堆指针。不要在栈上声明这些对象，使用对应的 `Create` 函数创建，用匹配的 `Close` / `Release` 函数释放。
- **选项也是堆对象**：`SendOptions` / `AsyncOptions` 同样需要通过 `SendOptionsCreate` / `AsyncOptionsCreate` 创建，拿到指针后再修改字段。
- **调用级别**：所有高层 HTTP/WS 调用必须在 `PASSIVE_LEVEL` 执行。
- **错误处理**：返回值统一为 `NTSTATUS`，用 `NT_SUCCESS(status)` 判断成功。标记 `_Must_inspect_result_` 的返回值必须检查，这是内核代码的基本纪律。
- **安全释放**：`Release` / `Close` 函数接受 `nullptr`，这意味着你可以在失败路径中无条件调用它们，简化清理逻辑。
- **响应体大小**：`MaxResponseBytes = 0` 表示不设置响应体聚合上限（推荐用法）；非零值才表示你主动限制 buffered response 大小。
- **JSON 只是透传**：`BodyCreateJson` 等函数只设置 `Content-Type: application/json; charset=utf-8` 并透传字节，不解析、不校验、不构造 JSON。如果你需要 JSON 操作，请使用专门的 JSON 库。

### 头文件总览

以下是高层 API 涉及的主要头文件。大多数情况下，你只需要包含 `KernelHttp/KernelHttp.h` 即可使用所有功能，但了解各个头文件的职责有助于理解代码组织：

| 头文件 | 内容 |
|--------|------|
| `KernelHttp/KernelHttp.h` | 总入口，包含高层 HTTP、WebSocket、底层 engine 与基础类型 |
| `KernelHttp/khttp/Types.h` | 枚举、配置结构体、回调类型、公开常量 |
| `KernelHttp/khttp/Session.h` | `SessionCreate` / `SessionClose` |
| `KernelHttp/khttp/Request.h` | `RequestCreate` / `RequestRelease` |
| `KernelHttp/khttp/Headers.h` | `Headers` 句柄创建、添加、释放 |
| `KernelHttp/khttp/Body.h` | `Body` 句柄创建、模式、trailer、释放 |
| `KernelHttp/khttp/Options.h` | `SendOptions` / `AsyncOptions` 创建与释放 |
| `KernelHttp/khttp/Http.h` | 同步 HTTP 发送与便捷函数（Get、Post 等） |
| `KernelHttp/khttp/HttpAsync.h` | 异步 HTTP 发送与便捷函数（AsyncGet、AsyncPost 等） |
| `KernelHttp/khttp/AsyncOp.h` | 异步操作等待、取消、取结果、释放 |
| `KernelHttp/khttp/Response.h` | 响应只读访问与释放 |
| `KernelHttp/khttp/Lifecycle.h` | `Destroy` 异步收尾入口 |
| `KernelHttp/kws/WebSocket.h` | 高层 WebSocket 连接、收发、关闭 |

## 类型与结构体总览

### 不透明句柄

高层 API 使用不透明句柄来管理资源。这些句柄都是堆分配的对象，你需要通过对应的创建函数获取，用完后通过释放函数归还。这种模式在内核编程中很常见，它能帮你避免资源泄露和生命周期问题。

| 类型 | 命名空间 | 创建函数 | 释放函数 | 说明 |
|------|----------|----------|----------|------|
| `Session` | `khttp` | `SessionCreate` | `SessionClose` | HTTP/WS 会话。内部拥有隐藏 WSK runtime 和 engine session |
| `Request` | `khttp` | `RequestCreate` | `RequestRelease` | 绑定到 `Session` 的发送句柄；不保存 URL、method、header、body |
| `Response` | `khttp` | 由发送/异步结果返回 | `ResponseRelease` | 独立响应句柄，包含状态码、响应体、响应头、trailer |
| `AsyncOp` | `khttp` | 异步发送或 WS 异步连接返回 | `AsyncRelease` | 异步操作句柄，可等待、取消、取结果 |
| `Headers` | `khttp` | `HeadersCreate` | `HeadersRelease` | 请求头集合；添加时复制 name/value |
| `Body` | `khttp` | `BodyCreate*` | `BodyRelease` | 请求体描述；支持引用/拷贝、表单、multipart、文件、chunked trailer |
| `WebSocket` | `kws` | `Connect` / `ConnectEx` / `AsyncGetWebSocket` | `Close` / `CloseEx` | WebSocket 连接句柄 |

### 枚举

枚举类型定义了 API 中使用的各种选项和模式。以下是完整的枚举定义：

```cpp
enum class Method : ULONG {
    Get, Post, Put, Patch, Delete, Head, Options, Connect
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

每个枚举的用途如下：

| 枚举 | 说明 |
|------|------|
| `Method` | HTTP 方法。`Connect` 主要供特殊场景或底层能力使用，普通 HTTP 请求不需要直接使用 |
| `PoolType` | 响应缓冲池类型。内核路径当前要求 `NonPaged`；`Paged` 是保留 ABI 值，暂时不要使用 |
| `TlsVersion` | TLS 最小/最大版本。推荐使用 `Tls12` 或更高版本 |
| `CertPolicy` | 证书校验策略。生产环境应该使用 `Verify`，仅在测试时考虑 `NoVerify` |
| `AddressFamily` | DNS/连接地址族选择。`Any` 会自动选择合适的地址族 |
| `ConnPolicy` | 单次发送连接池策略。`ReuseOrCreate` 是最常用的选择 |
| `BodyPartKind` | multipart part 类型。`Field` 用于普通表单字段，`FileBytes` 和 `FilePath` 用于文件上传 |
| `RequestBodyMode` | 请求体 framing：`ContentLength` 用于已知大小的请求体，`Chunked` 用于流式数据 |

### 发送标志

发送标志控制单次发送的特殊行为。你可以通过 `SendOptions::Flags` 字段设置：

```cpp
enum SendFlags : ULONG {
    SendFlagNone = 0,
    SendFlagAggregateWithCallbacks = 0x00000001,
    SendFlagDisableAutoRedirect = 0x00000002
};
```

| 标志 | 说明 |
|------|------|
| `SendFlagNone` | 默认行为，不需要显式设置 |
| `SendFlagAggregateWithCallbacks` | 调用 header/body 回调，同时保留聚合响应。适用于需要流式处理响应但又想保留完整响应的场景 |
| `SendFlagDisableAutoRedirect` | 禁用自动重定向，直接返回 3xx 响应。适用于需要手动处理重定向的场景 |

### 回调类型

回调函数让你能够在响应到达时进行流式处理，而不是等待整个响应完成。这在处理大响应或需要实时处理数据的场景中特别有用。

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

typedef void (*CompletionCallback)(
    void* context,
    NTSTATUS status);
```

| 回调 | 触发时机 | 返回值 |
|------|----------|--------|
| `HeaderCallback` | 收到响应头时逐个调用 | 返回失败会中止发送并传播该状态。你可以用这个回调来检查响应头或记录日志 |
| `BodyCallback` | 收到响应体分块时调用 | 返回失败会中止发送并传播该状态。`finalChunk` 为 `true` 时表示这是最后一块数据 |
| `CompletionCallback` | 异步操作完成时调用 | `void`，不影响操作结果。主要用于异步操作的完成通知 |

`context` 来自 `SendOptions::CallbackContext` 或 `AsyncOptions::CompletionContext`，这是你传递自定义数据给回调的方式。

## 结构体字段参考

### `TlsConfig`

`TlsConfig` 结构体用于配置 TLS 连接的安全参数。你可以在两个地方使用它：作为 `SessionConfig::Tls` 设置会话默认值，或者作为 `SendOptions::Tls` 为单次发送覆盖配置。

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
};
```

| 字段 | 默认 | 说明 |
|------|------|------|
| `MinVersion` | `Tls12` | 允许的最低 TLS 版本。除非有特殊需求，否则保持默认值即可 |
| `MaxVersion` | `Tls13` | 允许的最高 TLS 版本。`Tls13` 提供更好的安全性和性能 |
| `Certificate` | `Verify` | 是否校验证书链、主机名、策略。生产环境必须使用 `Verify` |
| `Store` | `nullptr` | 自定义证书存储；`nullptr` 使用库默认信任来源。如果你需要信任自签名证书，可以提供自定义存储 |
| `ServerName` / `ServerNameLength` | `nullptr` / `0` | SNI 与证书主机名；为空时从 URL host 推导。大多数情况下让库自动处理即可 |
| `Alpn` / `AlpnLength` | `nullptr` / `0` | 显式 ALPN；为空时按 `PreferHttp2` 自动提供。除非需要特定的 ALPN 协议，否则保持默认 |
| `PreferHttp2` | `true` | 自动 ALPN 时优先提供 HTTP/2。HTTP/2 提供多路复用和头部压缩，推荐保持 `true` |
| `Policy` | `{}` | TLS 安全策略，详见 TLS 文档。可以配置加密套件、签名算法等 |
| `ClientCredential` | `nullptr` | mTLS 客户端凭据。仅在需要客户端证书认证时设置 |
| `HandshakeTimeoutMs` | `DefaultTlsHandshakeTimeoutMs` | TLS 握手超时。网络环境较差时可以适当增大 |

### `ProxyConfig`

`ProxyConfig` 结构体用于配置 HTTPS CONNECT 代理。如果你需要通过代理服务器访问目标网站，可以在这里设置代理参数。

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

| 字段 | 默认 | 说明 |
|------|------|------|
| `Enabled` | `false` | 是否启用代理。设为 `true` 时才会使用代理连接 |
| `Address` | `{}` | 代理服务器的 socket 地址 |
| `Authority` / `AuthorityLength` | `nullptr` / `0` | CONNECT authority，例如 `proxy.example:8080`。这是代理服务器的地址和端口 |
| `AuthHeader` / `AuthHeaderLength` | `nullptr` / `0` | 可选 `Proxy-Authorization` 值，只发给代理。如果代理需要认证，在这里设置认证头 |

### `SessionConfig`

`SessionConfig` 结构体用于配置会话级别的参数。创建 `Session` 时传入这个结构体，可以控制连接池大小、缓冲区大小、超时时间等。大多数情况下，使用 `DefaultSessionConfig()` 获取默认值就足够了。

```cpp
struct SessionConfig final {
    PoolType ResponsePool;
    SIZE_T RequestBufferBytes;
    SIZE_T MaxResponseBytes;
    ULONG PoolCapacity;
    ULONG MaxConnsPerHost;
    ULONG IdleTimeoutMs;
    TlsConfig Tls;
    ProxyConfig Proxy;
};
```

| 字段 | 默认 | 说明 |
|------|------|------|
| `ResponsePool` | `NonPaged` | 响应缓冲池类型；内核路径当前要求 `NonPaged`，不要修改 |
| `RequestBufferBytes` | `16 KiB` | HTTP/1.1 请求行、请求头和请求体构造缓冲。如果请求头特别长，可以适当增大 |
| `MaxResponseBytes` | `0` | 0 表示不设置调用方响应体聚合上限（推荐用法）。非零值表示主动限制 buffered response 大小 |
| `PoolCapacity` | `8` | 连接池总容量。根据并发请求数量调整，但不要设置过大 |
| `MaxConnsPerHost` | `2` | 单主机最大连接数。HTTP/2 下通常 1 个连接就够了 |
| `IdleTimeoutMs` | `30000` | 空闲连接回收时间，单位毫秒。30 秒是合理的默认值 |
| `Tls` | `DefaultTlsConfig()` | 会话默认 TLS 配置。可以在单次发送时覆盖 |
| `Proxy` | disabled | HTTPS CONNECT 代理配置。默认不启用代理 |

### `SendOptions`

`SendOptions` 结构体用于控制单次同步发送的行为。你必须通过 `SendOptionsCreate` 创建它，然后修改字段。这个结构体让你能够针对特定请求调整参数，而不影响会话默认配置。

```cpp
struct SendOptions final {
    SIZE_T MaxResponseBytes;
    ULONG Flags;
    ULONG MaxRedirects;
    HeaderCallback OnHeader;
    BodyCallback OnBody;
    void* CallbackContext;
    TlsConfig Tls;
    bool HasTlsOverride;
    ConnPolicy ConnectionPolicy;
    AddressFamily Family;
};
```

| 字段 | 默认 | 说明 |
|------|------|------|
| `MaxResponseBytes` | `0` | 0 表示本次发送不设置调用方响应体聚合上限；非零值表示本次主动限制。大多数情况下保持 0 即可 |
| `Flags` | `SendFlagNone` | 发送标志。可以组合多个标志，例如 `SendFlagAggregateWithCallbacks | SendFlagDisableAutoRedirect` |
| `MaxRedirects` | `0` | 0 表示使用 engine 默认重定向上限（通常 5 次）；非零值覆盖。设为 1 可以快速发现重定向问题 |
| `OnHeader` | `nullptr` | 响应头回调。用于流式处理响应头，例如记录日志或检查特定头 |
| `OnBody` | `nullptr` | 响应体分块回调。用于流式处理响应体，例如实时计算哈希或边下载边处理 |
| `CallbackContext` | `nullptr` | 传给 `OnHeader` / `OnBody` 的上下文。这是你传递自定义数据给回调的方式 |
| `Tls` | `DefaultTlsConfig()` | 单次 TLS 配置。仅在 `HasTlsOverride` 为 `true` 时生效 |
| `HasTlsOverride` | `false` | `true` 时使用 `Tls` 覆盖会话 TLS 配置。适用于需要为特定请求使用不同证书或 TLS 策略的场景 |
| `ConnectionPolicy` | `ReuseOrCreate` | 本次发送连接策略。`ReuseOrCreate` 是最常用的选择，它会复用已有连接或创建新连接 |
| `Family` | `Any` | 本次发送地址族。除非需要强制使用 IPv4 或 IPv6，否则保持 `Any` |

### `AsyncOptions`

`AsyncOptions` 结构体用于控制单次异步 HTTP 发送的行为。它包含了 `SendOptions` 作为成员，这样你可以同时设置同步和异步相关的参数。

```cpp
struct AsyncOptions final {
    SendOptions Send;
    CompletionCallback OnComplete;
    void* CompletionContext;
};
```

| 字段 | 默认 | 说明 |
|------|------|------|
| `Send` | `DefaultSendOptions()` | 异步发送使用的同步发送选项。你可以在这里设置回调、TLS 配置等 |
| `OnComplete` | `nullptr` | 异步完成回调。当操作完成时会调用这个函数，适合用于实现事件驱动的架构 |
| `CompletionContext` | `nullptr` | 传给 `OnComplete` 的上下文。这是你传递自定义数据给回调的方式 |

### `NameValuePair`

`NameValuePair` 结构体用于描述 form-url-encoded 表单字段。当你需要发送 `application/x-www-form-urlencoded` 格式的表单数据时，使用这个结构体定义字段名和值。

```cpp
struct NameValuePair final {
    const char* Name;
    SIZE_T NameLength;
    const char* Value;
    SIZE_T ValueLength;
};
```

**重要提示**：`BodyCreateForm` 会复制 `NameValuePair` 描述数组，但字段指向的 name/value 字节按引用使用，必须保持到同步发送返回或异步发送完成/取消。这意味着你不能在发送前释放 name/value 字符串。

### `MultipartPart`

`MultipartPart` 结构体用于描述 multipart/form-data 的每个部分。当你需要上传文件或发送复杂表单数据时，使用这个结构体定义每个 part。

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

| 字段 | 说明 |
|------|------|
| `Kind` | `Field` 表示普通字段；`FileBytes` 表示内存中文件内容；`FilePath` 表示从路径读取文件 |
| `Name` / `NameLength` | form 字段名。这是必须设置的字段 |
| `Value` / `ValueLength` | `Field` 的字段值。仅在 `Kind` 为 `Field` 时使用 |
| `Data` / `DataLength` | `FileBytes` 的文件内容字节。仅在 `Kind` 为 `FileBytes` 时使用 |
| `FilePath` / `FilePathLength` | `FilePath` 的文件路径。仅在 `Kind` 为 `FilePath` 时使用。库会在发送时读取文件内容 |
| `FileName` / `FileNameLength` | multipart filename。这是文件在表单中的显示名称，可以和实际文件名不同 |
| `ContentType` / `ContentTypeLength` | part Content-Type。例如 `image/png` 或 `application/pdf`。禁止 CR/LF 注入 |

**重要提示**：`BodyCreateMultipart` 会复制 part 描述数组，但 part 内指针按引用使用，必须保持到发送结束。这意味着你不能在发送前释放 part 中的字符串数据。

### `kws` WebSocket 结构体

以下是 WebSocket 相关的结构体。WebSocket 提供了全双工通信能力，适合实时数据推送、聊天、游戏等场景。

#### `kws::Header`

`Header` 结构体用于在 WebSocket 连接时添加额外的 HTTP 头。这些头会在 opening handshake 时发送给服务器。

```cpp
struct Header final {
    const char* Name;
    SIZE_T NameLength;
    const char* Value;
    SIZE_T ValueLength;
};
```

可以添加的头包括 `Origin`、`Authorization`、`Cookie` 等。但库受控头如 `Host`、`Connection`、`Upgrade`、`Sec-WebSocket-*` 会被拒绝，因为这些头由库自动管理。

#### `kws::ConnectConfig`

`ConnectConfig` 结构体用于配置 WebSocket 连接参数。你可以设置 URL、子协议、额外头、TLS 配置等。

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

| 字段 | 默认 | 说明 |
|------|------|------|
| `Url` / `UrlLength` | `nullptr` / `0` | `ws://` 或 `wss://` URL。这是必须设置的字段 |
| `Subprotocol` / `SubprotocolLength` | `nullptr` / `0` | 可选 `Sec-WebSocket-Protocol`。用于协商应用层子协议 |
| `Headers` / `HeaderCount` | `nullptr` / `0` | opening handshake 额外头。可以添加认证、来源等信息 |
| `Tls` | `DefaultTlsConfig()` | `wss` 使用的 TLS 配置。仅在使用 `wss://` 时生效 |
| `Family` | `Any` | 地址族。除非需要强制 IPv4/IPv6，否则保持 `Any` |
| `MaxMessageBytes` | `DefaultMaxWebSocketMessageBytes` | 单消息默认上限。防止恶意服务器发送超大消息 |
| `AutoReplyPing` | `true` | 收到 ping 时自动 pong。大多数情况下保持 `true` 即可 |
| `AllowWebSocketOverHttp2` | `false` | 显式 opt-in RFC 8441 WebSocket over HTTP/2。这是较新的特性，默认关闭 |

#### `kws::SendOptions`

`SendOptions` 结构体用于控制 WebSocket 消息的发送行为，特别是分片消息。

```cpp
struct SendOptions final {
    bool FinalFragment;
};
```

`FinalFragment=false` 用于发送分片消息的非最后帧，后续用 `SendContinuation` / `SendContinuationEx` 续发。分片消息适合发送大块数据，避免一次性占用太多内存。

#### `kws::ReceiveOptions`

`ReceiveOptions` 结构体用于控制 WebSocket 消息的接收行为。

```cpp
struct ReceiveOptions final {
    SIZE_T MaxMessageBytes;
    bool AutoAllocate;
    MessageCallback OnMessage;
    void* CallbackContext;
};
```

| 字段 | 默认 | 说明 |
|------|------|------|
| `MaxMessageBytes` | `0` | 0 表示使用连接默认消息上限。可以为特定接收设置更小的限制 |
| `AutoAllocate` | `true` | 是否由库自动分配消息缓冲。设为 `false` 时你需要自己管理内存 |
| `OnMessage` | `nullptr` | 收到消息/分片时的回调。用于流式处理消息 |
| `CallbackContext` | `nullptr` | 传给 `OnMessage` 的上下文 |

#### `kws::Message`

`Message` 结构体表示接收到的 WebSocket 消息。它包含了消息类型、数据、以及分片信息。

```cpp
struct Message final {
    MsgType Type;
    const UCHAR* Data;
    SIZE_T DataLength;
    bool Final;
    bool FinalFragment;
};
```

**重要提示**：`Data` 指向库内部缓冲，下一次 receive 或 close 前有效。如果你需要长期保存消息数据，请在下次接收前复制它。

## 函数总览

以下是高层 API 提供的所有函数。为了方便查阅，我们按功能分组列出。每个函数的具体用法和参数说明请参考后面的详细文档。

### 默认配置函数

这些函数返回各种配置结构体的默认值。在创建对象前，你可以先用这些函数获取默认配置，然后根据需要修改：

| 函数 | 功能 |
|------|------|
| `DefaultTlsConfig` | 返回默认 TLS 配置值 |
| `DefaultSessionConfig` | 返回默认会话配置值 |
| `DefaultSendOptions` | 返回默认发送选项值；正式使用优先选择 `SendOptionsCreate` |
| `kws::DefaultConnectConfig` | 返回默认 WebSocket 连接配置值 |

### HTTP 生命周期与句柄

这些函数管理 HTTP 会话和请求句柄的创建与销毁：

| 函数 | 功能 |
|------|------|
| `SessionCreate` | 创建高层会话，内部初始化隐藏 WSK runtime |
| `SessionClose` | 关闭会话，释放隐藏 WSK runtime |
| `RequestCreate` | 创建绑定到会话的发送句柄 |
| `RequestRelease` | 释放发送句柄 |
| `Destroy` | 等待/收尾库级异步运行时 |

### Headers / Body / Options

这些函数用于构建请求头、请求体和发送选项：

| 函数 | 功能 |
|------|------|
| `HeadersCreate` / `HeadersAdd` / `HeadersAddEx` / `HeadersRelease` | 创建、添加、释放请求头集合 |
| `BodyCreateBytes*` | 创建原始字节请求体 |
| `BodyCreateText*` | 创建文本请求体，可设置 Content-Type |
| `BodyCreateJson*` | 创建 JSON 字节请求体，不解析 JSON |
| `BodyCreateForm` | 创建 `application/x-www-form-urlencoded` 请求体 |
| `BodyCreateMultipart` | 创建 `multipart/form-data` 请求体 |
| `BodyCreateFile*` | 创建文件请求体 |
| `BodySetMode` | 设置 Content-Length 或 chunked framing |
| `BodyAddTrailer*` | 为 chunked body 添加 trailer |
| `BodyRelease` | 释放请求体句柄 |
| `SendOptionsCreate` / `SendOptionsRelease` | 创建/释放同步发送选项 |
| `AsyncOptionsCreate` / `AsyncOptionsRelease` | 创建/释放异步发送选项 |

### 同步 HTTP

这些函数用于发送同步 HTTP 请求。`Send` / `SendEx` 是通用入口，其他是便捷函数：

| 函数族 | 功能 |
|--------|------|
| `Send` / `SendEx` | 通用同步发送入口，显式传入 method、URL、headers、body、options |
| `Get` / `GetEx` | 发送 GET |
| `Post` / `PostEx` | 发送 POST |
| `Put` / `PutEx` | 发送 PUT |
| `Patch` / `PatchEx` | 发送 PATCH |
| `Delete` / `DeleteEx` | 发送 DELETE |
| `Head` / `HeadEx` | 发送 HEAD |
| `Options` / `OptionsEx` | 发送 HTTP OPTIONS |

### 异步 HTTP 与异步操作

这些函数用于发送异步 HTTP 请求和管理异步操作：

| 函数族 | 功能 |
|--------|------|
| `AsyncSend` / `AsyncSendEx` | 通用异步发送入口 |
| `AsyncGet*` / `AsyncPost*` / `AsyncPut*` / `AsyncPatch*` / `AsyncDelete*` / `AsyncHead*` | 异步便捷函数 |
| `AsyncOptionsRequest*` | 异步 HTTP OPTIONS 函数 |
| `AsyncWait` | 等待异步操作完成 |
| `AsyncCancel` | 请求取消异步操作 |
| `AsyncGetStatus` | 读取异步操作状态 |
| `AsyncIsCompleted` | 判断是否完成 |
| `AsyncIsCanceled` | 判断是否已取消 |
| `AsyncGetResponse` | 取 HTTP 异步响应 |
| `AsyncRelease` | 释放异步操作 |

### Response

这些函数用于读取 HTTP 响应：

| 函数 | 功能 |
|------|------|
| `ResponseStatusCode` | 读取 HTTP 状态码 |
| `ResponseBody` / `ResponseBodyLength` | 读取响应体指针与长度 |
| `ResponseHeaderCount` / `ResponseTrailerCount` | 读取响应头/trailer 数量 |
| `ResponseGetHeader` / `ResponseGetHeaderAt` | 按名称或索引读取响应头 |
| `ResponseGetTrailer` / `ResponseGetTrailerAt` | 按名称或索引读取 trailer |
| `ResponseRelease` | 释放响应句柄 |

### WebSocket

这些函数用于 WebSocket 连接和通信：

| 函数族 | 功能 |
|--------|------|
| `kws::Connect` / `ConnectEx` | 同步连接 WebSocket |
| `kws::ConnectAsync` / `ConnectAsyncEx` | 异步连接 WebSocket |
| `kws::AsyncGetWebSocket` | 从异步操作取 WebSocket 句柄 |
| `kws::SendText*` / `SendBinary*` / `SendContinuation*` / `SendPing` / `SendPong` | 发送 WebSocket 帧 |
| `kws::Receive` / `ReceiveEx` | 接收 WebSocket 消息 |
| `kws::Close` / `CloseEx` | 关闭 WebSocket |
| `kws::SelectedSubprotocol` | 查询协商子协议 |

## 函数详细参考

### 默认配置函数

这些函数返回各种配置结构体的默认值。在创建对象前，你可以先用这些函数获取默认配置，然后根据需要修改。

#### `DefaultTlsConfig`

```cpp
TlsConfig DefaultTlsConfig() noexcept;
```

返回默认 TLS 配置值。这是一个便捷函数，让你不需要手动初始化每个字段。

无参数。

返回 `TlsConfig` 值，字段为默认 TLS 配置。

#### `DefaultSessionConfig`

```cpp
SessionConfig DefaultSessionConfig() noexcept;
```

返回默认会话配置值。这个配置适用于大多数场景，除非你有特殊需求，否则直接使用即可。

无参数。

返回 `SessionConfig` 值。

#### `DefaultSendOptions`

```cpp
SendOptions DefaultSendOptions() noexcept;
```

返回默认发送选项值。正式高层调用推荐使用 `SendOptionsCreate` 创建堆对象后修改字段；这个函数主要用于内部和兼容场景。

无参数。

返回 `SendOptions` 值。

## 生命周期函数

这些函数管理 HTTP 会话和请求句柄的生命周期。正确管理这些句柄是避免资源泄露的关键。

### `SessionCreate`

```cpp
NTSTATUS SessionCreate(
    _Out_ Session** session
) noexcept;

NTSTATUS SessionCreate(
    _In_opt_ const SessionConfig* config,
    _Out_ Session** session
) noexcept;
```

创建高层 HTTP/WS 会话。会话内部初始化隐藏 WSK runtime，并创建 engine session、连接池、workspace、TLS provider cache 等资源。这是使用高层 API 的第一步。

| 参数 | 说明 |
|------|------|
| `config` | 会话配置；`nullptr` 表示使用 `DefaultSessionConfig()` |
| `session` | 成功时接收 `Session*`；失败时置为 `nullptr` |

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 创建成功 |
| `STATUS_INVALID_PARAMETER` | `session == nullptr` 或配置非法 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配会话、WSK runtime 或内部资源失败 |
| 其他失败状态 | WSK 初始化或 engine session 创建失败 |

NOTE:  成功后必须调用 `SessionClose` 释放会话。高层 `SessionCreate` 不接收 `net::WskClient*`，这是内部实现细节。`SessionClose` 前仍可释放由该会话创建的 `Request`，但不要在会话关闭后继续使用旧 `Request` 发送。

### `SessionClose`

```cpp
void SessionClose(
    _In_opt_ Session* session
) noexcept;
```

关闭并释放会话。这是一个安全的函数，接受 `nullptr` 参数。

| 参数 | 说明 |
|------|------|
| `session` | 要关闭的会话；`nullptr` 直接返回 |

无返回值。

NOTE:  关闭会话会关闭内部 engine session 并关闭隐藏 WSK runtime。使用过异步 API 时，驱动卸载前还必须调用 `Destroy()`。

### `RequestCreate`

```cpp
NTSTATUS RequestCreate(
    _In_ Session* session,
    _Out_ Request** out
) noexcept;
```

创建绑定到 `Session` 的发送句柄。`Request` 可以作为 `Send*` / `AsyncSend*` 的第一个参数，与 `Session*` 行为等价。

| 参数 | 说明 |
|------|------|
| `session` | 父会话 |
| `out` | 成功时接收 `Request*` |

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 创建成功 |
| `STATUS_INVALID_PARAMETER` | 参数为空、会话无效或会话已关闭 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败 |

NOTE:  `Request` 不再是 builder。method、URL、headers、body、options 都在 `Send*` / `AsyncSend*` 调用中传入。这样设计是为了让同一个 `Request` 可以用于多次发送。

### `RequestRelease`

```cpp
void RequestRelease(
    _In_opt_ Request* request
) noexcept;
```

释放 `Request` 发送句柄。这是一个安全的函数，接受 `nullptr` 参数。

| 参数 | 说明 |
|------|------|
| `request` | 要释放的请求句柄 |

无返回值。

### `Destroy`

```cpp
void Destroy() noexcept;
```

库级异步收尾入口。这个函数用于清理异步运行时资源。

无参数。

无返回值。

NOTE: 用过 HTTP 或 WebSocket 异步 API 后，驱动卸载前必须调用。同步-only 路径可以无条件调用，不会有副作用。

## Headers 函数

这些函数用于管理 HTTP 请求头。请求头是 HTTP 请求的重要组成部分，用于传递元数据、认证信息、内容类型等。

### `HeadersCreate`

```cpp
NTSTATUS HeadersCreate(
    _Out_ Headers** headers
) noexcept;
```

创建空请求头集合。这是构建请求头的第一步。

| 参数 | 说明 |
|------|------|
| `headers` | 成功时接收 `Headers*`；失败时置为 `nullptr` |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 创建成功 |
| `STATUS_INVALID_PARAMETER` | `headers == nullptr` |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败 |

### `HeadersAdd` / `HeadersAddEx`

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

向 `Headers` 添加或覆盖一个请求头。按大小写不敏感字段名查重；同名字段会覆盖旧值。`HeadersAdd` 是便捷版本，要求 name/value 是 NUL 结尾字符串；`HeadersAddEx` 允许指定长度，适合非 NUL 结尾的字符串。

| 参数 | 说明 |
|------|------|
| `headers` | `HeadersCreate` 返回的句柄 |
| `name` | `_In_` | 否 | header 名称；`HeadersAdd` 要求 NUL 结尾 |
| `nameLength` | `_In_` | 否 | header 名称字节长度，不含 NUL |
| `value` | `_In_` | 否 | header 值；`HeadersAdd` 要求 NUL 结尾 |
| `valueLength` | `_In_` | 否 | header 值字节长度，不含 NUL |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 添加或覆盖成功 |
| `STATUS_INVALID_PARAMETER` | 句柄无效、名称非法、值含 CR/LF、或尝试添加库受控 header |
| `STATUS_INSUFFICIENT_RESOURCES` | 超过请求头数量上限或复制 name/value 失败 |

**所有权与限制**：

- name/value 总是复制到堆，调用返回后源缓冲可修改或释放。这意味着你不需要保持原始字符串的生命周期。
- 禁止 CR/LF 注入，这是安全要求。
- `Host`、`Content-Length`、连接 framing 相关字段等库受控 header 由库合成或拒绝。这些头由 HTTP 协议自动管理，不需要手动设置。

### `HeadersRelease`

```cpp
void HeadersRelease(
    _In_opt_ Headers* headers
) noexcept;
```

释放请求头集合及其复制的 name/value。这是一个安全的函数，接受 `nullptr` 参数。

| 参数 | 说明 |
|------|------|
| `headers` | 要释放的头集合 |

无返回值。

## Body 函数

这些函数用于创建和管理 HTTP 请求体。请求体是 HTTP 请求的可选部分，用于传递数据给服务器。khttp 支持多种请求体格式，包括原始字节、文本、JSON、表单、multipart 和文件。

### Body 引用与拷贝规则

理解 Body 的内存管理规则很重要。以下是不同 Body 创建函数的内存行为：

| 函数族 | 数据所有权 | 生命周期要求 |
|--------|------------|--------------|
| `BodyCreateBytes` / `BodyCreateText` / `BodyCreateJson` | 引用调用方字节 | 同步发送返回前有效；异步发送完成或取消前有效 |
| `BodyCreateBytesCopy` / `BodyCreateTextCopy` / `BodyCreateJsonCopy` | 创建时复制字节到堆 | 创建成功后源缓冲可释放 |
| `BodyCreateForm` | 复制 pair 描述数组，pair 内指针按引用使用 | pair 指向的 name/value 字节需保持到发送结束 |
| `BodyCreateMultipart` | 复制 part 描述数组，part 内指针按引用使用 | part 指向的字节需保持到发送结束 |
| `BodyCreateFile` / `BodyCreateFileEx` | 复制文件路径和 Content-Type | 文件内容在发送时读取 |

**简单规则**：如果你不确定该用哪个，优先使用带 `Copy` 后缀的函数，这样你不需要担心数据生命周期问题。

### `BodyCreateBytes` / `BodyCreateBytesEx`

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

创建引用调用方内存的原始字节 body，不设置 Content-Type。这是最基本的 body 创建函数。

| 参数 | 说明 |
|------|------|
| `data` | 请求体字节；`dataLength == 0` 时可空 |
| `dataLength` | 字节长度 |
| `body` | 成功时接收 `Body*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`

### `BodyCreateBytesCopy` / `BodyCreateBytesCopyEx`

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

创建原始字节 body，并在创建时复制调用方字节。创建成功后，`data` 可立即释放或修改。这是更安全的版本。

**参数和返回值**：同 `BodyCreateBytes`

### `BodyCreateText` / `BodyCreateTextEx`

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

创建引用调用方文本字节的 text body，可设置 Content-Type。适用于发送纯文本、HTML、XML 等文本格式。

| 参数 | 说明 |
|------|------|
| `text` | 文本字节，不要求 NUL 结尾；`textLength == 0` 时可空 |
| `textLength` | 文本字节长度 |
| `contentType` | Content-Type；`BodyCreateText` 要求 NUL 结尾 |
| `contentTypeLength` | Content-Type 字节长度，不含 NUL |
| `body` | 成功时接收 `Body*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`

### `BodyCreateTextCopy` / `BodyCreateTextCopyEx`

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

创建 text body，并复制文本和 Content-Type。创建成功后，`text` 与 `contentType` 源缓冲可立即释放或修改。这是更安全的版本。

**参数和返回值**：同 `BodyCreateText`

### `BodyCreateJson` / `BodyCreateJsonEx`

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

创建引用调用方 JSON 字节的 body，并设置 `Content-Type: application/json; charset=utf-8`。注意：库不解析、不校验 JSON，只负责设置正确的 Content-Type 头。

| 参数 | 说明 |
|------|------|
| `json` | JSON 字节；库不解析、不校验；`jsonLength == 0` 时可空 |
| `jsonLength` | JSON 字节长度 |
| `body` | 成功时接收 `Body*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`

### `BodyCreateJsonCopy` / `BodyCreateJsonCopyEx`

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

创建 JSON body，并复制 JSON 字节。创建成功后，`json` 源缓冲可立即释放或修改。这是更安全的版本。

**参数和返回值**：同 `BodyCreateJson`

### `BodyCreateForm`

```cpp
NTSTATUS BodyCreateForm(
    _In_ const NameValuePair* pairs,
    _In_ SIZE_T pairCount,
    _Out_ Body** body
) noexcept;
```

创建 `application/x-www-form-urlencoded` body。适用于提交表单数据。

| 参数 | 说明 |
|------|------|
| `pairs` | form 字段数组 |
| `pairCount` | 字段数量，必须大于 0 且不超过每请求字段上限 |
| `body` | 成功时接收 `Body*` |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 创建成功 |
| `STATUS_INVALID_PARAMETER` | `pairs` 为空、数量非法或字段非法 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败 |

### `BodyCreateMultipart`

```cpp
NTSTATUS BodyCreateMultipart(
    _In_ const MultipartPart* parts,
    _In_ SIZE_T partCount,
    _Out_ Body** body
) noexcept;
```

创建 `multipart/form-data` body。适用于文件上传和复杂表单提交。

| 参数 | 说明 |
|------|------|
| `parts` | multipart part 数组 |
| `partCount` | part 数量，必须大于 0 且不超过每请求字段上限 |
| `body` | 成功时接收 `Body*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`

### `BodyCreateFile` / `BodyCreateFileEx`

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

创建文件请求体。库复制文件路径和 Content-Type，发送时读取文件内容。适用于上传本地文件。

| 参数 | 说明 |
|------|------|
| `filePath` | 文件路径；`BodyCreateFile` 要求 NUL 结尾 |
| `filePathLength` | 文件路径字节长度 |
| `contentType` | Content-Type；为空则不显式设置 |
| `contentTypeLength` | Content-Type 字节长度 |
| `body` | 成功时接收 `Body*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`

### `BodySetMode`

```cpp
NTSTATUS BodySetMode(
    _Inout_ Body* body,
    _In_ RequestBodyMode mode
) noexcept;
```

设置请求体 framing 模式。默认是 `ContentLength`，适用于已知大小的请求体；`Chunked` 适用于流式数据。

| 参数 | 说明 |
|------|------|
| `body` | body 句柄 |
| `mode` | `ContentLength` 或 `Chunked` |

返回值：`STATUS_SUCCESS` 或 `STATUS_INVALID_PARAMETER`

### `BodyAddTrailer` / `BodyAddTrailerEx`

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

为 chunked 请求体添加 trailer 字段。Trailer 是在请求体发送完毕后发送的额外头字段，常用于发送签名或校验和。

| 参数 | 说明 |
|------|------|
| `body` | body 句柄 |
| `name` | trailer 名称 |
| `nameLength` | trailer 名称字节长度 |
| `value` | trailer 值 |
| `valueLength` | trailer 值字节长度 |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 添加成功 |
| `STATUS_INVALID_PARAMETER` | 参数非法、名称非法、值含 CR/LF |
| `STATUS_NOT_SUPPORTED` | trailer 字段被禁止，如 `Content-Length`、`Transfer-Encoding`、`Host`、认证或 cookie 相关字段 |
| `STATUS_INSUFFICIENT_RESOURCES` | 超过数量上限或复制失败 |

NOTE: trailer 只在 `BodySetMode(body, RequestBodyMode::Chunked)` 后发送。

### `BodyRelease`

```cpp
void BodyRelease(
    _In_opt_ Body* body
) noexcept;
```

释放 body 句柄及其拥有的堆内存。这是一个安全的函数，接受 `nullptr` 参数。

| 参数 | 说明 |
|------|------|
| `body` | body 句柄；可为空 |

无返回值。

## Options 函数

这些函数用于创建和管理发送选项。发送选项控制单次发送的行为，包括超时、重定向、回调等。

### `SendOptionsCreate`

```cpp
NTSTATUS SendOptionsCreate(
    _Out_ SendOptions** options
) noexcept;
```

创建堆上的 `SendOptions` 并填入默认值。这是创建发送选项的推荐方式。

| 参数 | 说明 |
|------|------|
| `options` | 成功时接收 `SendOptions*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`

### `SendOptionsRelease`

```cpp
void SendOptionsRelease(
    _In_opt_ SendOptions* options
) noexcept;
```

释放 `SendOptions`。这是一个安全的函数，接受 `nullptr` 参数。

| 参数 | 说明 |
|------|------|
| `options` | 发送选项句柄；可为空 |

无返回值。

### `AsyncOptionsCreate`

```cpp
NTSTATUS AsyncOptionsCreate(
    _Out_ AsyncOptions** options
) noexcept;
```

创建堆上的 `AsyncOptions` 并填入默认值。这是创建异步发送选项的推荐方式。

| 参数 | 说明 |
|------|------|
| `options` | 成功时接收 `AsyncOptions*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`

### `AsyncOptionsRelease`

```cpp
void AsyncOptionsRelease(
    _In_opt_ AsyncOptions* options
) noexcept;
```

释放 `AsyncOptions`。这是一个安全的函数，接受 `nullptr` 参数。

| 参数 | 说明 |
|------|------|
| `options` | 异步选项句柄；可为空 |

无返回值。

## 同步 HTTP 函数

同步函数会阻塞当前线程直到请求完成，适用于简单的请求-响应模式。

### `Send` / `SendEx` 和便捷函数

发送 HTTP 请求有两种方式：

```cpp
// 方式一：通用函数，需要手动传入 Method
NTSTATUS Send(Session* session, Method method, const char* url, 
              const Headers* headers, const Body* body, 
              const SendOptions* options, Response** response);
NTSTATUS SendEx(Session* session, Method method, const char* url, SIZE_T urlLength, ...);

// 方式二：便捷函数，函数名就是 HTTP 方法
NTSTATUS Get(Session* session, const char* url, Response** response);
NTSTATUS GetEx(Session* session, const char* url, SIZE_T urlLength,
               const Headers* headers, const SendOptions* options, Response** response);

NTSTATUS Post(Session* session, const char* url, const Body* body, Response** response);
NTSTATUS PostEx(Session* session, const char* url, SIZE_T urlLength,
                const Headers* headers, const Body* body,
                const SendOptions* options, Response** response);

// ... Put、Patch、Delete、Head、Options 类似
```

`Send` / `SendEx` 是通用入口，适用于所有场景。便捷函数（`Get`、`Post` 等）是语法糖，让你不需要手动构造 `Method` 枚举。两种方式在底层完全等价，选择哪种取决于个人偏好。

**NOTE**: `Request*` 也可以作为第一个参数，与 `Session*` 行为等价。

每个动词都有 `Session*` 和 `Request*` 两个版本，还各有三个重载：最简版（只传必要参数）、带长度的版、和完整版（带 headers/options）。

| 参数 | 说明 |
|------|------|
| `session` / `request` | 会话或请求句柄 |
| `method` | HTTP 方法，仅 `Send` / `SendEx` 需要 |
| `url` | 请求 URL。非 `Ex` 版本要求 NUL 结尾 |
| `urlLength` | URL 字节长度，仅 `Ex` 版本需要 |
| `headers` | 请求头集合，`nullptr` 表示只用库默认头 |
| `body` | 请求体，`nullptr` 表示无 body。`Get`/`Delete`/`Head`/`Options` 没有这个参数 |
| `options` | 发送选项，`nullptr` 表示用默认值 |
| `response` | 成功时接收 `Response*`，记得用 `ResponseRelease` 释放 |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 请求成功 |
| `STATUS_INVALID_PARAMETER` | 参数不合法 |
| `STATUS_INVALID_DEVICE_REQUEST` | 不在 `PASSIVE_LEVEL` 调用 |
| `STATUS_BUFFER_TOO_SMALL` | 响应超出了你设置的 `MaxResponseBytes` |
| `STATUS_IO_TIMEOUT` | 超时 |
| `STATUS_CONNECTION_DISCONNECTED` | 连接断开 |
| `STATUS_TRUST_FAILURE` | TLS 证书校验失败 |
| `STATUS_INVALID_NETWORK_RESPONSE` | 响应格式不对 |
| `STATUS_INSUFFICIENT_RESOURCES` | 内存不足或连接池满了 |
| 其他 `NTSTATUS` | 传输、TLS、解析或回调返回的错误 |

**NOTE**: 库会自动合成 `Host`、`Content-Length` 这类协议必需的 header。你传的 `headers` 会覆盖库的默认值（如果允许的话）。不要手动设置库受控的 header，会被拒绝或忽略。

`Session*` 重载签名：

```cpp
NTSTATUS Get(
    _In_ Session* session,
    _In_ const char* url,
    _Out_ Response** response
) noexcept;

NTSTATUS GetEx(
    _In_ Session* session,
    _In_ const char* url,
    _In_ SIZE_T urlLength,
    _In_opt_ const Headers* headers,
    _In_opt_ const SendOptions* options,
    _Out_ Response** response
) noexcept;

NTSTATUS Post(
    _In_ Session* session,
    _In_ const char* url,
    _In_opt_ const Body* body,
    _Out_ Response** response
) noexcept;

NTSTATUS PostEx(
    _In_ Session* session,
    _In_ const char* url,
    _In_ SIZE_T urlLength,
    _In_opt_ const Headers* headers,
    _In_opt_ const Body* body,
    _In_opt_ const SendOptions* options,
    _Out_ Response** response
) noexcept;

// ... Put、Patch、Delete、Head、Options 类似
```

`Request*` 重载签名：

```cpp
NTSTATUS Get(
    _In_ Request* request,
    _In_ const char* url,
    _Out_ Response** response
) noexcept;

NTSTATUS GetEx(
    _In_ Request* request,
    _In_ const char* url,
    _In_ SIZE_T urlLength,
    _In_opt_ const Headers* headers,
    _In_opt_ const SendOptions* options,
    _Out_ Response** response
) noexcept;

// ... Post、Put、Patch、Delete、Head、Options 类似
```

| 参数 | 说明 |
|------|------|
| `session` | 会话句柄；用于 `Session*` 重载 |
| `request` | 请求发送句柄；用于 `Request*` 重载 |
| `url` | 请求 URL。非 `Ex` 重载按 NUL 结尾字符串计算长度 |
| `urlLength` | URL 字节长度，不包含额外 NUL；仅 `Ex` 和显式长度便捷重载使用 |
| `headers` | 请求头集合；为空时只使用库合成 header |
| `body` | `Post` / `Put` / `Patch` 的请求体；无 body 时传 `nullptr` |
| `bodyLength` | 原始字节 body 长度；仅 `Session*` 的 `Post` / `Put` / `Patch` 字节便捷重载使用 |
| `options` | 同步发送选项；为空时使用默认发送选项 |
| `response` | 成功时接收 `Response*`，调用方用 `ResponseRelease` 释放 |

返回值：与 `Send` / `SendEx` 一致。`STATUS_SUCCESS` 表示收到并构造响应；`STATUS_INVALID_PARAMETER` 表示句柄、URL、输出指针等非法；其他失败状态来自 DNS、连接、TLS、HTTP 解析、重定向、回调或内存分配路径。

注意事项：

- `Get`、`Delete`、`Head`、`Options` 没有 `Body*` 参数；需要带 body 的非典型请求请使用通用 `Send` / `SendEx`。
- `Post`、`Put`、`Patch` 的 `Body*` 重载不会复制 body 句柄本身；body 的引用/拷贝语义由 `BodyCreate*` 函数决定。
- `Session*` 的原始字节便捷重载会创建调用期引用 body；`body` 必须在调用返回前保持有效。
- `Head` 请求通常不返回响应体；仍然通过 `Response*` 读取状态码和响应头。

## 异步 HTTP 函数

异步函数不会阻塞当前线程，适合需要并发处理多个请求或不想阻塞调用线程的场景。异步操作的典型用法是：创建操作 -> 等待完成 -> 获取结果 -> 释放操作。

### `AsyncSend` / `AsyncSendEx` 和异步便捷函数

和同步函数一样，异步也有通用入口和便捷函数两种方式：

```cpp
// 通用方式
NTSTATUS AsyncSend(Session* session, Method method, const char* url,
                   const Headers* headers, const Body* body,
                   const AsyncOptions* options, AsyncOp** operation);
NTSTATUS AsyncSendEx(Session* session, Method method, const char* url, SIZE_T urlLength,
                     const Headers* headers, const Body* body,
                     const AsyncOptions* options, AsyncOp** operation);

// Request* 版本
NTSTATUS AsyncSend(Request* request, Method method, const char* url, ...);
NTSTATUS AsyncSendEx(Request* request, Method method, const char* url, SIZE_T urlLength, ...);

// 便捷函数：更简洁
NTSTATUS AsyncGet(Session* session, const char* url, AsyncOp** operation);
NTSTATUS AsyncGetEx(Session* session, const char* url, SIZE_T urlLength,
                    const Headers* headers, const AsyncOptions* options, AsyncOp** operation);

NTSTATUS AsyncPost(Session* session, const char* url, const Body* body, AsyncOp** operation);
NTSTATUS AsyncPostEx(Session* session, const char* url, SIZE_T urlLength,
                     const Headers* headers, const Body* body,
                     const AsyncOptions* options, AsyncOp** operation);

// ... AsyncPut、AsyncPatch、AsyncDelete、AsyncHead 类似
// 注意：HTTP OPTIONS 的异步版本叫 AsyncOptionsRequest，不是 AsyncOptions（避免和类型名冲突）
```

参数：

| 参数 | 说明 |
|------|------|
| `session` / `request` | 会话或请求句柄 |
| `method` | HTTP 方法，仅 `AsyncSend` / `AsyncSendEx` 需要 |
| `url` / `urlLength` | URL 和长度 |
| `headers` | 请求头集合 |
| `body` | 请求体。`AsyncGet`/`AsyncDelete`/`AsyncHead` 没有这个参数 |
| `options` | 异步发送选项，`nullptr` 用默认值 |
| `operation` | 成功时接收 `AsyncOp*` |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 异步操作创建并排队成功 |
| `STATUS_INVALID_PARAMETER` | 参数或句柄非法 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败或异步队列满 |
| 其他失败状态 | 发送准备阶段失败 |

**生命周期注意事项**：

- 引用型 `Body` 的源缓冲必须保持到异步操作完成或取消
- 完成后调用 `AsyncGetResponse` 取响应，再调用 `ResponseRelease`
- 最后调用 `AsyncRelease`

| 函数族 | HTTP 方法 | 请求体 |
|--------|-----------|--------|
| `AsyncGet` / `AsyncGetEx` | `GET` | 无 |
| `AsyncPost` / `AsyncPostEx` | `POST` | 可选 |
| `AsyncPut` / `AsyncPutEx` | `PUT` | 可选 |
| `AsyncPatch` / `AsyncPatchEx` | `PATCH` | 可选 |
| `AsyncDelete` / `AsyncDeleteEx` | `DELETE` | 无 |
| `AsyncHead` / `AsyncHeadEx` | `HEAD` | 无 |
| `AsyncOptionsRequest` / `AsyncOptionsRequestEx` | `OPTIONS` | 无 |

NOTE: `AsyncOptionsRequest` 这个名字有点奇怪，但没办法——如果叫 `AsyncOptions` 就和选项类型名冲突了。`AsyncGet`、`AsyncDelete`、`AsyncHead`、`AsyncOptionsRequest` 没有 `Body*` 参数；需要非典型带 body 的请求请用通用 `AsyncSend`。引用型 `Body` 的源缓冲必须保持到异步操作完成或取消。成功创建操作后，调用方应 `AsyncWait` 等待终态，调用 `AsyncGetResponse` 取得响应，再分别释放 `Response` 和 `AsyncOp`。

## 异步操作函数

这些函数用于管理异步操作的生命周期和状态。

### `AsyncWait`

```cpp
NTSTATUS AsyncWait(
    _In_ AsyncOp* operation,
    _In_ ULONG timeoutMs
) noexcept;
```

等待异步操作完成。这是同步等待异步结果的方式。

| 参数 | 说明 |
|------|------|
| `operation` | 异步操作句柄 |
| `timeoutMs` | 等待超时毫秒；传 `0xffffffffUL` 表示无限等待 |

返回值：完成状态、`STATUS_TIMEOUT`、`STATUS_INVALID_PARAMETER` 或等待过程中的失败状态

### `AsyncCancel`

```cpp
NTSTATUS AsyncCancel(
    _In_ AsyncOp* operation
) noexcept;
```

请求取消异步操作。取消是协作式的，不是立即生效的。

| 参数 | 说明 |
|------|------|
| `operation` | 异步操作句柄；不可为空 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER` 或取消过程失败状态

NOTE: 取消后仍应调用 `AsyncWait` 等待终态，再释放操作。不要假设取消后操作立即完成。

### `AsyncGetStatus`

```cpp
NTSTATUS AsyncGetStatus(
    _In_opt_ const AsyncOp* operation
) noexcept;
```

读取异步操作当前/最终状态。适合用于非阻塞检查。

| 参数 | 说明 |
|------|------|
| `operation` | 异步操作句柄；可为空；空或无效句柄返回失败状态 |

返回值：当前 `NTSTATUS`

### `AsyncIsCompleted`

```cpp
bool AsyncIsCompleted(
    _In_opt_ const AsyncOp* operation
) noexcept;
```

判断异步操作是否完成。这是一个轻量级的检查，不会阻塞。

| 参数 | 说明 |
|------|------|
| `operation` | 异步操作句柄；可为空 |

返回值：完成返回 `true`，未完成或句柄为空返回 `false`

### `AsyncIsCanceled`

```cpp
bool AsyncIsCanceled(
    _In_opt_ const AsyncOp* operation
) noexcept;
```

判断异步操作是否被请求取消。

| 参数 | 说明 |
|------|------|
| `operation` | 异步操作句柄；可为空 |

返回值：已取消返回 `true`，否则返回 `false`

### `AsyncGetResponse`

```cpp
NTSTATUS AsyncGetResponse(
    _In_ AsyncOp* operation,
    _Out_ Response** response
) noexcept;
```

从已完成 HTTP 异步操作中取出响应。必须在操作完成后调用。

| 参数 | 说明 |
|------|------|
| `operation` | HTTP send 异步操作 |
| `response` | 成功时接收 `Response*` |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 成功取出响应 |
| `STATUS_INVALID_PARAMETER` | 参数或操作类型非法 |
| `STATUS_PENDING` | 操作尚未完成，先调用 `AsyncWait` |
| 其他失败状态 | 发送失败或被取消 |

### `AsyncRelease`

```cpp
void AsyncRelease(
    _In_opt_ AsyncOp* operation
) noexcept;
```

释放异步操作句柄。这是一个安全的函数，接受 `nullptr` 参数。

| 参数 | 说明 |
|------|------|
| `operation` | 异步操作句柄；可为空 |

无返回值。

## Response 函数

这些函数用于读取 HTTP 响应的内容。Response 是一个只读句柄，包含了状态码、响应头、响应体和 trailer。

### `ResponseStatusCode`

```cpp
ULONG ResponseStatusCode(
    _In_opt_ const Response* response
) noexcept;
```

读取 HTTP 状态码。这是你检查请求是否成功的第一步。

| 参数 | 说明 |
|------|------|
| `response` | 响应句柄；可为空 |

返回值：状态码（如 200、404、500）；空或无效句柄返回 `0`

### `ResponseBody` / `ResponseBodyLength`

```cpp
const UCHAR* ResponseBody(
    _In_opt_ const Response* response
) noexcept;

SIZE_T ResponseBodyLength(
    _In_opt_ const Response* response
) noexcept;
```

读取聚合响应体指针与长度。响应体是库自动聚合的完整内容。

| 参数 | 说明 |
|------|------|
| `response` | 响应句柄；可为空 |

返回值：`ResponseBody` 返回库内部缓冲指针，`ResponseBodyLength` 返回字节长度。指针在 `ResponseRelease` 前有效。

NOTE: 如果你设置了回调（`OnBody`），响应体可能为空，因为数据已经通过回调流式处理了。

### `ResponseHeaderCount` / `ResponseTrailerCount`

```cpp
SIZE_T ResponseHeaderCount(
    _In_opt_ const Response* response
) noexcept;

SIZE_T ResponseTrailerCount(
    _In_opt_ const Response* response
) noexcept;
```

读取响应头或 trailer 数量。用于遍历所有头字段。

| 参数 | 说明 |
|------|------|
| `response` | 响应句柄；可为空 |

返回值：数量；空或无效句柄返回 `0`

### `ResponseGetHeader`

```cpp
NTSTATUS ResponseGetHeader(
    _In_ const Response* response,
    _In_ const char* name,
    _In_ SIZE_T nameLength,
    _Out_ const char** value,
    _Out_ SIZE_T* valueLength
) noexcept;
```

按名称读取响应头。名称匹配大小写不敏感，所以你可以传 `"content-type"` 或 `"Content-Type"`。

| 参数 | 说明 |
|------|------|
| `response` | 响应句柄 |
| `name` | header 名称 |
| `nameLength` | 名称字节长度 |
| `value` | 成功时接收 header 值指针 |
| `valueLength` | 成功时接收值长度 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_NOT_FOUND`

### `ResponseGetHeaderAt`

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

按索引枚举响应头。适合当你想遍历所有头字段时使用。

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_NOT_FOUND`

### `ResponseGetTrailer` / `ResponseGetTrailerAt`

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

按名称或索引读取响应 trailer。Trailer 是在响应体之后发送的头字段，常用于 chunked 传输。

**参数与返回值**：同 header 读取函数

### `ResponseRelease`

```cpp
void ResponseRelease(
    _In_opt_ Response* response
) noexcept;
```

释放响应句柄及其内部缓冲。这是一个安全的函数，接受 `nullptr` 参数。

| 参数 | 说明 |
|------|------|
| `response` | 响应句柄；可为空 |

无返回值。

## WebSocket 函数

这些函数用于 WebSocket 连接和通信。WebSocket 提供全双工通信能力，适合实时数据推送、聊天、游戏等场景。

### `kws::DefaultConnectConfig`

```cpp
kws::ConnectConfig DefaultConnectConfig() noexcept;
```

返回默认 WebSocket 连接配置。在创建连接前，可以先用这个函数获取默认配置，然后根据需要修改。

无参数。

返回值：`ConnectConfig` 值

### `kws::Connect` / `kws::ConnectEx`

```cpp
// 简单版本：只传 URL
NTSTATUS Connect(
    _In_ khttp::Session* session,
    _In_ const char* url,
    _In_ SIZE_T urlLength,
    _Out_ WebSocket** websocket
) noexcept;

// 完整版本：传配置结构体
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

同步建立 WebSocket 连接。函数会阻塞直到握手完成。

| 参数 | 说明 |
|------|------|
| `session` | 高层会话 |
| `url` / `urlLength` | `ws://` 或 `wss://` URL |
| `config` | 连接配置 |
| `websocket` | 成功时接收 `WebSocket*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_NOT_SUPPORTED`、网络/TLS/HTTP 握手失败状态

### `kws::ConnectAsync` / `kws::ConnectAsyncEx`

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

异步建立 WebSocket 连接。参数与 `Connect` 类似，但输出为 `AsyncOp**`。成功后用 `AsyncWait` 等待，再用 `kws::AsyncGetWebSocket` 取连接。

### `kws::AsyncGetWebSocket`

```cpp
NTSTATUS AsyncGetWebSocket(
    _In_ khttp::AsyncOp* operation,
    _Out_ WebSocket** websocket
) noexcept;
```

从已完成 WebSocket connect 异步操作中取出 `WebSocket` 句柄。

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_PENDING` 或连接最终失败状态

### WebSocket 发送函数

这些函数用于发送 WebSocket 帧。WebSocket 支持文本、二进制、续帧、ping、pong 等帧类型。

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

| 参数 | 说明 |
|------|------|
| `websocket` | WebSocket 句柄 |
| `text` | 文本字节 |
| `data` | 二进制或续帧字节 |
| `payload` | ping/pong payload；`payloadLength == 0` 时可空 |
| `options` | `FinalFragment` 选项 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、连接关闭/断开/超时等传输失败状态

### `kws::Receive` / `kws::ReceiveEx`

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

接收 WebSocket 消息。这是一个阻塞调用，会等待直到收到消息或出错。

| 参数 | 说明 |
|------|------|
| `websocket` | WebSocket 句柄 |
| `options` | 接收选项 |
| `message` | 成功时接收消息视图；`ReceiveEx` 中可空 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_BUFFER_TOO_SMALL`、连接关闭/断开/超时等状态

### `kws::Close` / `kws::CloseEx`

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

关闭 WebSocket 连接。`Close` 是简单版本，`CloseEx` 允许你指定关闭状态码和原因。

| 参数 | 说明 |
|------|------|
| `websocket` | WebSocket 句柄；可为空 |
| `statusCode` | 关闭状态码 |
| `reason` | 关闭原因；`reasonLength == 0` 时可为空 |
| `reasonLength` | 关闭原因字节长度 |

返回值：关闭成功或传输失败状态

NOTE: 不要在同一 `WebSocket` 上并发执行 `Close` 和新的发送/接收。关闭操作应该是最后的操作。

### `kws::SelectedSubprotocol`

```cpp
NTSTATUS SelectedSubprotocol(
    _In_ WebSocket* websocket,
    _Out_ const char** subprotocol,
    _Out_ SIZE_T* subprotocolLength
) noexcept;
```

读取服务端选择的 WebSocket 子协议。在连接建立后调用，查看服务器选择了哪个子协议。

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_NOT_FOUND`

## 完整示例

下面是两个实际使用场景的代码示例，展示如何使用高层 API 发送 HTTP 请求。

### 同步 POST JSON

这个例子展示如何发送一个 JSON POST 请求，并读取响应：

```cpp
khttp::Session* session = nullptr;
khttp::Headers* headers = nullptr;
khttp::Body* body = nullptr;
khttp::SendOptions* options = nullptr;
khttp::Response* response = nullptr;

// 1. 创建会话
NTSTATUS status = khttp::SessionCreate(&session);

// 2. 创建请求头
if (NT_SUCCESS(status)) {
    status = khttp::HeadersCreate(&headers);
}
if (NT_SUCCESS(status)) {
    status = khttp::HeadersAdd(headers, "User-Agent", "KernelHttp/1.0");
}

// 3. 创建 JSON 请求体（使用 Copy 版本，这样我们不需要保持原始字符串）
if (NT_SUCCESS(status)) {
    status = khttp::BodyCreateJsonCopy("{\"hello\":\"world\"}", 17, &body);
}

// 4. 创建发送选项（可选）
if (NT_SUCCESS(status)) {
    status = khttp::SendOptionsCreate(&options);
}

// 5. 发送请求
if (NT_SUCCESS(status)) {
    options->MaxResponseBytes = 0;  // 不限制响应大小
    status = khttp::PostEx(
        session,
        "https://api.example.com/v1",
        sizeof("https://api.example.com/v1") - 1,
        headers,
        body,
        options,
        &response);
}

// 6. 处理响应
if (NT_SUCCESS(status)) {
    ULONG code = khttp::ResponseStatusCode(response);
    const UCHAR* bytes = khttp::ResponseBody(response);
    SIZE_T bytesLength = khttp::ResponseBodyLength(response);
    // 在这里处理响应数据...
}

// 7. 清理资源（释放顺序无所谓，因为所有函数都接受 nullptr）
khttp::ResponseRelease(response);
khttp::SendOptionsRelease(options);
khttp::BodyRelease(body);
khttp::HeadersRelease(headers);
khttp::SessionClose(session);
```

### 异步 GET

这个例子展示如何发送异步 GET 请求：

```cpp
khttp::AsyncOp* op = nullptr;
khttp::Response* response = nullptr;

// 1. 发送异步请求
NTSTATUS status = khttp::AsyncGetEx(
    session,
    url,
    urlLength,
    nullptr,  // 不需要额外头
n    nullptr,  // 使用默认选项
n    &op);

// 2. 等待完成（最多等 30 秒）
if (NT_SUCCESS(status)) {
    status = khttp::AsyncWait(op, 30000);
}

// 3. 获取响应
if (NT_SUCCESS(status)) {
    status = khttp::AsyncGetResponse(op, &response);
}

// 4. 处理响应...

// 5. 清理
khttp::ResponseRelease(response);
khttp::AsyncRelease(op);
```

## English

This page is the detailed high-level API reference for `khttp` and `kws`. The Chinese section above is the source of truth for signatures, parameters, return values, ownership, and lifetime rules.

Here are the key points:

- **Session creation**: High-level `SessionCreate` hides WSK. Use `SessionCreate(&session)` or `SessionCreate(&config, &session)`.
- **Handle management**: Public high-level objects are heap handles. Create them with API functions and release them with matching `Close` / `Release` functions. All release functions accept `nullptr`.
- **Send handles**: `Session*` and `Request*` are equivalent send handles. `Request` is not a builder.
- **HTTP sends**: Pass `method`, URL, optional `Headers`, optional `Body`, optional options, and an output handle per call.
- **Memory ownership**: `HeadersAdd*` copies name/value data. Non-copy body functions reference caller memory until sync send returns or async send completes/cancels.
- **JSON**: JSON body functions do not parse or build JSON; they only set `application/json; charset=utf-8` and pass bytes through.
- **Async**: Async HTTP entry points use the `Async` prefix. HTTP OPTIONS is `AsyncOptionsRequest` / `AsyncOptionsRequestEx` to avoid the C++ name collision with `AsyncOptions`.
- **Cleanup**: After using async APIs, call `khttp::Destroy()` before driver unload.
