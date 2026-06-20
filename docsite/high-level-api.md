# 高层 API / High-Level API

本页是 `khttp` / `kws` 高层 API 的结构体与函数参考。HTTP 在命名空间 `khttp`，WebSocket 在命名空间 `kws`。高层 HTTP API 隐藏 WSK 运行时：调用方创建 `Session` 后即可发送请求，不向高层 `SessionCreate` 传入 `net::WskClient`。

[English](#english) | 简体中文

---

## 简体中文

### 阅读约定

- 所有高层公开句柄都是不透明堆句柄：`Session`、`Request`、`Response`、`AsyncOp`、`Headers`、`Body`、`kws::WebSocket`。
- 不要在内核调用方栈上声明高层公开对象。使用 `Create` 函数创建，用匹配的 `Close` / `Release` 函数释放。
- `SendOptions` / `AsyncOptions` 也是堆创建公开字段结构体，通过 `SendOptionsCreate` / `AsyncOptionsCreate` 获取指针后修改字段。
- 所有高层 HTTP/WS 调用要求 `PASSIVE_LEVEL`。
- 返回值统一为 `NTSTATUS`，用 `NT_SUCCESS(status)` 判断成功。标记 `_Must_inspect_result_` 的返回值必须检查。
- `Release` / `Close` 函数接受 `nullptr`，可在失败路径无条件调用。
- `MaxResponseBytes = 0` 表示不设置调用方响应体聚合上限；非零值才表示调用方主动限制 buffered response 大小。
- JSON body helper 只设置 `Content-Type: application/json; charset=utf-8` 并透传字节，不解析、不校验、不构造 JSON。

### 头文件总览

| 头文件 | 内容 |
|--------|------|
| `KernelHttp/KernelHttp.h` | 总入口，包含高层 HTTP、WebSocket、底层 engine 与基础类型 |
| `KernelHttp/khttp/Types.h` | 枚举、配置结构体、回调类型、公开常量 |
| `KernelHttp/khttp/Session.h` | `SessionCreate` / `SessionClose` |
| `KernelHttp/khttp/Request.h` | `RequestCreate` / `RequestRelease` |
| `KernelHttp/khttp/Headers.h` | `Headers` 句柄创建、添加、释放 |
| `KernelHttp/khttp/Body.h` | `Body` 句柄创建、模式、trailer、释放 |
| `KernelHttp/khttp/Options.h` | `SendOptions` / `AsyncOptions` 创建与释放 |
| `KernelHttp/khttp/Http.h` | 同步 HTTP 发送与动词 helper |
| `KernelHttp/khttp/HttpAsync.h` | 异步 HTTP 发送与动词 helper |
| `KernelHttp/khttp/AsyncOp.h` | 异步操作等待、取消、取结果、释放 |
| `KernelHttp/khttp/Response.h` | 响应只读访问与释放 |
| `KernelHttp/khttp/Lifecycle.h` | `Destroy` 异步收尾入口 |
| `KernelHttp/kws/WebSocket.h` | 高层 WebSocket 连接、收发、关闭 |

## 类型与结构体总览

### 不透明句柄

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

| 枚举 | 说明 |
|------|------|
| `Method` | HTTP 方法。`Connect` 主要供特殊场景或底层能力使用 |
| `PoolType` | 响应缓冲池类型。内核路径当前要求 `NonPaged`；`Paged` 是保留 ABI 值 |
| `TlsVersion` | TLS 最小/最大版本 |
| `CertPolicy` | 证书校验策略 |
| `AddressFamily` | DNS/连接地址族选择 |
| `ConnPolicy` | 单次发送连接池策略 |
| `BodyPartKind` | multipart part 类型 |
| `RequestBodyMode` | 请求体 framing：`ContentLength` 或 `Chunked` |

### 发送标志

```cpp
enum SendFlags : ULONG {
    SendFlagNone = 0,
    SendFlagAggregateWithCallbacks = 0x00000001,
    SendFlagDisableAutoRedirect = 0x00000002
};
```

| 标志 | 说明 |
|------|------|
| `SendFlagNone` | 默认行为 |
| `SendFlagAggregateWithCallbacks` | 调用 header/body 回调，同时保留聚合响应 |
| `SendFlagDisableAutoRedirect` | 禁用自动重定向，直接返回 3xx 响应 |

### 回调类型

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
| `HeaderCallback` | 收到响应头时逐个调用 | 返回失败会中止发送并传播该状态 |
| `BodyCallback` | 收到响应体分块时调用 | 返回失败会中止发送并传播该状态 |
| `CompletionCallback` | 异步操作完成时调用 | `void`，不影响操作结果 |

`context` 来自 `SendOptions::CallbackContext` 或 `AsyncOptions::CompletionContext`。

## 结构体字段参考

### `TlsConfig`

功能：描述会话默认 TLS 策略，或通过 `SendOptions` 为单次发送覆盖 TLS 策略。

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
| `MinVersion` | `Tls12` | 允许的最低 TLS 版本 |
| `MaxVersion` | `Tls13` | 允许的最高 TLS 版本 |
| `Certificate` | `Verify` | 是否校验证书链、主机名、策略 |
| `Store` | `nullptr` | 自定义证书存储；`nullptr` 使用库默认信任来源 |
| `ServerName` / `ServerNameLength` | `nullptr` / `0` | SNI 与证书主机名；为空时从 URL host 推导 |
| `Alpn` / `AlpnLength` | `nullptr` / `0` | 显式 ALPN；为空时按 `PreferHttp2` 自动提供 |
| `PreferHttp2` | `true` | 自动 ALPN 时优先提供 HTTP/2 |
| `Policy` | `{}` | TLS 安全策略，详见 TLS 文档 |
| `ClientCredential` | `nullptr` | mTLS 客户端凭据 |
| `HandshakeTimeoutMs` | `DefaultTlsHandshakeTimeoutMs` | TLS 握手超时 |

### `ProxyConfig`

功能：配置会话级 HTTPS CONNECT 代理。

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
| `Enabled` | `false` | 是否启用代理 |
| `Address` | `{}` | 代理 socket 地址 |
| `Authority` / `AuthorityLength` | `nullptr` / `0` | CONNECT authority，例如 `proxy.example:8080` |
| `AuthHeader` / `AuthHeaderLength` | `nullptr` / `0` | 可选 `Proxy-Authorization` 值，只发给代理 |

### `SessionConfig`

功能：创建 `Session` 时的会话级配置。

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
| `ResponsePool` | `NonPaged` | 响应缓冲池类型；内核路径当前要求 `NonPaged` |
| `RequestBufferBytes` | `16 KiB` | HTTP/1.1 请求行、请求头和请求体构造缓冲 |
| `MaxResponseBytes` | `0` | 0 表示不设置调用方响应体聚合上限 |
| `PoolCapacity` | `8` | 连接池总容量 |
| `MaxConnsPerHost` | `2` | 单主机最大连接数 |
| `IdleTimeoutMs` | `30000` | 空闲连接回收时间 |
| `Tls` | `DefaultTlsConfig()` | 会话默认 TLS 配置 |
| `Proxy` | disabled | HTTPS CONNECT 代理配置 |

### `SendOptions`

功能：单次同步发送的可选行为。必须通过 `SendOptionsCreate` 创建，在指针上修改字段。

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
| `MaxResponseBytes` | `0` | 0 表示本次发送不设置调用方响应体聚合上限；非零值表示本次主动限制 |
| `Flags` | `SendFlagNone` | 发送标志 |
| `MaxRedirects` | `0` | 0 表示使用 engine 默认重定向上限；非零值覆盖 |
| `OnHeader` | `nullptr` | 响应头回调 |
| `OnBody` | `nullptr` | 响应体分块回调 |
| `CallbackContext` | `nullptr` | 传给 `OnHeader` / `OnBody` 的上下文 |
| `Tls` | `DefaultTlsConfig()` | 单次 TLS 配置 |
| `HasTlsOverride` | `false` | `true` 时使用 `Tls` 覆盖会话 TLS 配置 |
| `ConnectionPolicy` | `ReuseOrCreate` | 本次发送连接策略 |
| `Family` | `Any` | 本次发送地址族 |

### `AsyncOptions`

功能：单次异步 HTTP 发送的可选行为。

```cpp
struct AsyncOptions final {
    SendOptions Send;
    CompletionCallback OnComplete;
    void* CompletionContext;
};
```

| 字段 | 默认 | 说明 |
|------|------|------|
| `Send` | `DefaultSendOptions()` | 异步发送使用的同步发送选项 |
| `OnComplete` | `nullptr` | 异步完成回调 |
| `CompletionContext` | `nullptr` | 传给 `OnComplete` 的上下文 |

### `NameValuePair`

功能：`BodyCreateForm` 的 form-url-encoded 字段描述。

```cpp
struct NameValuePair final {
    const char* Name;
    SIZE_T NameLength;
    const char* Value;
    SIZE_T ValueLength;
};
```

`BodyCreateForm` 会复制 `NameValuePair` 描述数组，但字段指向的 name/value 字节按引用使用，必须保持到同步发送返回或异步发送完成/取消。

### `MultipartPart`

功能：`BodyCreateMultipart` 的 multipart/form-data part 描述。

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
| `Name` / `NameLength` | form 字段名 |
| `Value` / `ValueLength` | `Field` 的字段值 |
| `Data` / `DataLength` | `FileBytes` 的文件内容字节 |
| `FilePath` / `FilePathLength` | `FilePath` 的文件路径 |
| `FileName` / `FileNameLength` | multipart filename |
| `ContentType` / `ContentTypeLength` | part Content-Type；禁止 CR/LF 注入 |

`BodyCreateMultipart` 会复制 part 描述数组，但 part 内指针按引用使用，必须保持到发送结束。

### `kws` WebSocket 结构体

#### `kws::Header`

```cpp
struct Header final {
    const char* Name;
    SIZE_T NameLength;
    const char* Value;
    SIZE_T ValueLength;
};
```

用于 `ConnectConfig.Headers`。可放 opening handshake 额外头，例如 `Origin`、`Authorization`、`Cookie`。库受控头如 `Host`、`Connection`、`Upgrade`、`Sec-WebSocket-*` 会被拒绝。

#### `kws::ConnectConfig`

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
| `Url` / `UrlLength` | `nullptr` / `0` | `ws://` 或 `wss://` URL |
| `Subprotocol` / `SubprotocolLength` | `nullptr` / `0` | 可选 `Sec-WebSocket-Protocol` |
| `Headers` / `HeaderCount` | `nullptr` / `0` | opening handshake 额外头 |
| `Tls` | `DefaultTlsConfig()` | `wss` 使用的 TLS 配置 |
| `Family` | `Any` | 地址族 |
| `MaxMessageBytes` | `DefaultMaxWebSocketMessageBytes` | 单消息默认上限 |
| `AutoReplyPing` | `true` | 收到 ping 时自动 pong |
| `AllowWebSocketOverHttp2` | `false` | 显式 opt-in RFC 8441 WebSocket over HTTP/2 |

#### `kws::SendOptions`

```cpp
struct SendOptions final {
    bool FinalFragment;
};
```

`FinalFragment=false` 用于发送分片消息的非最后帧，后续用 `SendContinuation` / `SendContinuationEx` 续发。

#### `kws::ReceiveOptions`

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
| `MaxMessageBytes` | `0` | 0 表示使用连接默认消息上限 |
| `AutoAllocate` | `true` | 是否由库自动分配消息缓冲 |
| `OnMessage` | `nullptr` | 收到消息/分片时的回调 |
| `CallbackContext` | `nullptr` | 传给 `OnMessage` 的上下文 |

#### `kws::Message`

```cpp
struct Message final {
    MsgType Type;
    const UCHAR* Data;
    SIZE_T DataLength;
    bool Final;
    bool FinalFragment;
};
```

`Data` 指向库内部缓冲，下一次 receive 或 close 前有效。

## 函数总览

### 默认配置函数

| 函数 | 功能 |
|------|------|
| `DefaultTlsConfig` | 返回默认 TLS 配置值 |
| `DefaultSessionConfig` | 返回默认会话配置值 |
| `DefaultSendOptions` | 返回默认发送选项值；正式使用优先选择 `SendOptionsCreate` |
| `kws::DefaultConnectConfig` | 返回默认 WebSocket 连接配置值 |

### HTTP 生命周期与句柄

| 函数 | 功能 |
|------|------|
| `SessionCreate` | 创建高层会话，内部初始化隐藏 WSK runtime |
| `SessionClose` | 关闭会话，释放隐藏 WSK runtime |
| `RequestCreate` | 创建绑定到会话的发送句柄 |
| `RequestRelease` | 释放发送句柄 |
| `Destroy` | 等待/收尾库级异步运行时 |

### Headers / Body / Options

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

| 函数族 | 功能 |
|--------|------|
| `AsyncSend` / `AsyncSendEx` | 通用异步发送入口 |
| `AsyncGet*` / `AsyncPost*` / `AsyncPut*` / `AsyncPatch*` / `AsyncDelete*` / `AsyncHead*` | 异步动词 helper |
| `AsyncOptionsRequest*` | 异步 HTTP OPTIONS helper |
| `AsyncWait` | 等待异步操作完成 |
| `AsyncCancel` | 请求取消异步操作 |
| `AsyncGetStatus` | 读取异步操作状态 |
| `AsyncIsCompleted` | 判断是否完成 |
| `AsyncIsCanceled` | 判断是否已取消 |
| `AsyncGetResponse` | 取 HTTP 异步响应 |
| `AsyncRelease` | 释放异步操作 |

### Response

| 函数 | 功能 |
|------|------|
| `ResponseStatusCode` | 读取 HTTP 状态码 |
| `ResponseBody` / `ResponseBodyLength` | 读取响应体指针与长度 |
| `ResponseHeaderCount` / `ResponseTrailerCount` | 读取响应头/trailer 数量 |
| `ResponseGetHeader` / `ResponseGetHeaderAt` | 按名称或索引读取响应头 |
| `ResponseGetTrailer` / `ResponseGetTrailerAt` | 按名称或索引读取 trailer |
| `ResponseRelease` | 释放响应句柄 |

### WebSocket

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

#### `DefaultTlsConfig`

功能：返回默认 TLS 配置值。

```cpp
TlsConfig DefaultTlsConfig() noexcept;
```

参数：无。

返回值：`TlsConfig` 值，字段为默认 TLS 配置。

#### `DefaultSessionConfig`

功能：返回默认会话配置值。

```cpp
SessionConfig DefaultSessionConfig() noexcept;
```

参数：无。

返回值：`SessionConfig` 值。

#### `DefaultSendOptions`

功能：返回默认发送选项值。正式高层调用推荐使用 `SendOptionsCreate` 创建堆对象后修改字段；该函数保留用于内部和兼容场景。

```cpp
SendOptions DefaultSendOptions() noexcept;
```

参数：无。

返回值：`SendOptions` 值。

## 生命周期函数

### `SessionCreate`

功能：创建高层 HTTP/WS 会话。会话内部初始化隐藏 WSK runtime，并创建 engine session、连接池、workspace、TLS provider cache 等资源。

```cpp
NTSTATUS SessionCreate(Session** session) noexcept;
NTSTATUS SessionCreate(const SessionConfig* config, Session** session) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `config` | in | 是 | 会话配置；`nullptr` 表示使用 `DefaultSessionConfig()` |
| `session` | out | 否 | 成功时接收 `Session*`；失败时置为 `nullptr` |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 创建成功 |
| `STATUS_INVALID_PARAMETER` | `session == nullptr` 或配置非法 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配会话、WSK runtime 或内部资源失败 |
| 其他失败状态 | WSK 初始化或 engine session 创建失败 |

注意事项：

- 成功后必须调用 `SessionClose`。
- 高层 `SessionCreate` 不接收 `net::WskClient*`。
- `SessionClose` 前仍可释放由该会话创建的 `Request`，但不要在会话关闭后继续使用旧 `Request` 发送。

### `SessionClose`

功能：关闭并释放会话。

```cpp
void SessionClose(Session* session) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `session` | in | 是 | 要关闭的会话；`nullptr` 直接返回 |

返回值：无。

注意事项：关闭会话会关闭内部 engine session 并关闭隐藏 WSK runtime。使用过异步 API 时，驱动卸载前还必须调用 `Destroy()`。

### `RequestCreate`

功能：创建绑定到 `Session` 的发送句柄。

```cpp
NTSTATUS RequestCreate(Session* session, Request** out) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `session` | in | 否 | 父会话 |
| `out` | out | 否 | 成功时接收 `Request*` |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 创建成功 |
| `STATUS_INVALID_PARAMETER` | 参数为空、会话无效或会话已关闭 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败 |

注意事项：`Request` 不再是 builder。method、URL、headers、body、options 都在 `Send*` / `AsyncSend*` 调用中传入。

### `RequestRelease`

功能：释放 `Request` 发送句柄。

```cpp
void RequestRelease(Request* request) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `request` | in | 是 | 要释放的请求句柄 |

返回值：无。

### `Destroy`

功能：库级异步收尾入口。

```cpp
void Destroy() noexcept;
```

参数：无。

返回值：无。

注意事项：

- 用过 HTTP 或 WebSocket 异步 API 后，驱动卸载前必须调用。
- 同步-only 路径可以无条件调用。

## Headers 函数

### `HeadersCreate`

功能：创建空请求头集合。

```cpp
NTSTATUS HeadersCreate(Headers** headers) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `headers` | out | 否 | 成功时接收 `Headers*`；失败时置为 `nullptr` |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 创建成功 |
| `STATUS_INVALID_PARAMETER` | `headers == nullptr` |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败 |

### `HeadersAdd` / `HeadersAddEx`

功能：向 `Headers` 添加或覆盖一个请求头。按大小写不敏感字段名查重；同名字段会覆盖旧值。

```cpp
NTSTATUS HeadersAdd(Headers* headers, const char* name, const char* value) noexcept;

NTSTATUS HeadersAddEx(
    Headers* headers,
    const char* name,
    SIZE_T nameLength,
    const char* value,
    SIZE_T valueLength) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `headers` | inout | 否 | `HeadersCreate` 返回的句柄 |
| `name` | in | 否 | header 名称；`HeadersAdd` 要求 NUL 结尾 |
| `nameLength` | in | 否 | header 名称字节长度，不含 NUL |
| `value` | in | 否 | header 值；`HeadersAdd` 要求 NUL 结尾 |
| `valueLength` | in | 否 | header 值字节长度，不含 NUL |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 添加或覆盖成功 |
| `STATUS_INVALID_PARAMETER` | 句柄无效、名称非法、值含 CR/LF、或尝试添加库受控 header |
| `STATUS_INSUFFICIENT_RESOURCES` | 超过请求头数量上限或复制 name/value 失败 |

所有权与限制：

- name/value 总是复制到堆，调用返回后源缓冲可修改或释放。
- 禁止 CR/LF 注入。
- `Host`、`Content-Length`、连接 framing 相关字段等库受控 header 由库合成或拒绝。

### `HeadersRelease`

功能：释放请求头集合及其复制的 name/value。

```cpp
void HeadersRelease(Headers* headers) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `headers` | in | 是 | 要释放的头集合 |

返回值：无。

## Body 函数

### Body 引用与拷贝规则

| 函数族 | 数据所有权 | 生命周期要求 |
|--------|------------|--------------|
| `BodyCreateBytes` / `BodyCreateText` / `BodyCreateJson` | 引用调用方字节 | 同步发送返回前有效；异步发送完成或取消前有效 |
| `BodyCreateBytesCopy` / `BodyCreateTextCopy` / `BodyCreateJsonCopy` | 创建时复制字节到堆 | 创建成功后源缓冲可释放 |
| `BodyCreateForm` | 复制 pair 描述数组，pair 内指针按引用使用 | pair 指向的 name/value 字节需保持到发送结束 |
| `BodyCreateMultipart` | 复制 part 描述数组，part 内指针按引用使用 | part 指向的字节需保持到发送结束 |
| `BodyCreateFile` / `BodyCreateFileEx` | 复制文件路径和 Content-Type | 文件内容在发送时读取 |

### `BodyCreateBytes` / `BodyCreateBytesEx`

功能：创建引用调用方内存的原始字节 body，不设置 Content-Type。

```cpp
NTSTATUS BodyCreateBytes(const UCHAR* data, SIZE_T dataLength, Body** body) noexcept;
NTSTATUS BodyCreateBytesEx(const UCHAR* data, SIZE_T dataLength, Body** body) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `data` | in | `dataLength == 0` 时可空 | 请求体字节 |
| `dataLength` | in | 否 | 字节长度 |
| `body` | out | 否 | 成功时接收 `Body*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`。

### `BodyCreateBytesCopy` / `BodyCreateBytesCopyEx`

功能：创建原始字节 body，并在创建时复制调用方字节。

```cpp
NTSTATUS BodyCreateBytesCopy(const UCHAR* data, SIZE_T dataLength, Body** body) noexcept;
NTSTATUS BodyCreateBytesCopyEx(const UCHAR* data, SIZE_T dataLength, Body** body) noexcept;
```

参数和返回值同 `BodyCreateBytes`。创建成功后，`data` 可立即释放或修改。

### `BodyCreateText` / `BodyCreateTextEx`

功能：创建引用调用方文本字节的 text body，可设置 Content-Type。

```cpp
NTSTATUS BodyCreateText(
    const char* text,
    SIZE_T textLength,
    const char* contentType,
    Body** body) noexcept;

NTSTATUS BodyCreateTextEx(
    const char* text,
    SIZE_T textLength,
    const char* contentType,
    SIZE_T contentTypeLength,
    Body** body) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `text` | in | `textLength == 0` 时可空 | 文本字节，不要求 NUL 结尾 |
| `textLength` | in | 否 | 文本字节长度 |
| `contentType` | in | 是 | Content-Type；`BodyCreateText` 要求 NUL 结尾 |
| `contentTypeLength` | in | 否 | Content-Type 字节长度，不含 NUL |
| `body` | out | 否 | 成功时接收 `Body*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`。

### `BodyCreateTextCopy` / `BodyCreateTextCopyEx`

功能：创建 text body，并复制文本和 Content-Type。

```cpp
NTSTATUS BodyCreateTextCopy(
    const char* text,
    SIZE_T textLength,
    const char* contentType,
    Body** body) noexcept;

NTSTATUS BodyCreateTextCopyEx(
    const char* text,
    SIZE_T textLength,
    const char* contentType,
    SIZE_T contentTypeLength,
    Body** body) noexcept;
```

参数和返回值同 `BodyCreateText`。创建成功后，`text` 与 `contentType` 源缓冲可立即释放或修改。

### `BodyCreateJson` / `BodyCreateJsonEx`

功能：创建引用调用方 JSON 字节的 body，并设置 `Content-Type: application/json; charset=utf-8`。

```cpp
NTSTATUS BodyCreateJson(const char* json, SIZE_T jsonLength, Body** body) noexcept;
NTSTATUS BodyCreateJsonEx(const char* json, SIZE_T jsonLength, Body** body) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `json` | in | `jsonLength == 0` 时可空 | JSON 字节；库不解析、不校验 |
| `jsonLength` | in | 否 | JSON 字节长度 |
| `body` | out | 否 | 成功时接收 `Body*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`。

### `BodyCreateJsonCopy` / `BodyCreateJsonCopyEx`

功能：创建 JSON body，并复制 JSON 字节。

```cpp
NTSTATUS BodyCreateJsonCopy(const char* json, SIZE_T jsonLength, Body** body) noexcept;
NTSTATUS BodyCreateJsonCopyEx(const char* json, SIZE_T jsonLength, Body** body) noexcept;
```

参数和返回值同 `BodyCreateJson`。创建成功后，`json` 源缓冲可立即释放或修改。

### `BodyCreateForm`

功能：创建 `application/x-www-form-urlencoded` body。

```cpp
NTSTATUS BodyCreateForm(
    const NameValuePair* pairs,
    SIZE_T pairCount,
    Body** body) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `pairs` | in | 否 | form 字段数组 |
| `pairCount` | in | 否 | 字段数量，必须大于 0 且不超过每请求字段上限 |
| `body` | out | 否 | 成功时接收 `Body*` |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 创建成功 |
| `STATUS_INVALID_PARAMETER` | `pairs` 为空、数量非法或字段非法 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败 |

### `BodyCreateMultipart`

功能：创建 `multipart/form-data` body。

```cpp
NTSTATUS BodyCreateMultipart(
    const MultipartPart* parts,
    SIZE_T partCount,
    Body** body) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `parts` | in | 否 | multipart part 数组 |
| `partCount` | in | 否 | part 数量，必须大于 0 且不超过每请求字段上限 |
| `body` | out | 否 | 成功时接收 `Body*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`。

### `BodyCreateFile` / `BodyCreateFileEx`

功能：创建文件请求体。库复制文件路径和 Content-Type，发送时读取文件内容。

```cpp
NTSTATUS BodyCreateFile(
    const char* filePath,
    const char* contentType,
    Body** body) noexcept;

NTSTATUS BodyCreateFileEx(
    const char* filePath,
    SIZE_T filePathLength,
    const char* contentType,
    SIZE_T contentTypeLength,
    Body** body) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `filePath` | in | 否 | 文件路径；`BodyCreateFile` 要求 NUL 结尾 |
| `filePathLength` | in | 否 | 文件路径字节长度 |
| `contentType` | in | 是 | Content-Type；为空则不显式设置 |
| `contentTypeLength` | in | 否 | Content-Type 字节长度 |
| `body` | out | 否 | 成功时接收 `Body*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`。

### `BodySetMode`

功能：设置请求体 framing 模式。

```cpp
NTSTATUS BodySetMode(Body* body, RequestBodyMode mode) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `body` | inout | 否 | body 句柄 |
| `mode` | in | 否 | `ContentLength` 或 `Chunked` |

返回值：`STATUS_SUCCESS` 或 `STATUS_INVALID_PARAMETER`。

### `BodyAddTrailer` / `BodyAddTrailerEx`

功能：为 chunked 请求体添加 trailer 字段。

```cpp
NTSTATUS BodyAddTrailer(Body* body, const char* name, const char* value) noexcept;

NTSTATUS BodyAddTrailerEx(
    Body* body,
    const char* name,
    SIZE_T nameLength,
    const char* value,
    SIZE_T valueLength) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `body` | inout | 否 | body 句柄 |
| `name` | in | 否 | trailer 名称 |
| `nameLength` | in | 否 | trailer 名称字节长度 |
| `value` | in | 否 | trailer 值 |
| `valueLength` | in | 否 | trailer 值字节长度 |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 添加成功 |
| `STATUS_INVALID_PARAMETER` | 参数非法、名称非法、值含 CR/LF |
| `STATUS_NOT_SUPPORTED` | trailer 字段被禁止，如 `Content-Length`、`Transfer-Encoding`、`Host`、认证或 cookie 相关字段 |
| `STATUS_INSUFFICIENT_RESOURCES` | 超过数量上限或复制失败 |

注意事项：trailer 只在 `BodySetMode(body, RequestBodyMode::Chunked)` 后发送。

### `BodyRelease`

功能：释放 body 句柄及其拥有的堆内存。

```cpp
void BodyRelease(Body* body) noexcept;
```

参数：`body` 可为 `nullptr`。

返回值：无。

## Options 函数

### `SendOptionsCreate`

功能：创建堆上的 `SendOptions` 并填入默认值。

```cpp
NTSTATUS SendOptionsCreate(SendOptions** options) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `options` | out | 否 | 成功时接收 `SendOptions*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`。

### `SendOptionsRelease`

功能：释放 `SendOptions`。

```cpp
void SendOptionsRelease(SendOptions* options) noexcept;
```

参数：`options` 可为 `nullptr`。

返回值：无。

### `AsyncOptionsCreate`

功能：创建堆上的 `AsyncOptions` 并填入默认值。

```cpp
NTSTATUS AsyncOptionsCreate(AsyncOptions** options) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `options` | out | 否 | 成功时接收 `AsyncOptions*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_INSUFFICIENT_RESOURCES`。

### `AsyncOptionsRelease`

功能：释放 `AsyncOptions`。

```cpp
void AsyncOptionsRelease(AsyncOptions* options) noexcept;
```

参数：`options` 可为 `nullptr`。

返回值：无。

## 同步 HTTP 函数

### `Send` / `SendEx`

功能：通用同步 HTTP 发送。`Session*` 和 `Request*` 都可作为 send handle，行为等价。

```cpp
NTSTATUS Send(
    Session* session,
    Method method,
    const char* url,
    const Headers* headers,
    const Body* body,
    const SendOptions* options,
    Response** response) noexcept;

NTSTATUS SendEx(
    Session* session,
    Method method,
    const char* url,
    SIZE_T urlLength,
    const Headers* headers,
    const Body* body,
    const SendOptions* options,
    Response** response) noexcept;

NTSTATUS Send(
    Request* request,
    Method method,
    const char* url,
    const Headers* headers,
    const Body* body,
    const SendOptions* options,
    Response** response) noexcept;

NTSTATUS SendEx(
    Request* request,
    Method method,
    const char* url,
    SIZE_T urlLength,
    const Headers* headers,
    const Body* body,
    const SendOptions* options,
    Response** response) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `session` | in | 否 | 会话 send handle |
| `request` | in | 否 | 请求 send handle |
| `method` | in | 否 | HTTP 方法 |
| `url` | in | 否 | HTTP/HTTPS URL；`Send` 要求 NUL 结尾 |
| `urlLength` | in | 否 | URL 字节长度，不含 NUL |
| `headers` | in | 是 | 调用方请求头集合 |
| `body` | in | 是 | 请求体；`nullptr` 表示无 body 或空 body |
| `options` | in | 是 | 单次发送选项；`nullptr` 表示默认行为 |
| `response` | out | 否 | 成功时接收 `Response*`；失败时可能为 `nullptr` |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 请求成功发送并收到响应 |
| `STATUS_INVALID_PARAMETER` | 句柄、method、URL、输出指针或对象状态非法 |
| `STATUS_INVALID_DEVICE_REQUEST` | 非 `PASSIVE_LEVEL` 调用 |
| `STATUS_BUFFER_TOO_SMALL` | 响应超过非零 `MaxResponseBytes` 或内部缓冲不足 |
| `STATUS_IO_TIMEOUT` | WSK/TLS/HTTP 操作超时 |
| `STATUS_CONNECTION_DISCONNECTED` | 连接断开 |
| `STATUS_TRUST_FAILURE` | TLS 证书校验失败 |
| `STATUS_INVALID_NETWORK_RESPONSE` | 响应违反协议 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败、连接池配额不足或队列资源不足 |
| 其他 `NTSTATUS` | 传输、TLS、解析或回调返回的失败状态 |

header 合成与覆盖：

- 库先构造协议必需/default header，再应用调用方 `headers`。
- 调用方允许覆盖可覆盖默认 header。
- 库受控 header 如 `Host`、`Content-Length`、连接 framing 字段由库合成或拒绝。

### 同步动词 helper

功能：按函数名选择 HTTP 方法并调用通用 `Send` / `SendEx` 路径。调用方不需要手动传 `Method`，适合最常见的 GET、POST、PUT、PATCH、DELETE、HEAD、OPTIONS 请求。

动词与语义：

| 函数族 | HTTP 方法 | 请求体 | 典型用途 |
|--------|-----------|--------|----------|
| `Get` / `GetEx` | `GET` | 无 | 获取资源 |
| `Post` / `PostEx` | `POST` | 可选 | 创建资源、提交表单或 JSON 字节 |
| `Put` / `PutEx` | `PUT` | 可选 | 整体替换资源 |
| `Patch` / `PatchEx` | `PATCH` | 可选 | 局部修改资源 |
| `Delete` / `DeleteEx` | `DELETE` | 无 | 删除资源 |
| `Head` / `HeadEx` | `HEAD` | 无 | 只取响应头 |
| `Options` / `OptionsEx` | `OPTIONS` | 无 | 查询服务端能力 |

`Session*` 重载签名：

```cpp
NTSTATUS Get(Session* session, const char* url, Response** response) noexcept;
NTSTATUS GetEx(Session* session, const char* url, SIZE_T urlLength,
               const Headers* headers, const SendOptions* options,
               Response** response) noexcept;
NTSTATUS Get(Session* session, const char* url, SIZE_T urlLength,
             Response** response) noexcept;

NTSTATUS Post(Session* session, const char* url, const Body* body, Response** response) noexcept;
NTSTATUS PostEx(Session* session, const char* url, SIZE_T urlLength,
                const Headers* headers, const Body* body,
                const SendOptions* options, Response** response) noexcept;
NTSTATUS Post(Session* session, const char* url, SIZE_T urlLength,
              const UCHAR* body, SIZE_T bodyLength, Response** response) noexcept;

NTSTATUS Put(Session* session, const char* url, const Body* body, Response** response) noexcept;
NTSTATUS PutEx(Session* session, const char* url, SIZE_T urlLength,
               const Headers* headers, const Body* body,
               const SendOptions* options, Response** response) noexcept;
NTSTATUS Put(Session* session, const char* url, SIZE_T urlLength,
             const UCHAR* body, SIZE_T bodyLength, Response** response) noexcept;

NTSTATUS Patch(Session* session, const char* url, const Body* body, Response** response) noexcept;
NTSTATUS PatchEx(Session* session, const char* url, SIZE_T urlLength,
                 const Headers* headers, const Body* body,
                 const SendOptions* options, Response** response) noexcept;
NTSTATUS Patch(Session* session, const char* url, SIZE_T urlLength,
               const UCHAR* body, SIZE_T bodyLength, Response** response) noexcept;

NTSTATUS Delete(Session* session, const char* url, Response** response) noexcept;
NTSTATUS DeleteEx(Session* session, const char* url, SIZE_T urlLength,
                  const Headers* headers, const SendOptions* options,
                  Response** response) noexcept;
NTSTATUS Delete(Session* session, const char* url, SIZE_T urlLength,
                Response** response) noexcept;

NTSTATUS Head(Session* session, const char* url, Response** response) noexcept;
NTSTATUS HeadEx(Session* session, const char* url, SIZE_T urlLength,
                const Headers* headers, const SendOptions* options,
                Response** response) noexcept;
NTSTATUS Head(Session* session, const char* url, SIZE_T urlLength,
              Response** response) noexcept;

NTSTATUS Options(Session* session, const char* url, Response** response) noexcept;
NTSTATUS OptionsEx(Session* session, const char* url, SIZE_T urlLength,
                   const Headers* headers, const SendOptions* options,
                   Response** response) noexcept;
NTSTATUS Options(Session* session, const char* url, SIZE_T urlLength,
                 Response** response) noexcept;
```

`Request*` send handle 重载签名：

```cpp
NTSTATUS Get(Request* request, const char* url, Response** response) noexcept;
NTSTATUS GetEx(Request* request, const char* url, SIZE_T urlLength,
               const Headers* headers, const SendOptions* options,
               Response** response) noexcept;

NTSTATUS Post(Request* request, const char* url, const Body* body, Response** response) noexcept;
NTSTATUS PostEx(Request* request, const char* url, SIZE_T urlLength,
                const Headers* headers, const Body* body,
                const SendOptions* options, Response** response) noexcept;

NTSTATUS Put(Request* request, const char* url, const Body* body, Response** response) noexcept;
NTSTATUS PutEx(Request* request, const char* url, SIZE_T urlLength,
               const Headers* headers, const Body* body,
               const SendOptions* options, Response** response) noexcept;

NTSTATUS Patch(Request* request, const char* url, const Body* body, Response** response) noexcept;
NTSTATUS PatchEx(Request* request, const char* url, SIZE_T urlLength,
                 const Headers* headers, const Body* body,
                 const SendOptions* options, Response** response) noexcept;

NTSTATUS Delete(Request* request, const char* url, Response** response) noexcept;
NTSTATUS DeleteEx(Request* request, const char* url, SIZE_T urlLength,
                  const Headers* headers, const SendOptions* options,
                  Response** response) noexcept;

NTSTATUS Head(Request* request, const char* url, Response** response) noexcept;
NTSTATUS HeadEx(Request* request, const char* url, SIZE_T urlLength,
                const Headers* headers, const SendOptions* options,
                Response** response) noexcept;

NTSTATUS Options(Request* request, const char* url, Response** response) noexcept;
NTSTATUS OptionsEx(Request* request, const char* url, SIZE_T urlLength,
                   const Headers* headers, const SendOptions* options,
                   Response** response) noexcept;
```

参数：

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `session` | in | 否 | 会话句柄；用于 `Session*` 重载 |
| `request` | in | 否 | 请求发送句柄；用于 `Request*` 重载 |
| `url` | in | 否 | 请求 URL。非 `Ex` 重载按 NUL 结尾字符串计算长度 |
| `urlLength` | in | 否 | URL 字节长度，不包含额外 NUL；仅 `Ex` 和显式长度便捷重载使用 |
| `headers` | in | 是 | 请求头集合；为空时只使用库合成 header |
| `body` | in | 是 | `Post` / `Put` / `Patch` 的请求体；无 body 时传 `nullptr` |
| `bodyLength` | in | 否 | 原始字节 body 长度；仅 `Session*` 的 `Post` / `Put` / `Patch` 字节便捷重载使用 |
| `options` | in | 是 | 同步发送选项；为空时使用默认发送选项 |
| `response` | out | 否 | 成功时接收 `Response*`，调用方用 `ResponseRelease` 释放 |

返回值：与 `Send` / `SendEx` 一致。`STATUS_SUCCESS` 表示收到并构造响应；`STATUS_INVALID_PARAMETER` 表示句柄、URL、输出指针等非法；其他失败状态来自 DNS、连接、TLS、HTTP 解析、重定向、回调或内存分配路径。

注意事项：

- `Get`、`Delete`、`Head`、`Options` 没有 `Body*` 参数；需要带 body 的非典型请求请使用通用 `Send` / `SendEx`。
- `Post`、`Put`、`Patch` 的 `Body*` 重载不会复制 body 句柄本身；body 的引用/拷贝语义由 `BodyCreate*` 函数决定。
- `Session*` 的原始字节便捷重载会创建调用期引用 body；`body` 必须在调用返回前保持有效。
- `Head` 请求通常不返回响应体；仍然通过 `Response*` 读取状态码和响应头。

## 异步 HTTP 函数

### `AsyncSend` / `AsyncSendEx`

功能：通用异步 HTTP 发送。函数返回后操作进入异步运行时，结果通过 `AsyncWait` + `AsyncGetResponse` 获取。

```cpp
NTSTATUS AsyncSend(
    Session* session,
    Method method,
    const char* url,
    const Headers* headers,
    const Body* body,
    const AsyncOptions* options,
    AsyncOp** operation) noexcept;

NTSTATUS AsyncSendEx(
    Session* session,
    Method method,
    const char* url,
    SIZE_T urlLength,
    const Headers* headers,
    const Body* body,
    const AsyncOptions* options,
    AsyncOp** operation) noexcept;

NTSTATUS AsyncSend(
    Request* request,
    Method method,
    const char* url,
    const Headers* headers,
    const Body* body,
    const AsyncOptions* options,
    AsyncOp** operation) noexcept;

NTSTATUS AsyncSendEx(
    Request* request,
    Method method,
    const char* url,
    SIZE_T urlLength,
    const Headers* headers,
    const Body* body,
    const AsyncOptions* options,
    AsyncOp** operation) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `session` / `request` | in | 否 | send handle |
| `method` | in | 否 | HTTP 方法 |
| `url` / `urlLength` | in | 否 | URL 与长度 |
| `headers` | in | 是 | 请求头集合 |
| `body` | in | 是 | 请求体 |
| `options` | in | 是 | 异步发送选项 |
| `operation` | out | 否 | 成功时接收 `AsyncOp*` |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 异步操作创建并排队成功 |
| `STATUS_INVALID_PARAMETER` | 参数或句柄非法 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败或异步队列满 |
| 其他失败状态 | 发送准备阶段失败 |

生命周期：

- 引用型 `Body` 的源缓冲必须保持到异步操作完成或取消。
- 完成后调用 `AsyncGetResponse` 取响应，再调用 `ResponseRelease`。
- 最后调用 `AsyncRelease`。

### 异步动词 helper

功能：按函数名选择 HTTP 方法并调用通用 `AsyncSend` / `AsyncSendEx` 路径。函数只创建并排队异步操作，响应需要后续通过 `AsyncWait` + `AsyncGetResponse` 获取。

动词与语义：

| 函数族 | HTTP 方法 | 请求体 | 结果获取 |
|--------|-----------|--------|----------|
| `AsyncGet` / `AsyncGetEx` | `GET` | 无 | `AsyncGetResponse` |
| `AsyncPost` / `AsyncPostEx` | `POST` | 可选 | `AsyncGetResponse` |
| `AsyncPut` / `AsyncPutEx` | `PUT` | 可选 | `AsyncGetResponse` |
| `AsyncPatch` / `AsyncPatchEx` | `PATCH` | 可选 | `AsyncGetResponse` |
| `AsyncDelete` / `AsyncDeleteEx` | `DELETE` | 无 | `AsyncGetResponse` |
| `AsyncHead` / `AsyncHeadEx` | `HEAD` | 无 | `AsyncGetResponse` |
| `AsyncOptionsRequest` / `AsyncOptionsRequestEx` | `OPTIONS` | 无 | `AsyncGetResponse` |

`Session*` 重载签名：

```cpp
NTSTATUS AsyncGet(Session* session, const char* url, AsyncOp** operation) noexcept;
NTSTATUS AsyncGetEx(Session* session, const char* url, SIZE_T urlLength,
                    const Headers* headers, const AsyncOptions* options,
                    AsyncOp** operation) noexcept;

NTSTATUS AsyncPost(Session* session, const char* url, const Body* body, AsyncOp** operation) noexcept;
NTSTATUS AsyncPostEx(Session* session, const char* url, SIZE_T urlLength,
                     const Headers* headers, const Body* body,
                     const AsyncOptions* options, AsyncOp** operation) noexcept;

NTSTATUS AsyncPut(Session* session, const char* url, const Body* body, AsyncOp** operation) noexcept;
NTSTATUS AsyncPutEx(Session* session, const char* url, SIZE_T urlLength,
                    const Headers* headers, const Body* body,
                    const AsyncOptions* options, AsyncOp** operation) noexcept;

NTSTATUS AsyncPatch(Session* session, const char* url, const Body* body, AsyncOp** operation) noexcept;
NTSTATUS AsyncPatchEx(Session* session, const char* url, SIZE_T urlLength,
                      const Headers* headers, const Body* body,
                      const AsyncOptions* options, AsyncOp** operation) noexcept;

NTSTATUS AsyncDelete(Session* session, const char* url, AsyncOp** operation) noexcept;
NTSTATUS AsyncDeleteEx(Session* session, const char* url, SIZE_T urlLength,
                       const Headers* headers, const AsyncOptions* options,
                       AsyncOp** operation) noexcept;

NTSTATUS AsyncHead(Session* session, const char* url, AsyncOp** operation) noexcept;
NTSTATUS AsyncHeadEx(Session* session, const char* url, SIZE_T urlLength,
                     const Headers* headers, const AsyncOptions* options,
                     AsyncOp** operation) noexcept;

NTSTATUS AsyncOptionsRequest(Session* session, const char* url, AsyncOp** operation) noexcept;
NTSTATUS AsyncOptionsRequestEx(Session* session, const char* url, SIZE_T urlLength,
                               const Headers* headers, const AsyncOptions* options,
                               AsyncOp** operation) noexcept;
```

`Request*` send handle 重载签名：

```cpp
NTSTATUS AsyncGet(Request* request, const char* url, AsyncOp** operation) noexcept;
NTSTATUS AsyncGetEx(Request* request, const char* url, SIZE_T urlLength,
                    const Headers* headers, const AsyncOptions* options,
                    AsyncOp** operation) noexcept;

NTSTATUS AsyncPost(Request* request, const char* url, const Body* body, AsyncOp** operation) noexcept;
NTSTATUS AsyncPostEx(Request* request, const char* url, SIZE_T urlLength,
                     const Headers* headers, const Body* body,
                     const AsyncOptions* options, AsyncOp** operation) noexcept;

NTSTATUS AsyncPut(Request* request, const char* url, const Body* body, AsyncOp** operation) noexcept;
NTSTATUS AsyncPutEx(Request* request, const char* url, SIZE_T urlLength,
                    const Headers* headers, const Body* body,
                    const AsyncOptions* options, AsyncOp** operation) noexcept;

NTSTATUS AsyncPatch(Request* request, const char* url, const Body* body, AsyncOp** operation) noexcept;
NTSTATUS AsyncPatchEx(Request* request, const char* url, SIZE_T urlLength,
                      const Headers* headers, const Body* body,
                      const AsyncOptions* options, AsyncOp** operation) noexcept;

NTSTATUS AsyncDelete(Request* request, const char* url, AsyncOp** operation) noexcept;
NTSTATUS AsyncDeleteEx(Request* request, const char* url, SIZE_T urlLength,
                       const Headers* headers, const AsyncOptions* options,
                       AsyncOp** operation) noexcept;

NTSTATUS AsyncHead(Request* request, const char* url, AsyncOp** operation) noexcept;
NTSTATUS AsyncHeadEx(Request* request, const char* url, SIZE_T urlLength,
                     const Headers* headers, const AsyncOptions* options,
                     AsyncOp** operation) noexcept;

NTSTATUS AsyncOptionsRequest(Request* request, const char* url, AsyncOp** operation) noexcept;
NTSTATUS AsyncOptionsRequestEx(Request* request, const char* url, SIZE_T urlLength,
                               const Headers* headers, const AsyncOptions* options,
                               AsyncOp** operation) noexcept;
```

参数：

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `session` | in | 否 | 会话句柄；用于 `Session*` 重载 |
| `request` | in | 否 | 请求发送句柄；用于 `Request*` 重载 |
| `url` | in | 否 | 请求 URL。非 `Ex` 重载按 NUL 结尾字符串计算长度 |
| `urlLength` | in | 否 | URL 字节长度，不包含额外 NUL；仅 `Ex` 重载使用 |
| `headers` | in | 是 | 请求头集合 |
| `body` | in | 是 | `AsyncPost` / `AsyncPut` / `AsyncPatch` 的请求体 |
| `options` | in | 是 | 异步发送选项；为空时使用默认异步发送行为 |
| `operation` | out | 否 | 成功时接收 `AsyncOp*`，调用方最终用 `AsyncRelease` 释放 |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 异步操作创建并排队成功 |
| `STATUS_INVALID_PARAMETER` | 句柄、URL、输出指针等非法 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败或异步资源不足 |
| 其他失败状态 | 请求准备或排队阶段失败 |

注意事项：

- `AsyncOptionsRequest` / `AsyncOptionsRequestEx` 是 HTTP OPTIONS 动词 helper；没有命名为 `AsyncOptions` 是为了避免和 `AsyncOptions` 类型名冲突。
- `AsyncGet`、`AsyncDelete`、`AsyncHead`、`AsyncOptionsRequest` 没有 `Body*` 参数；需要非典型带 body 的请求请使用通用 `AsyncSend` / `AsyncSendEx`。
- 引用型 `Body` 的源缓冲必须保持到异步操作完成或取消。
- 成功创建操作后，调用方应 `AsyncWait` 等待终态，调用 `AsyncGetResponse` 取得响应，再分别释放 `Response` 和 `AsyncOp`。

## 异步操作函数

### `AsyncWait`

功能：等待异步操作完成。

```cpp
NTSTATUS AsyncWait(AsyncOp* operation, ULONG timeoutMs) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `operation` | in | 否 | 异步操作句柄 |
| `timeoutMs` | in | 否 | 等待超时毫秒；通常可传 `0xffffffffUL` 表示长期等待 |

返回值：完成状态、`STATUS_TIMEOUT`、`STATUS_INVALID_PARAMETER` 或等待过程中的失败状态。

### `AsyncCancel`

功能：请求取消异步操作。

```cpp
NTSTATUS AsyncCancel(AsyncOp* operation) noexcept;
```

参数：`operation` 不可为空。

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER` 或取消过程失败状态。

注意事项：取消是协作式的。取消后仍应调用 `AsyncWait` 等待终态，再释放操作。

### `AsyncGetStatus`

功能：读取异步操作当前/最终状态。

```cpp
NTSTATUS AsyncGetStatus(const AsyncOp* operation) noexcept;
```

参数：`operation` 可为空；空或无效句柄返回失败状态。

返回值：当前 `NTSTATUS`。

### `AsyncIsCompleted`

功能：判断异步操作是否完成。

```cpp
bool AsyncIsCompleted(const AsyncOp* operation) noexcept;
```

返回值：完成返回 `true`，未完成或句柄为空返回 `false`。

### `AsyncIsCanceled`

功能：判断异步操作是否被请求取消。

```cpp
bool AsyncIsCanceled(const AsyncOp* operation) noexcept;
```

返回值：已取消返回 `true`，否则返回 `false`。

### `AsyncGetResponse`

功能：从已完成 HTTP 异步操作中取出响应。

```cpp
NTSTATUS AsyncGetResponse(AsyncOp* operation, Response** response) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `operation` | in | 否 | HTTP send 异步操作 |
| `response` | out | 否 | 成功时接收 `Response*` |

返回值：

| 返回值 | 含义 |
|--------|------|
| `STATUS_SUCCESS` | 成功取出响应 |
| `STATUS_INVALID_PARAMETER` | 参数或操作类型非法 |
| `STATUS_PENDING` / 等待相关状态 | 操作尚未完成 |
| 操作最终失败状态 | 发送失败或被取消 |

### `AsyncRelease`

功能：释放异步操作句柄。

```cpp
void AsyncRelease(AsyncOp* operation) noexcept;
```

参数：`operation` 可为 `nullptr`。

返回值：无。

## Response 函数

### `ResponseStatusCode`

功能：读取 HTTP 状态码。

```cpp
ULONG ResponseStatusCode(const Response* response) noexcept;
```

参数：`response` 可为空。

返回值：状态码；空或无效句柄返回 `0`。

### `ResponseBody` / `ResponseBodyLength`

功能：读取聚合响应体指针与长度。

```cpp
const UCHAR* ResponseBody(const Response* response) noexcept;
SIZE_T ResponseBodyLength(const Response* response) noexcept;
```

参数：`response` 可为空。

返回值：`ResponseBody` 返回库内部缓冲指针，`ResponseBodyLength` 返回字节长度。指针在 `ResponseRelease` 前有效。

### `ResponseHeaderCount` / `ResponseTrailerCount`

功能：读取响应头或 trailer 数量。

```cpp
SIZE_T ResponseHeaderCount(const Response* response) noexcept;
SIZE_T ResponseTrailerCount(const Response* response) noexcept;
```

参数：`response` 可为空。

返回值：数量；空或无效句柄返回 `0`。

### `ResponseGetHeader`

功能：按名称读取响应头。名称匹配大小写不敏感。

```cpp
NTSTATUS ResponseGetHeader(
    const Response* response,
    const char* name,
    SIZE_T nameLength,
    const char** value,
    SIZE_T* valueLength) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `response` | in | 否 | 响应句柄 |
| `name` | in | 否 | header 名称 |
| `nameLength` | in | 否 | 名称字节长度 |
| `value` | out | 否 | 成功时接收 header 值指针 |
| `valueLength` | out | 否 | 成功时接收值长度 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_NOT_FOUND`。

### `ResponseGetHeaderAt`

功能：按索引枚举响应头。

```cpp
NTSTATUS ResponseGetHeaderAt(
    const Response* response,
    SIZE_T index,
    const char** name,
    SIZE_T* nameLength,
    const char** value,
    SIZE_T* valueLength) noexcept;
```

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_NOT_FOUND`。

### `ResponseGetTrailer` / `ResponseGetTrailerAt`

功能：按名称或索引读取响应 trailer。

```cpp
NTSTATUS ResponseGetTrailer(
    const Response* response,
    const char* name,
    SIZE_T nameLength,
    const char** value,
    SIZE_T* valueLength) noexcept;

NTSTATUS ResponseGetTrailerAt(
    const Response* response,
    SIZE_T index,
    const char** name,
    SIZE_T* nameLength,
    const char** value,
    SIZE_T* valueLength) noexcept;
```

参数与返回值同 header 读取函数。

### `ResponseRelease`

功能：释放响应句柄及其内部缓冲。

```cpp
void ResponseRelease(Response* response) noexcept;
```

参数：`response` 可为 `nullptr`。

返回值：无。

## WebSocket 函数

### `kws::DefaultConnectConfig`

功能：返回默认 WebSocket 连接配置。

```cpp
kws::ConnectConfig DefaultConnectConfig() noexcept;
```

参数：无。

返回值：`ConnectConfig` 值。

### `kws::Connect` / `kws::ConnectEx`

功能：同步建立 WebSocket 连接。

```cpp
NTSTATUS Connect(
    khttp::Session* session,
    const char* url,
    SIZE_T urlLength,
    WebSocket** websocket) noexcept;

NTSTATUS Connect(
    khttp::Session* session,
    const ConnectConfig* config,
    WebSocket** websocket) noexcept;

NTSTATUS ConnectEx(
    khttp::Session* session,
    const ConnectConfig* config,
    WebSocket** websocket) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `session` | in | 否 | 高层会话 |
| `url` / `urlLength` | in | 否 | `ws://` 或 `wss://` URL |
| `config` | in | 否 | 连接配置 |
| `websocket` | out | 否 | 成功时接收 `WebSocket*` |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_NOT_SUPPORTED`、网络/TLS/HTTP 握手失败状态。

### `kws::ConnectAsync` / `kws::ConnectAsyncEx`

功能：异步建立 WebSocket 连接。

```cpp
NTSTATUS ConnectAsync(
    khttp::Session* session,
    const char* url,
    SIZE_T urlLength,
    khttp::AsyncOp** operation) noexcept;

NTSTATUS ConnectAsync(
    khttp::Session* session,
    const ConnectConfig* config,
    khttp::AsyncOp** operation) noexcept;

NTSTATUS ConnectAsyncEx(
    khttp::Session* session,
    const ConnectConfig* config,
    khttp::AsyncOp** operation) noexcept;
```

参数与 `Connect` 类似，但输出为 `AsyncOp**`。成功后用 `AsyncWait` 等待，再用 `kws::AsyncGetWebSocket` 取连接。

### `kws::AsyncGetWebSocket`

功能：从已完成 WebSocket connect 异步操作中取出 `WebSocket` 句柄。

```cpp
NTSTATUS AsyncGetWebSocket(khttp::AsyncOp* operation, WebSocket** websocket) noexcept;
```

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_PENDING` 或连接最终失败状态。

### WebSocket 发送函数

功能：发送文本、二进制、续帧、ping、pong。

```cpp
NTSTATUS SendText(WebSocket* websocket, const char* text, SIZE_T textLength) noexcept;
NTSTATUS SendTextEx(WebSocket* websocket, const char* text, SIZE_T textLength,
                    const SendOptions* options) noexcept;

NTSTATUS SendBinary(WebSocket* websocket, const UCHAR* data, SIZE_T dataLength) noexcept;
NTSTATUS SendBinaryEx(WebSocket* websocket, const UCHAR* data, SIZE_T dataLength,
                      const SendOptions* options) noexcept;

NTSTATUS SendContinuation(WebSocket* websocket, const UCHAR* data, SIZE_T dataLength) noexcept;
NTSTATUS SendContinuationEx(WebSocket* websocket, const UCHAR* data, SIZE_T dataLength,
                            const SendOptions* options) noexcept;

NTSTATUS SendPing(WebSocket* websocket, const UCHAR* payload, SIZE_T payloadLength) noexcept;
NTSTATUS SendPong(WebSocket* websocket, const UCHAR* payload, SIZE_T payloadLength) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `websocket` | in | 否 | WebSocket 句柄 |
| `text` | in | 否 | 文本字节 |
| `data` | in | 否 | 二进制或续帧字节 |
| `payload` | in | `payloadLength == 0` 时可空 | ping/pong payload |
| `options` | in | 是 | `FinalFragment` 选项 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、连接关闭/断开/超时等传输失败状态。

### `kws::Receive` / `kws::ReceiveEx`

功能：接收 WebSocket 消息。

```cpp
NTSTATUS Receive(WebSocket* websocket, Message* message) noexcept;

NTSTATUS ReceiveEx(
    WebSocket* websocket,
    const ReceiveOptions* options,
    Message* message) noexcept;
```

| 参数 | 方向 | 是否可空 | 说明 |
|------|------|----------|------|
| `websocket` | in | 否 | WebSocket 句柄 |
| `options` | in | 是 | 接收选项 |
| `message` | out | `ReceiveEx` 中可空 | 成功时接收消息视图 |

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_BUFFER_TOO_SMALL`、连接关闭/断开/超时等状态。

### `kws::Close` / `kws::CloseEx`

功能：关闭 WebSocket。

```cpp
NTSTATUS Close(WebSocket* websocket) noexcept;

NTSTATUS CloseEx(
    WebSocket* websocket,
    USHORT statusCode,
    const UCHAR* reason,
    SIZE_T reasonLength) noexcept;
```

参数：`websocket` 可为空；`reason` 在 `reasonLength == 0` 时可为空。

返回值：关闭成功或传输失败状态。

注意事项：不要在同一 `WebSocket` 上并发执行 `Close` 和新的发送/接收。

### `kws::SelectedSubprotocol`

功能：读取服务端选择的 WebSocket 子协议。

```cpp
NTSTATUS SelectedSubprotocol(
    WebSocket* websocket,
    const char** subprotocol,
    SIZE_T* subprotocolLength) noexcept;
```

返回值：`STATUS_SUCCESS`、`STATUS_INVALID_PARAMETER`、`STATUS_NOT_FOUND`。

## 完整示例

### 同步 POST JSON

```cpp
khttp::Session* session = nullptr;
khttp::Headers* headers = nullptr;
khttp::Body* body = nullptr;
khttp::SendOptions* options = nullptr;
khttp::Response* response = nullptr;

NTSTATUS status = khttp::SessionCreate(&session);
if (NT_SUCCESS(status)) {
    status = khttp::HeadersCreate(&headers);
}
if (NT_SUCCESS(status)) {
    status = khttp::HeadersAdd(headers, "User-Agent", "KernelHttp/1.0");
}
if (NT_SUCCESS(status)) {
    status = khttp::BodyCreateJsonCopy("{\"hello\":\"world\"}", 17, &body);
}
if (NT_SUCCESS(status)) {
    status = khttp::SendOptionsCreate(&options);
}
if (NT_SUCCESS(status)) {
    options->MaxResponseBytes = 0;
    status = khttp::PostEx(
        session,
        "https://api.example.com/v1",
        sizeof("https://api.example.com/v1") - 1,
        headers,
        body,
        options,
        &response);
}

if (NT_SUCCESS(status)) {
    ULONG code = khttp::ResponseStatusCode(response);
    const UCHAR* bytes = khttp::ResponseBody(response);
    SIZE_T bytesLength = khttp::ResponseBodyLength(response);
    UNREFERENCED_PARAMETER(code);
    UNREFERENCED_PARAMETER(bytes);
    UNREFERENCED_PARAMETER(bytesLength);
}

khttp::ResponseRelease(response);
khttp::SendOptionsRelease(options);
khttp::BodyRelease(body);
khttp::HeadersRelease(headers);
khttp::SessionClose(session);
```

### 异步 GET

```cpp
khttp::AsyncOp* op = nullptr;
khttp::Response* response = nullptr;

NTSTATUS status = khttp::AsyncGetEx(
    session,
    url,
    urlLength,
    nullptr,
    nullptr,
    &op);

if (NT_SUCCESS(status)) {
    status = khttp::AsyncWait(op, 30000);
}
if (NT_SUCCESS(status)) {
    status = khttp::AsyncGetResponse(op, &response);
}

khttp::ResponseRelease(response);
khttp::AsyncRelease(op);
```

## English

This page is the detailed high-level API reference for `khttp` and `kws`. The Chinese section above is the source of truth for signatures, parameters, return values, ownership, and lifetime rules.

Key points:

- High-level `SessionCreate` hides WSK. Use `SessionCreate(&session)` or `SessionCreate(&config, &session)`.
- Public high-level objects are heap handles. Create them with API functions and release them with matching `Close` / `Release` functions.
- `Session*` and `Request*` are equivalent send handles. `Request` is not a builder.
- HTTP sends pass `method`, URL, optional `Headers`, optional `Body`, optional options, and an output handle per call.
- `HeadersAdd*` copies name/value data. Non-copy body helpers reference caller memory until sync send returns or async send completes/cancels.
- JSON helpers do not parse or build JSON; they only set `application/json; charset=utf-8` and pass bytes through.
- Async HTTP entry points use the `Async` prefix. HTTP OPTIONS is `AsyncOptionsRequest` / `AsyncOptionsRequestEx` to avoid the C++ name collision with `AsyncOptions`.
- After using async APIs, call `khttp::Destroy()` before driver unload.
