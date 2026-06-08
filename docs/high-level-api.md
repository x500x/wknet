# 高层 API 开发文档（`KernelHttp::khttp`）

本文档面向使用 KernelHttp 高层接口编写驱动代码的开发者。所有接口都位于命名空间 `KernelHttp::khttp`（顶层别名 `::khttp`），头文件位于 `include/KernelHttp/khttp/`。所有接口都是 `noexcept`，绝大多数标注了 `_Must_inspect_result_`，必须按 NTSTATUS 返回值分支处理。

> 工程约束（来自 `AGENTS.md`）：内核驱动；传输层使用 WSK，密码学使用 CNG/BCrypt；C++ 受 `/kernel` 限制：无异常、无 RTTI，避免直接 `new/delete`。本 API 全部满足这些约束。

> **并发安全**：内部实现已对连接池、句柄释放、异步完成等关键路径加锁保护。异步路径使用独立的 Workspace 避免数据竞争。调用方仍需保证同一 `Request` 不被多个 `Send` 并发使用。

> **协议与 IRQL 边界**：同步 HTTP、WebSocket、TLS 和证书验证路径要求 `PASSIVE_LEVEL`。HTTP/1.1 请求体使用 `Content-Length`；用户设置请求 `Transfer-Encoding` 会返回 `STATUS_NOT_SUPPORTED`，暂不支持 chunked 上传或向调用方暴露 trailer。响应 `Transfer-Encoding` 支持 `chunked/gzip/deflate/compress` 链式解码，`br` 仅作为 `Content-Encoding` 支持；close-delimited 响应和 `101 Switching Protocols` 升级响应不会进入普通 HTTP 连接池。HTTP/2 不支持 server push、priority 或复杂多流调度。WebSocket 默认接收完整消息，不暴露接收分片回调，也不协商扩展。TLS ALPN 结果必须来自客户端 offer 列表；TLS1.2 只能在获得可验证版本协商证据后选择；证书错误、ALPN mismatch、网络超时或 record 解密失败都不是 TLS1.2-only 证据。证书主机为 IP literal 时只匹配 iPAddress SAN，不回退到 dNSName 或 CN。
> **证书策略**：当前不实现 OCSP/CRL 撤销检查；叶子证书默认硬性要求 ServerAuth EKU、KeyUsage digitalSignature 且不能是 CA；中间/根证书要求 BasicConstraints CA 和 KeyUsage keyCertSign。

## 1. 模块组成与依赖关系

| 头文件 | 主要内容 |
|---|---|
| `khttp/Types.h` | 句柄前向声明、枚举、配置/选项结构体、回调类型、默认值、`Default*Config()` 工厂函数 |
| `khttp/Session.h` | `SessionCreate` / `SessionClose` |
| `khttp/Request.h` | `RequestCreate` / `RequestRelease` 以及全部 `RequestSet*` 构造接口 |
| `khttp/Http.h` | 同步快捷函数（`Get/Post/Put/Patch/Delete/Head/Options`）与 `Send / SendEx` |
| `khttp/HttpAsync.h` | 异步入口（`GetAsync / PostAsync / SendAsync / SendAsyncEx`） |
| `khttp/AsyncOp.h` | 异步操作的等待、取消、查询、句柄获取与释放 |
| `khttp/Response.h` | 响应只读访问器 |
| `khttp/WebSocket.h` | WebSocket 同步与异步连接、收发、关闭 |

不透明句柄类型（`Session / Request / Response / AsyncOp / WebSocket`）只通过 API 操作，不要直接 `delete`。运行时表示由内部 `engine` 层提供，并通过 `khttp/Detail.h` 中的 `reinterpret_cast` 跨层桥接。

## 2. 资源生命周期与所有权

调用方负责在每个对象上配对调用创建/释放函数。

| 句柄 | 创建 | 释放 |
|---|---|---|
| `Session*` | `SessionCreate` | `SessionClose` |
| `Request*` | `RequestCreate` | `RequestRelease` |
| `Response*` | `Send / SendEx` 出参或 `AsyncGetResponse` | `ResponseRelease` |
| `AsyncOp*` | `*Async / *AsyncEx` 出参 | `AsyncRelease` |
| `WebSocket*` | `WsConnect / WsConnectEx` 出参或 `AsyncGetWebSocket` | `WsClose` |

调用规则：

- `RequestRelease`、`ResponseRelease`、`AsyncRelease`、`SessionClose`、`WsClose` 接受 `nullptr`，可以无条件调用。
- `Send` 失败时仍可能返回非空 `Response*`，调用方仍需 `ResponseRelease`（参见 `samples/HighLevelApiSamples.cpp` 的 `CaptureResponse`）。
- `AsyncOp` 拿到 `Response*` 或 `WebSocket*` 后，`AsyncRelease` 与对应资源的释放是独立的，都需要调用。
- `Request` 在被 `Send` 系列消费后，调用方仍需 `RequestRelease`；同一个 `Request` 不应被多个 `Send` 并发使用。

## 3. 字符串、缓冲区与回调约定

- 所有字符串都使用 `const char*` + `SIZE_T` 长度对，**不要求 null 结尾**；长度可由 `strlen` 之外的计算方式给出。
- 回调类型见 `khttp/Types.h`：
  - `HeaderCallback(context, name, nameLen, value, valueLen) -> NTSTATUS`
  - `BodyCallback(context, data, dataLen, finalChunk) -> NTSTATUS`
  - `CompletionCallback(context, status) -> void`
  - `WsMessageCallback(context, type, data, dataLen, finalFragment) -> NTSTATUS`
- 头/体回调返回非成功 NTSTATUS 会被视为失败，导致整个请求失败（参考样例中的 `HeaderCallback`、`BodyCallback`）。
- `OnBody` 在最后一次回调时 `finalChunk == true`；当请求被聚合发送时（见 `SendFlagAggregateWithCallbacks`），仍能依次产生分块回调。

## 4. Session：连接池与全局策略容器

```cpp
NTSTATUS SessionCreate(
    net::WskClient* wskClient,
    const SessionConfig* config,   // 可空，使用默认
    Session** out) noexcept;
void SessionClose(Session* session) noexcept;
```

`net::WskClient` 必须由调用方先 `Initialize()`，并保证在 `SessionClose` 之前一直存活。`SessionConfig`：

```cpp
struct SessionConfig final {
    PoolType ResponsePool      = PoolType::NonPaged; // 响应缓冲使用的池
    SIZE_T   RequestBufferBytes = DefaultRequestBufferBytes; // 请求行/头/体构造缓冲
    SIZE_T   MaxResponseBytes  = DefaultMaxResponseBytes;   // 0 表示不限制
    ULONG    PoolCapacity      = DefaultPoolCapacity;       // 8 个连接槽位
    ULONG    MaxConnsPerHost   = DefaultMaxConnsPerHost;    // 每主机 2
    ULONG    IdleTimeoutMs     = DefaultIdleTimeoutMs;      // 30000ms
    TlsConfig Tls = {};                                     // 见下
};
```

调用 `DefaultSessionConfig()` 获取一份默认值再按需修改即可（`samples/HighLevelApiSamples.cpp:1701-1707`）。会话级 TLS 在 `SessionConfig::Tls` 中提供，单个请求可通过 `RequestSetTls` 覆盖。

### TlsConfig（会话默认 / 请求覆盖）

```cpp
struct TlsConfig final {
    TlsVersion MinVersion        = TlsVersion::Tls12;
    TlsVersion MaxVersion        = TlsVersion::Tls13;
    CertPolicy Certificate       = CertPolicy::Verify;
    const tls::CertificateStore* Store = nullptr; // 自定义信任根/锁定
    const char* ServerName       = nullptr;       // 覆盖 SNI
    SIZE_T      ServerNameLength = 0;
    const char* Alpn             = nullptr;       // 例 "h2" / "http/1.1"
    SIZE_T      AlpnLength       = 0;
    ULONG       HandshakeTimeoutMs = DefaultTlsHandshakeTimeoutMs;
};
```

注意：`Store` 指向的 `CertificateStore` 由调用方拥有，必须在使用期间保持有效。`samples/ExternalTrustStore.{h,cpp}` 给出了基于外部信任锚 + leaf SPKI 锁定的初始化模板。

## 5. 一次同步请求的最短路径

```cpp
khttp::Session* session = nullptr;
NTSTATUS s = khttp::SessionCreate(&wskClient, nullptr, &session);

khttp::Response* resp = nullptr;
s = khttp::Get(session,
               "http://nghttp2.org/httpbin/get",
               sizeof("http://nghttp2.org/httpbin/get") - 1,
               &resp);

if (NT_SUCCESS(s)) {
    ULONG code = khttp::ResponseStatusCode(resp);
    const UCHAR* body = khttp::ResponseBody(resp);
    SIZE_T len = khttp::ResponseBodyLength(resp);
    // ... 使用响应
}

khttp::ResponseRelease(resp);
khttp::SessionClose(session);
```

URL 内嵌 scheme：`http://`、`https://`、`ws://`、`wss://`。HTTPS/WSS 自动启用 TLS（按会话 / 请求 TLS 配置）。

## 6. Request 构造（细粒度入口）

`Request` 是个写一次的请求构造器，构造完后传给 `Send / SendEx / SendAsync / SendAsyncEx` 消费。

| 方法 | 作用 |
|---|---|
| `RequestSetUrl` | 必填，设置完整 URL |
| `RequestSetMethod` | 默认 `Get`；用 `Method::Post / Put / Patch / Delete / Head / Options` |
| `RequestSetHeader` | 追加单个请求头；可重复调用 |
| `RequestSetBody` | 通用裸字节体（未指定 Content-Type） |
| `RequestSetTextBody` | 文本体；`contentType` 可空时默认 `text/plain; charset=utf-8` |
| `RequestSetJsonBody` | JSON 体；隐含 `application/json` |
| `RequestSetRawBody` | 自定义 Content-Type 的裸字节 |
| `RequestSetFormBody` | `application/x-www-form-urlencoded`，传入 `NameValuePair` 数组 |
| `RequestSetMultipartBody` | `multipart/form-data`，传入 `MultipartPart` 数组（字段、文件字节、文件路径） |
| `RequestSetFileBody` | 文件路径作为请求体（内核态走 `\SystemRoot\…` NT 路径） |
| `RequestClearBody` | 清除已设置的请求体 |
| `RequestSetTls` | 覆盖会话默认 TLS（含证书策略、ALPN、SNI、信任库） |
| `RequestSetConnPolicy` | `ReuseOrCreate`（默认池化复用）/ `ForceNew`（强制新连接）/ `NoPool`（既不复用也不进池） |
| `RequestSetAddressFamily` | `Any` / `Ipv4` / `Ipv6` |

`MultipartPart::Kind` 决定该段携带的字段：`Field`（`Name/Value`）、`FileBytes`（`Name/FileName/ContentType/Data/DataLength`）、`FilePath`（`Name/FileName/ContentType/FilePath/FilePathLength`）。

## 7. 同步发送：Send / SendEx

```cpp
NTSTATUS Send(Session*, Request*, Response** response);
NTSTATUS Send(Session*, Request*, const SendOptions* options, Response** response /*可空*/);
NTSTATUS SendEx(Session*, Request*, const SendOptions* options, Response** response /*可空*/);
```

- `SendOptions::MaxResponseBytes`：覆盖响应上限；`0` 表示不限制。`options == nullptr` 时同样不限制。
- `SendOptions::OnHeader / OnBody`：在解析过程中触发。要在使用回调的同时仍获得完整聚合响应，需要在 `Flags` 中加入 `SendFlagAggregateWithCallbacks`（参考 `RunSendWithOptions` 中的写法）。
- `SendEx` 与 `Send(带选项)` 当前对外语义等价，前者通常用于驱动选择 `ConnPolicy::ForceNew` 等更精细的策略组合（见样例对比）。
- `OnComplete / CompletionContext` 仅在异步路径上生效，同步发送时这两个字段被忽略。

## 8. 同步快捷函数

`khttp/Http.h` 提供等价于 `RequestCreate + RequestSetUrl + RequestSetMethod + Send` 的便捷形式：

```cpp
NTSTATUS Get/Post/Put/Patch/Delete/Head/Options(
    Session*, const char* url, SIZE_T urlLen,
    [const UCHAR* body, SIZE_T bodyLen,]   // POST/PUT/PATCH 才有
    Response** out);
```

它们使用会话默认 TLS / 连接策略 / 地址族；如需自定义，转走 `Request*` + `Send`。

## 9. 异步发送

`khttp/HttpAsync.h` 给出三组入口：

```cpp
NTSTATUS GetAsync (Session*, url, urlLen, AsyncOp** op);
NTSTATUS PostAsync(Session*, url, urlLen, body, bodyLen, AsyncOp** op);
NTSTATUS SendAsync(Session*, Request*, AsyncOp** op);
NTSTATUS SendAsync(Session*, Request*, const SendOptions* options, AsyncOp** op);
NTSTATUS SendAsyncEx(Session*, Request*, const SendOptions* options, AsyncOp** op);
```

`AsyncOp` 上可用的方法（`khttp/AsyncOp.h`）：

```cpp
NTSTATUS AsyncWait(AsyncOp*, ULONG timeoutMs);     // 阻塞等待完成
NTSTATUS AsyncCancel(AsyncOp*);                    // 请求取消
NTSTATUS AsyncGetStatus(const AsyncOp*);           // 当前累计状态
bool     AsyncIsCompleted(const AsyncOp*);
bool     AsyncIsCanceled(const AsyncOp*);
NTSTATUS AsyncGetResponse(AsyncOp*, Response** out);
NTSTATUS AsyncGetWebSocket(AsyncOp*, WebSocket** out);
void     AsyncRelease(AsyncOp*);
```

典型流程（参考 `CompleteHttpAsync`）：

```cpp
khttp::AsyncOp* op = nullptr;
NTSTATUS s = khttp::SendAsyncEx(session, request, &options, &op);
if (NT_SUCCESS(s)) {
    s = khttp::AsyncWait(op, 60000);
    if (NT_SUCCESS(s)) {
        khttp::Response* resp = nullptr;
        s = khttp::AsyncGetResponse(op, &resp);
        // 使用 resp ...
        khttp::ResponseRelease(resp);
    }
}
khttp::AsyncRelease(op);
```

`SendOptions::OnComplete` 在异步分支上会在最终状态确定时调用一次（成功或失败），可用于跨线程通知。`AsyncCancel` 不一定能及时打断已经在飞的 IO，使用方应继续 `AsyncWait` 或基于 `AsyncIsCanceled` 判断。

**并发保护**：
- 异步操作使用原子标志确保只完成一次
- `AsyncRelease` 使用原子操作防止重复释放
- 异步路径使用独立的 Workspace，与同步路径隔离

## 10. Response 只读访问

```cpp
ULONG       ResponseStatusCode(const Response*);     // 0 表示无响应
const UCHAR* ResponseBody(const Response*);          // 可空
SIZE_T      ResponseBodyLength(const Response*);
SIZE_T      ResponseHeaderCount(const Response*);
NTSTATUS    ResponseGetHeader(const Response*, name, nameLen, &value, &valueLen);
NTSTATUS    ResponseGetHeaderAt(const Response*, index, &name,&nameLen, &value,&valueLen);
void        ResponseRelease(Response*);
```

`ResponseGetHeader` 按名称查询（大小写不敏感）；找不到时返回 `STATUS_NOT_FOUND`。`ResponseGetHeaderAt` 用 0 起索引枚举所有响应头。

响应体会先按 HTTP/1.1 `Transfer-Encoding` 链解码（`chunked / gzip / deflate / compress`），再按 `Content-Encoding` 解码（`gzip / deflate / br / identity`）；当响应头里看到 `Content-Length` 与解码后长度不一致时，应以 `ResponseBodyLength()` 为准。

## 11. WebSocket

连接：

```cpp
NTSTATUS WsConnect       (Session*, const char* url, SIZE_T urlLen, WebSocket**);
NTSTATUS WsConnect       (Session*, const WsConnectConfig*, WebSocket**);
NTSTATUS WsConnectEx     (Session*, const WsConnectConfig*, WebSocket**);
NTSTATUS WsConnectAsync  (Session*, const char* url, SIZE_T urlLen, AsyncOp**);
NTSTATUS WsConnectAsync  (Session*, const WsConnectConfig*, AsyncOp**);
NTSTATUS WsConnectAsyncEx(Session*, const WsConnectConfig*, AsyncOp**);
```

`WsConnectConfig`：

```cpp
struct WsConnectConfig final {
    const char* Url;            SIZE_T UrlLength;
    const char* Subprotocol;    SIZE_T SubprotocolLength;  // 可空
    TlsConfig   Tls = {};                                  // 仅 wss:// 生效
    AddressFamily Family = AddressFamily::Any;
    SIZE_T MaxMessageBytes = DefaultMaxResponseBytes;
    bool   AutoReplyPing = true;                           // 自动回复 Ping
};
```

收发与关闭：

```cpp
NTSTATUS WsSendText  (WebSocket*, const char*, SIZE_T);
NTSTATUS WsSendTextEx(WebSocket*, const char*, SIZE_T, const WsSendOptions*);
NTSTATUS WsSendBinary  (WebSocket*, const UCHAR*, SIZE_T);
NTSTATUS WsSendBinaryEx(WebSocket*, const UCHAR*, SIZE_T, const WsSendOptions*);
NTSTATUS WsReceive   (WebSocket*, WsMessage* out);
NTSTATUS WsReceiveEx (WebSocket*, const WsReceiveOptions*, WsMessage* out /*可空*/);
NTSTATUS WsClose     (WebSocket*);
```

- `WsSendOptions::FinalFragment = false` 用于发送分片消息（默认 `true`）。
- `WsReceiveOptions::AutoAllocate = true` 时由实现分配存储并写入 `WsMessage::Data`，调用方在 `WsClose` 后不再持有该指针；`AutoAllocate = false` 时需要传入 `OnMessage` 回调消费数据。
- `WsMessage::Type` 取自 `WsMsgType { Text, Binary, Ping, Close }`。
- 接收路径默认返回完整消息；服务端分片消息会被聚合，Ping 控制帧默认自动回复。
- `AutoReplyPing = false` 时，收到 Ping 会以 `WsMsgType::Ping` 控制事件返回，不会自动发送 Pong。
- 发送二进制 echo 服务端时，注意服务端类型差异：示例代码区分了 `WebSocketSecureEchoUrl` 与 `WebSocketBinaryEchoUrl`。

异步连接通过 `AsyncGetWebSocket(op, &ws)` 获取连接成功后的句柄；连接失败则该函数返回 NTSTATUS，`ws` 保持为空。

## 12. 枚举与默认值速查

`Method`：`Get / Post / Put / Patch / Delete / Head / Options`
`PoolType`：`NonPaged / Paged`（响应缓冲所属池）
`TlsVersion`：`Tls12 (0x0303) / Tls13 (0x0304)`
`CertPolicy`：`Verify / NoVerify`
`AddressFamily`：`Any / Ipv4 / Ipv6`
`ConnPolicy`：`ReuseOrCreate / ForceNew / NoPool`
`WsMsgType`：`Text / Binary / Ping / Close`
`BodyPartKind`：`Field / FileBytes / FilePath`
`SendFlags`：`SendFlagNone (0)`、`SendFlagAggregateWithCallbacks (0x1)`

```cpp
constexpr SIZE_T DefaultRequestBufferBytes      = 16 * 1024;
constexpr SIZE_T DefaultMaxResponseBytes        = 1024 * 1024;
constexpr ULONG  DefaultPoolCapacity            = 8;
constexpr ULONG  DefaultMaxConnsPerHost         = 2;
constexpr ULONG  DefaultIdleTimeoutMs           = 30000;
constexpr ULONG  DefaultTlsHandshakeTimeoutMs   = TlsHandshakeReceiveTimeoutMilliseconds; // 120000
```

`DefaultTlsConfig() / DefaultSessionConfig() / DefaultSendOptions() / DefaultWsConnectConfig()` 直接返回上述默认结构，开发中建议先取默认再改差异字段，避免遗漏新字段。

## 13. 错误处理建议

- 区分协议层失败（HTTP 状态码）与传输 / TLS / WSK 失败（NTSTATUS）。`Send*` 返回 `NT_SUCCESS` 时仍可能拿到 4xx/5xx 响应。
- 与 TLS / 证书相关的常见 NTSTATUS：`STATUS_TRUST_FAILURE`、`STATUS_INVALID_SIGNATURE`、`STATUS_NOT_SUPPORTED`（如 ALPN 不匹配）。
- 与连接 / 池相关：`STATUS_DEVICE_NOT_CONNECTED`、`STATUS_CONNECTION_DISCONNECTED`、`STATUS_IO_TIMEOUT`。
- 异步路径上 `AsyncWait` 的 `STATUS_TIMEOUT` / `STATUS_PENDING` 表示超时未完成；`STATUS_CANCELLED` 表示被 `AsyncCancel` 打断。

## 14. 可运行示例索引

`src/KernelHttpTest/samples/HighLevelApiSamples.cpp` 中按场景列出了：会话创建、HTTP 同步快捷函数、Request 构造、各类请求体、Send 选项与回调、响应头读取、各种异步入口、`AsyncCancel`、HTTPS（含 ALPN 切换）、WebSocket 同步与异步连接、文本 / 二进制 / Ex / 回调接收等。可以直接对照阅读，每个样例都打印请求与响应详情，便于调试。

`src/KernelHttpTest/samples/ExternalTrustStore.{h,cpp}` 给出了如何构造会话级证书 `Store`（`tls::CertificateTrustAnchor` + `tls::CertificatePin`）的模板，并被 `RunHighLevelApiSamples` 在创建 Session 时使用。

## 15. 相关文档

- [底层 API 文档](low-level-api.md)：底层 API 的详细使用说明，适合需要精细控制、性能优化或特殊定制的场景
- [API 概述](api-overview.md)：高层 API 和底层 API 的对比和选择指南
- [项目说明](../README.md)：项目概述和构建说明
- [AGENTS.md](../AGENTS.md)：工程约束和开发规范
