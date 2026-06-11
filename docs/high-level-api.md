# 高层 API 开发文档（`KernelHttp::khttp`）

本文档面向使用 KernelHttp 高层接口编写驱动代码的开发者。所有接口都位于命名空间 `KernelHttp::khttp`（顶层别名 `::khttp`），头文件位于 `include/KernelHttp/khttp/`。所有接口都是 `noexcept`，绝大多数标注了 `_Must_inspect_result_`，必须按 NTSTATUS 返回值分支处理。

> 工程约束（来自 `AGENTS.md`）：内核驱动；传输层使用 WSK，密码学使用 CNG/BCrypt；C++ 受 `/kernel` 限制：无异常、无 RTTI，避免直接 `new/delete`。本 API 全部满足这些约束。

> **并发安全**：内部实现已对连接池、句柄释放、异步完成等关键路径加锁保护。异步路径使用独立的 Workspace 避免数据竞争。调用方仍需保证同一 `Request` 不被多个 `Send` 并发使用。

> **协议与 IRQL 边界**：同步 HTTP、WebSocket、TLS 和证书验证路径要求 `PASSIVE_LEVEL`。HTTP/1.1 请求体默认使用 `Content-Length`，也可通过 `RequestSetBodyMode(Chunked)` 显式发送 chunked 请求体；用户设置请求 `Transfer-Encoding`、`TE`、`Trailer` 会返回 `STATUS_NOT_SUPPORTED`，带请求体的 `Expect: 100-continue` 暂不支持，request trailer 暂不支持。响应 `Transfer-Encoding` 支持 `chunked/gzip/deflate/compress` 链式解码且不接受 transfer-coding 参数；`br` 仅作为 `Content-Encoding` 支持；chunked trailer 会被校验、消费，并可通过 trailer 只读 API 在响应完成后访问。close-delimited 响应和 `101 Switching Protocols` 升级响应不会进入普通 HTTP 连接池。HTTP/2 TLS 主路径要求 ALPN `h2`；h2c prior knowledge / Upgrade 仅保留为显式 legacy/test path，不作为现代内核主路径能力宣传。HTTP/2 不支持 RFC 8441 WebSocket over HTTP/2、server push、priority 或完整多流调度，收到禁用的 `PUSH_PROMISE` 视为协议错误，缺失 SETTINGS ACK 会以 `SETTINGS_TIMEOUT` 关闭，收到 GOAWAY 会终止当前单请求连接语义。WebSocket 主路径是 HTTP/1.1 Upgrade，默认接收完整消息，不暴露接收分片回调、不协商扩展，也不提供自定义 opening handshake headers。TLS ALPN 结果必须来自客户端 offer 列表；TLS1.2 只能在获得可验证版本协商证据后选择；证书错误、ALPN mismatch、网络超时或 record 解密失败都不是 TLS1.2-only 证据。证书主机为 IP literal 时只匹配 iPAddress SAN，不回退到 dNSName 或 CN。
> **安全策略**：自动 redirect 默认拒绝 HTTPS 到 HTTP 降级；跨源 redirect 清理 `Authorization`、`Cookie`、`Proxy-Authorization`；reused stale 连接失败只对 `GET`、`HEAD`、`OPTIONS` 等安全/幂等请求自动 fresh retry。TLS 1.3 0-RTT 默认关闭，启用时仍要求调用方显式标记 replay-safe。TLS 1.2 RSA key exchange、CBC 和 renegotiation 已实现但默认关闭，只能通过 `TlsSecurityProfile::CompatibilityExplicit` 和对应开关显式启用。证书链构建、Name Constraints、certificatePolicies、IDNA 和 OCSP/CRL 缓存条目会参与验证；强撤销判定依赖调用方提供的新鲜 stapled/cached revocation entry，库层不在证书验证过程中递归发起在线 HTTP 获取。叶子证书默认硬性要求 ServerAuth EKU、KeyUsage digitalSignature 且不能是 CA；中间/根证书要求 BasicConstraints CA 和 KeyUsage keyCertSign。

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
- `OnBody` 当前不是边收边回调；实现会先完成响应读取、HTTP/1.1 Transfer-Encoding 解码和 Content-Encoding 解码，再以一次完整 body 回调返回，且 `finalChunk == true`。需要同时保留 `Response*` 时使用 `SendFlagAggregateWithCallbacks`。

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

`MaxConnsPerHost` 是 scheme + host + port + address-family 维度的 active + idle 配额，不是完整 TLS 身份维度。实际复用仍要求完整连接池 key 一致，包括 SNI、ALPN、证书策略、信任库、TLS 版本边界、TLS policy identity 和客户端凭据；同一 host 但 TLS 身份不同的连接不会互相复用。若同 host 配额被空闲的旧 TLS 身份占住，连接池可以先关闭该空闲连接再创建新身份连接；active 连接占满时返回 `STATUS_INSUFFICIENT_RESOURCES`。

DNS 解析通过 `net::WskClient::ResolveAll` 同步完成。解析进入 WSK provider 后不承诺被 `AsyncCancel` 中断，取消只保证上层异步操作、后续 connect/handshake/send/receive 等有界路径观察取消。DNS cache 是模块全局正向缓存：固定 5 分钟 TTL、16 个槽位，key 包含 host/service/address-family（ASCII 大小写不敏感），不读取 DNS 记录 TTL，不实现 negative cache 或公共 flush API；任一 `WskClient::Shutdown()` 会清空全局缓存。`Any` 地址族按 resolver 返回顺序连接，失败后尝试下一个地址，当前不实现 Happy Eyeballs 并行 IPv4/IPv6 竞速。

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
               "http://httpbun.com/get",
               sizeof("http://httpbun.com/get") - 1,
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

HTTP 请求只接受完整 URL，发送时生成 origin-form request-target；fragment 会被剥离，query-only URL 会发送为 `/?query`。path/query 中的 percent-encoding 按字节原样透传，不做解码、大小写归一化或路径归一化；非法 percent triplet 返回 `STATUS_INVALID_PARAMETER`。request-target 上限为 8000 octets，超过时返回 `STATUS_BUFFER_TOO_SMALL`。host 只接受 ASCII 可见字符，非 ASCII/IDNA 主机名和 IPv6 zone id 当前不是目标能力；IPv6 literal 会自动生成带方括号的 `Host`。

高层 HTTP API 不暴露 absolute-form、authority-form 或 asterisk-form 发送；CONNECT、TRACE 和自定义 method 不在当前 `Method` 枚举范围内。`Range`、`If-None-Match` 等条件请求/范围请求字段按普通 header 透传，不实现 RFC 9111 cache 或内核缓存 API。

## 6. Request 构造（细粒度入口）

`Request` 是个写一次的请求构造器，构造完后传给 `Send / SendEx / SendAsync / SendAsyncEx` 消费。

| 方法 | 作用 |
|---|---|
| `RequestSetUrl` | 必填，设置完整 URL |
| `RequestSetMethod` | 默认 `Get`；用 `Method::Post / Put / Patch / Delete / Head / Options` |
| `RequestSetHeader` | 追加单个请求头；可重复调用 |
| `RequestSetBody` | 通用裸字节体（未指定 Content-Type） |
| `RequestSetBodyMode` | `ContentLength`（默认）或显式 `Chunked` 请求体；不支持 request trailer |
| `RequestSetTextBody` | 文本体；`contentType` 可空时默认 `text/plain; charset=utf-8` |
| `RequestSetJsonBody` | JSON 体；隐含 `application/json` |
| `RequestSetRawBody` | 自定义 Content-Type 的裸字节 |
| `RequestSetFormBody` | `application/x-www-form-urlencoded`，传入 `NameValuePair` 数组 |
| `RequestSetMultipartBody` | `multipart/form-data`，传入 `MultipartPart` 数组（字段、文件字节、文件路径） |
| `RequestSetFileBody` | 文件路径作为请求体（内核态走 `\SystemRoot\…` NT 路径） |
| `RequestClearBody` | 清除已设置的请求体 |
| `RequestSetTls` | 覆盖会话默认 TLS（含证书策略、ALPN、SNI、信任库、TLS policy、客户端凭据） |
| `RequestSetConnPolicy` | `ReuseOrCreate`（默认池化复用）/ `ForceNew`（强制新连接）/ `NoPool`（既不复用也不进池） |
| `RequestSetAddressFamily` | `Any` / `Ipv4` / `Ipv6` |

`MultipartPart::Kind` 决定该段携带的字段：`Field`（`Name/Value`）、`FileBytes`（`Name/FileName/ContentType/Data/DataLength`）、`FilePath`（`Name/FileName/ContentType/FilePath/FilePathLength`）。

请求保留字段在发送前统一校验：`Host`、`Content-Length`、`Connection` 由实现生成，调用方手写会返回 `STATUS_INVALID_PARAMETER`；`Transfer-Encoding`、`TE`、`Trailer` 返回 `STATUS_NOT_SUPPORTED`；带非空请求体时设置 `Expect: 100-continue` 返回 `STATUS_NOT_SUPPORTED`。`Accept-Encoding` 可由调用方覆盖，但当前不承诺完整 qvalue/content negotiation 语义；默认发送的编码集合只表示本实现能处理的响应 decoder 子集。当前不提供 HTTP 代理隧道、入站 request parser/server role 或 RFC 9111 内核缓存 API。

## 7. 同步发送：Send / SendEx

```cpp
NTSTATUS Send(Session*, Request*, Response** response);
NTSTATUS Send(Session*, Request*, const SendOptions* options, Response** response /*可空*/);
NTSTATUS SendEx(Session*, Request*, const SendOptions* options, Response** response /*可空*/);
```

- `SendOptions::MaxResponseBytes`：覆盖响应上限；`0` 表示不限制。`options == nullptr` 时同样不限制。
- `SendOptions::OnHeader / OnBody`：响应聚合并解析完成后触发；`OnBody` 接收完整解码 body，不是网络流式分块。要在使用回调的同时仍获得完整聚合响应，需要在 `Flags` 中加入 `SendFlagAggregateWithCallbacks`（参考 `RunSendWithOptions` 中的写法）。
- `SendOptions::Flags`：`SendFlagDisableAutoRedirect` 可关闭自动 redirect；默认 redirect 上限为 `DefaultMaxRedirects`，可用 `MaxRedirects` 覆盖。
- `SendOptions::MaxRedirects`：`0` 表示使用默认 redirect 上限。
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
SIZE_T      ResponseTrailerCount(const Response*);
NTSTATUS    ResponseGetHeader(const Response*, name, nameLen, &value, &valueLen);
NTSTATUS    ResponseGetHeaderAt(const Response*, index, &name,&nameLen, &value,&valueLen);
NTSTATUS    ResponseGetTrailer(const Response*, name, nameLen, &value, &valueLen);
NTSTATUS    ResponseGetTrailerAt(const Response*, index, &name,&nameLen, &value,&valueLen);
void        ResponseRelease(Response*);
```

`ResponseGetHeader` 按名称查询（大小写不敏感）并返回第一个匹配字段；找不到时返回 `STATUS_NOT_FOUND`。`ResponseGetHeaderAt` 用 0 起索引枚举所有响应头。API 不做字段特定合并，重复字段会保持原始顺序暴露，`Set-Cookie` 也不会被合并。
`ResponseGetTrailer` / `ResponseGetTrailerAt` 只在 chunked 响应完整解析后可见；非法 trailer field-name 或 framing/routing/auth 相关 forbidden trailer 会使解析失败，不会作为成功响应暴露。

响应体会先按 HTTP/1.1 `Transfer-Encoding` 链解码（`chunked / gzip / deflate / compress`），再按 `Content-Encoding` 解码（`gzip / deflate / br / compress / x-compress / identity`）；当响应头里看到 `Content-Length` 与解码后长度不一致时，应以 `ResponseBodyLength()` 为准。

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
NTSTATUS WsSendPing    (WebSocket*, const UCHAR*, SIZE_T);
NTSTATUS WsSendPong    (WebSocket*, const UCHAR*, SIZE_T);
NTSTATUS WsReceive   (WebSocket*, WsMessage* out);
NTSTATUS WsReceiveEx (WebSocket*, const WsReceiveOptions*, WsMessage* out /*可空*/);
NTSTATUS WsClose     (WebSocket*);
NTSTATUS WsCloseEx   (WebSocket*, USHORT statusCode, const UCHAR* reason, SIZE_T reasonLength);
NTSTATUS WsSelectedSubprotocol(WebSocket*, const char** subprotocol, SIZE_T* subprotocolLength);
```

- `WsSendOptions::FinalFragment = false` 用于发送分片消息（默认 `true`）。
- `WsSendPing` / `WsSendPong` 发送 RFC 6455 控制帧，payload 最大 125 字节；`AutoReplyPing = false` 时，调用方可在收到 `WsMsgType::Ping` 后显式调用 `WsSendPong`。
- `WsCloseEx` 支持指定 close code 和 UTF-8 reason，非法 close code 或超过控制帧上限的 reason 返回 `STATUS_INVALID_PARAMETER`；`WsClose` 等价于默认关闭。主动关闭采用客户端简化语义：可发送时先发 close frame，然后关闭底层 transport；收到 peer close 时 echo close frame 后关闭。
- `WsSelectedSubprotocol` 返回服务端最终选择的 subprotocol；未协商时返回空视图。
- `WsReceiveOptions::AutoAllocate = true` 时由实现分配存储并写入 `WsMessage::Data`，调用方在 `WsClose` 后不再持有该指针；`AutoAllocate = false` 时需要传入 `OnMessage` 回调消费数据。
- `WsMessage::Type` 取自 `WsMsgType { Text, Binary, Close, Continuation, Ping, Pong }`。
- 接收路径默认返回完整消息；服务端分片消息会被聚合，Ping 控制帧默认自动回复。
- `AutoReplyPing = false` 时，收到 Ping 会以 `WsMsgType::Ping` 控制事件返回，不会自动发送 Pong；收到 Pong 会以 `WsMsgType::Pong` 返回。默认自动处理控制帧时 Pong 不会作为消息返回。
- 文本发送会校验 UTF-8，空文本、空二进制和空 continuation 分片是允许的。
- 发送二进制 echo 服务端时，注意服务端类型差异：示例代码区分了 `WebSocketSecureEchoUrl` 与 `WebSocketBinaryEchoUrl`。

异步连接通过 `AsyncGetWebSocket(op, &ws)` 获取连接成功后的句柄；连接失败则该函数返回 NTSTATUS，`ws` 保持为空。

## 12. 枚举与默认值速查

`Method`：`Get / Post / Put / Patch / Delete / Head / Options`
`PoolType`：`NonPaged / Paged`（响应缓冲所属池）
`TlsVersion`：`Tls12 (0x0303) / Tls13 (0x0304)`
`CertPolicy`：`Verify / NoVerify`
`AddressFamily`：`Any / Ipv4 / Ipv6`
`ConnPolicy`：`ReuseOrCreate / ForceNew / NoPool`
`WsMsgType`：`Text / Binary / Close / Continuation / Ping / Pong`
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
- 与 TLS / 证书相关的常见 NTSTATUS：`STATUS_TRUST_FAILURE`、`STATUS_TRUST_NO_TRUST`、`STATUS_INVALID_SIGNATURE`、`STATUS_INVALID_NETWORK_RESPONSE`、`STATUS_NOT_SUPPORTED`。`STATUS_NOT_SUPPORTED` 常见于本地 provider 不支持、TLS policy 禁止、0-RTT 未标记 replay-safe 或 ALPN 无匹配。
- 与连接 / 池相关：`STATUS_DEVICE_NOT_CONNECTED`、`STATUS_CONNECTION_DISCONNECTED`、`STATUS_IO_TIMEOUT`。
- 异步路径上 `AsyncWait` 的 `STATUS_TIMEOUT` / `STATUS_PENDING` 表示超时未完成；`STATUS_CANCELLED` 表示被 `AsyncCancel` 打断。

## 14. 可运行示例索引

`src/KernelHttpTest/samples/HighLevelApiSamples.cpp` 中按场景列出了：会话创建、HTTP 同步快捷函数、Request 构造、各类请求体、Send 选项与回调、响应头读取、各种异步入口、`AsyncCancel`、HTTPS（含 ALPN 切换）、WebSocket 同步与异步连接、文本 / 二进制 / Ex / 回调接收等。可以直接对照阅读，每个样例都打印请求与响应详情，便于调试。

驱动加载时的公网矩阵是运行环境诊断，不是确定性的协议 conformance 测试。DNS 无匹配、网络/主机/协议不可达、连接拒绝、连接断开/重置/中止、设备未连接和 I/O 超时会记录到对应 result 字段，但不让这些公网诊断项决定整个样例矩阵成败。协议解析错误、API misuse、证书信任失败、签名错误、ALPN mismatch 或 unsupported protocol 仍按失败处理；公网 WebSocket 也只把 DNS/connect 阶段的环境失败视为诊断，已建连后的握手、echo 或 frame 错误仍是 fatal。

公网样例端点按能力选择：`httpbin.dev` 用于 HTTPS HTTP/2 verb、content-encoding 和 advanced httpbin-style 路径；`httpbun.com` 用于 plain HTTP/1.1 GET/POST/PUT/PATCH/DELETE verb echo；`nghttp2.org` 只保留需要其 HTTP/2/h2c 能力的路径，例如 h2c upgrade，以及尚未迁移验证的 HEAD/OPTIONS 样例。公网服务仍可能变更行为，live driver validation 需要记录日期和时区、endpoint host、传输模式、HTTP 状态码或 NTSTATUS，以及该结果被计为 fatal 还是 diagnostic。

`src/KernelHttpTest/samples/ExternalTrustStore.{h,cpp}` 给出了如何从 PEM bundle 构造会话级证书 `Store` 的模板，并被 `RunHighLevelApiSamples` 在创建 Session 时使用。测试驱动默认从驱动镜像目录读取 `cacert.pem`；也可在服务注册表值 `CertificateBundlePath` 中配置完整路径，例如 `\??\E:\work\kernel_http\certs\cacert.pem`。

## 15. 相关文档

- [底层 API 文档](low-level-api.md)：底层 API 的详细使用说明，适合需要精细控制、性能优化或特殊定制的场景
- [API 概述](api-overview.md)：高层 API 和底层 API 的对比和选择指南
- [项目说明](../README.md)：项目概述和构建说明
- [AGENTS.md](../AGENTS.md)：工程约束和开发规范
