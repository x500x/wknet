# 高层 API / High-Level API

HTTP 在命名空间 `KernelHttp::khttp`，WebSocket 在 `KernelHttp::kws`。句柄类型不透明，资源由对应 Release/Close 释放（均接受 `nullptr`）。

[English](#english) | 简体中文

---

## 简体中文

### 句柄与生命周期

- `khttp::Session` / `Request` / `Response` / `AsyncOp`，`kws::WebSocket`。
- `Response` 与发起它的 `Request`/`AsyncOp` 是**独立**生命周期，分别释放。
- 全部调用在 `PASSIVE_LEVEL`。用过异步 API 后，卸载前必须 `khttp::Destroy()`；同步-only 路径可不调用，但可无条件调用。

### 生命周期（`khttp/Lifecycle.h`）

```cpp
void Destroy() noexcept;   // 高层卸载收尾入口，等待全部在飞异步操作结束
```

### Session（`khttp/Session.h`）

```cpp
NTSTATUS SessionCreate(net::WskClient* wskClient, const SessionConfig* config, Session** out) noexcept;
void     SessionClose(Session* session) noexcept;   // 接受 nullptr
```
`config` 传 `nullptr` 使用默认（见 [配置项](configuration.md)）。

### Request 构造（`khttp/Request.h`）

```cpp
NTSTATUS RequestCreate(Session*, Request** out) noexcept;
void     RequestRelease(Request*) noexcept;
NTSTATUS RequestSetUrl(Request*, const char* url, SIZE_T urlLength) noexcept;
NTSTATUS RequestSetMethod(Request*, Method method) noexcept;
NTSTATUS RequestSetHeader(Request*, const char* name, SIZE_T nameLen, const char* value, SIZE_T valueLen) noexcept;
// 请求体（多种形式）
NTSTATUS RequestSetBody(Request*, const UCHAR* data, SIZE_T len) noexcept;        // 原始字节（引用）
NTSTATUS RequestSetRawBody(Request*, const UCHAR* data, SIZE_T len, const char* contentType, SIZE_T ctLen) noexcept;
NTSTATUS RequestSetTextBody(Request*, const char* text, SIZE_T len, const char* contentType, SIZE_T ctLen) noexcept;
NTSTATUS RequestSetJsonBody(Request*, const char* json, SIZE_T len) noexcept;     // application/json
NTSTATUS RequestSetFormBody(Request*, const NameValuePair* pairs, SIZE_T count) noexcept;  // x-www-form-urlencoded
NTSTATUS RequestSetMultipartBody(Request*, const MultipartPart* parts, SIZE_T count) noexcept; // multipart/form-data
NTSTATUS RequestSetFileBody(Request*, const char* filePath, SIZE_T pathLen, const char* contentType, SIZE_T ctLen) noexcept;
NTSTATUS RequestSetBodyMode(Request*, RequestBodyMode mode) noexcept;             // ContentLength / Chunked
NTSTATUS RequestAddTrailer(Request*, const char* name, SIZE_T nameLen, const char* value, SIZE_T valueLen) noexcept;
NTSTATUS RequestClearBody(Request*) noexcept;
// 连接 / TLS / 地址族
NTSTATUS RequestSetTls(Request*, const TlsConfig* config) noexcept;
NTSTATUS RequestSetConnPolicy(Request*, ConnPolicy policy) noexcept;
NTSTATUS RequestSetAddressFamily(Request*, AddressFamily family) noexcept;
```

枚举：`Method { Get, Post, Put, Patch, Delete, Head, Options, Connect }`、`ConnPolicy { ReuseOrCreate, ForceNew, NoPool }`、`AddressFamily { Any, Ipv4=4, Ipv6=6 }`、`RequestBodyMode { ContentLength, Chunked }`、`BodyPartKind { Field, FileBytes, FilePath }`。

`RequestAddTrailer` 仅随 `RequestBodyMode::Chunked` 发送终止块后的 trailer 字段；禁止 `Content-Length` / `Transfer-Encoding` / `Host` / `Authorization` / `Proxy-Authorization` / `Cookie` / `Set-Cookie` 等 trailer 字段。

### 同步请求（`khttp/Http.h`）

```cpp
NTSTATUS Get(Session*, const char* url, SIZE_T urlLen, Response** resp) noexcept;
NTSTATUS Post(Session*, const char* url, SIZE_T urlLen, const UCHAR* body, SIZE_T bodyLen, Response** resp) noexcept;
NTSTATUS Put(Session*, const char* url, SIZE_T urlLen, const UCHAR* body, SIZE_T bodyLen, Response** resp) noexcept;
NTSTATUS Patch(Session*, const char* url, SIZE_T urlLen, const UCHAR* body, SIZE_T bodyLen, Response** resp) noexcept;
NTSTATUS Delete(Session*, const char* url, SIZE_T urlLen, Response** resp) noexcept;
NTSTATUS Head(Session*, const char* url, SIZE_T urlLen, Response** resp) noexcept;
NTSTATUS Options(Session*, const char* url, SIZE_T urlLen, Response** resp) noexcept;
NTSTATUS Send(Session*, Request*, Response** resp) noexcept;
NTSTATUS Send(Session*, Request*, const SendOptions* opt, Response** resp) noexcept;  // 带选项
NTSTATUS SendEx(Session*, Request*, const SendOptions* opt, Response** resp) noexcept;
```

### 异步请求（`khttp/HttpAsync.h` + `khttp/AsyncOp.h`）

```cpp
NTSTATUS GetAsync(Session*, const char* url, SIZE_T urlLen, AsyncOp** op) noexcept;
NTSTATUS PostAsync(Session*, const char* url, SIZE_T urlLen, const UCHAR* body, SIZE_T bodyLen, AsyncOp** op) noexcept;
NTSTATUS SendAsync(Session*, Request*, AsyncOp** op) noexcept;
NTSTATUS SendAsync(Session*, Request*, const SendOptions* opt, AsyncOp** op) noexcept;

NTSTATUS AsyncWait(AsyncOp*, ULONG timeoutMs) noexcept;
NTSTATUS AsyncCancel(AsyncOp*) noexcept;
NTSTATUS AsyncGetStatus(const AsyncOp*) noexcept;
bool     AsyncIsCompleted(const AsyncOp*) noexcept;
bool     AsyncIsCanceled(const AsyncOp*) noexcept;
NTSTATUS AsyncGetResponse(AsyncOp*, Response** resp) noexcept;
void     AsyncRelease(AsyncOp*) noexcept;
```
详见 [异步模型](async-model.md)。

### Response 只读访问（`khttp/Response.h`）

```cpp
ULONG        ResponseStatusCode(const Response*) noexcept;
const UCHAR* ResponseBody(const Response*) noexcept;
SIZE_T       ResponseBodyLength(const Response*) noexcept;
SIZE_T       ResponseHeaderCount(const Response*) noexcept;
SIZE_T       ResponseTrailerCount(const Response*) noexcept;
NTSTATUS     ResponseGetHeader(const Response*, const char* name, SIZE_T nameLen, const char** value, SIZE_T* valueLen) noexcept;
NTSTATUS     ResponseGetHeaderAt(const Response*, SIZE_T index, const char** name, SIZE_T* nameLen, const char** value, SIZE_T* valueLen) noexcept;
NTSTATUS     ResponseGetTrailer(const Response*, const char* name, SIZE_T nameLen, const char** value, SIZE_T* valueLen) noexcept;
NTSTATUS     ResponseGetTrailerAt(const Response*, SIZE_T index, ...) noexcept;
void         ResponseRelease(Response*) noexcept;
```

### SendOptions（流式 / 覆盖）

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `MaxResponseBytes` | `SIZE_T` | 0 | 非零时覆盖会话上限；0=使用会话上限，若会话也是 0 则不限制 |
| `Flags` | `ULONG` | `SendFlagNone` | `AggregateWithCallbacks` / `DisableAutoRedirect` |
| `MaxRedirects` | `ULONG` | 0 | 0=用默认（10） |
| `OnHeader` | `HeaderCallback` | nullptr | 逐头回调 |
| `OnBody` | `BodyCallback` | nullptr | 逐块回调（流式接收） |
| `CallbackContext` | `void*` | nullptr | |
| `OnComplete` / `CompletionContext` | | nullptr | 完成回调 |

回调签名：
```cpp
NTSTATUS HeaderCallback(void* ctx, const char* name, SIZE_T nameLen, const char* value, SIZE_T valueLen);
NTSTATUS BodyCallback(void* ctx, const UCHAR* data, SIZE_T len, bool finalChunk);
void     CompletionCallback(void* ctx, NTSTATUS status);
```

### WebSocket（`kws`，头文件 `kws/WebSocket.h`）

```cpp
// 连接（同步 / 异步，URL 或 ConnectConfig）
NTSTATUS kws::Connect(khttp::Session*, const char* url, SIZE_T urlLen, WebSocket** ws) noexcept;
NTSTATUS kws::Connect(khttp::Session*, const ConnectConfig*, WebSocket** ws) noexcept;
NTSTATUS kws::ConnectAsync(khttp::Session*, const char* url, SIZE_T urlLen, khttp::AsyncOp** op) noexcept;
NTSTATUS kws::AsyncGetWebSocket(khttp::AsyncOp*, WebSocket** ws) noexcept;
// 发送
NTSTATUS kws::SendText(WebSocket*, const char* text, SIZE_T len) noexcept;
NTSTATUS kws::SendBinary(WebSocket*, const UCHAR* data, SIZE_T len) noexcept;
NTSTATUS kws::SendContinuation(WebSocket*, const UCHAR* data, SIZE_T len) noexcept;       // 分片续帧
NTSTATUS kws::SendPing(WebSocket*, const UCHAR* payload, SIZE_T len) noexcept;
NTSTATUS kws::SendPong(WebSocket*, const UCHAR* payload, SIZE_T len) noexcept;
// 各有 *Ex 重载，带 SendOptions{ bool FinalFragment }
// 接收 / 关闭 / 查询
NTSTATUS kws::Receive(WebSocket*, Message* msg) noexcept;
NTSTATUS kws::ReceiveEx(WebSocket*, const ReceiveOptions*, Message* msg) noexcept;
NTSTATUS kws::Close(WebSocket*) noexcept;
NTSTATUS kws::CloseEx(WebSocket*, USHORT statusCode, const UCHAR* reason, SIZE_T reasonLen) noexcept;
NTSTATUS kws::SelectedSubprotocol(WebSocket*, const char** sub, SIZE_T* subLen) noexcept;
```

`kws::MsgType { Text, Binary, Close, Continuation, Ping, Pong }`。`Message{ MsgType Type; const UCHAR* Data; SIZE_T DataLength; bool Final; }`，`Data` 指向内部缓冲，下次收/关前有效。详见 [WebSocket 协议](websocket.md)。

`ConnectConfig.Headers` / `HeaderCount` 可传 opening-handshake 额外头；库受控头（`Host`、`Connection`、`Upgrade`、`Sec-WebSocket-*` 等）会被拒绝。`ConnectConfig.AllowWebSocketOverHttp2=true` 时，`wss` 连接可显式 opt-in RFC 8441 WebSocket over HTTP/2；默认仍走 HTTP/1.1 Upgrade，`ws://` 不隐式走 h2c。

> **WebSocket 全双工时序**：`Close` 不得与同句柄上「新 I/O 发起」并发；最安全是单线程内 连接→发→收→关。

### 示例

```cpp
khttp::Session* s = nullptr;
khttp::SessionCreate(&wskClient, nullptr, &s);

khttp::Response* r = nullptr;
if (NT_SUCCESS(khttp::Get(s, "https://api.example.com/v1", 26, &r))) {
    ULONG code = khttp::ResponseStatusCode(r);
    const UCHAR* body = khttp::ResponseBody(r);
    SIZE_T len = khttp::ResponseBodyLength(r);
    khttp::ResponseRelease(r);
}
khttp::SessionClose(s);
```

---

## English

HTTP lives in `KernelHttp::khttp`, WebSocket in `KernelHttp::kws`. Handles are opaque; release with the matching Release/Close (all accept `nullptr`). A `Response` has a lifetime independent of its `Request`/`AsyncOp`. All calls at `PASSIVE_LEVEL`; after async usage call `khttp::Destroy()` before unload. Synchronous-only paths do not require it, but may call it unconditionally.

The full signatures, enums, `SendOptions` fields, and callback prototypes are listed in the Chinese section above (code is language-neutral). Key entry points: `Destroy`; `SessionCreate`/`SessionClose`; `RequestCreate` + setters (`SetUrl`/`SetMethod`/`SetHeader`/`Set*Body`/`RequestAddTrailer`/`SetTls`/`SetConnPolicy`/`SetAddressFamily`); synchronous `Get`/`Post`/`Put`/`Patch`/`Delete`/`Head`/`Options`/`Send`; asynchronous `GetAsync`/`PostAsync`/`SendAsync` + `AsyncWait`/`AsyncCancel`/`AsyncGetResponse`/`AsyncRelease`; response accessors `ResponseStatusCode`/`ResponseBody`/`ResponseGetHeader`/...

**WebSocket (`kws`)**: `Connect`/`ConnectAsync` (`ConnectConfig.Headers` for opening-handshake headers; `AllowWebSocketOverHttp2` explicitly opts `wss` into RFC 8441), `SendText`/`SendBinary`/`SendContinuation`/`SendPing`/`SendPong` (+ `*Ex` with `FinalFragment`), `Receive`/`ReceiveEx`, `Close`/`CloseEx`, `SelectedSubprotocol`. `Message.Data` points to an internal buffer valid until the next receive/close. Never run `Close` concurrently with new I/O on the same handle.
