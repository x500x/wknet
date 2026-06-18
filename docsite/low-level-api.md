# 底层 API / Low-Level API

命名空间 `KernelHttp::engine`，所有公开函数以 `Kh` 前缀、句柄类型以 `KH_` 前缀。这是 ABI 稳定层，高层 `khttp`/`kws` 即在其上薄封装。适合性能关键、特殊定制、测试调试。

[English](#english) | 简体中文

---

## 简体中文

### 句柄类型

```cpp
typedef KhSession*        KH_SESSION;
typedef KhRequest*        KH_REQUEST;
typedef KhResponse*       KH_RESPONSE;
typedef KhWebSocket*      KH_WEBSOCKET;
typedef KhAsyncOperation* KH_ASYNC_OPERATION;
```

### 枚举

```cpp
enum class KhHttpMethod        { Get, Post, Put, Patch, Delete, Head, Options };
enum class KhTlsVersion        { Tls12 = 0x0303, Tls13 = 0x0304 };
enum class KhCertificatePolicy { Verify, NoVerify };
enum class KhConnectionPolicy  { ReuseOrCreate, ForceNew, NoPool };
enum class KhAddressFamily     { Any, Ipv4 = 4, Ipv6 = 6 };
enum class KhPoolType          { NonPaged, Paged };  // Paged 为保留值，内核仅 NonPaged
enum class KhRequestBodyMode   { ContentLength, Chunked };
enum class KhRequestBodyPartKind { Field, FileBytes, FilePath };
enum class KhWebSocketMessageType { Text, Binary, Close, Continuation, Ping, Pong };
enum KhHttpSendFlags { KhHttpSendFlagNone = 0,
                       KhHttpSendFlagAggregateWithCallbacks = 0x1,
                       KhHttpSendFlagDisableAutoRedirect = 0x2 };
```

### 会话

```cpp
NTSTATUS KhSessionCreate(net::WskClient*, const KhSessionOptions*, KH_SESSION* out) noexcept;
void     KhSessionClose(KH_SESSION) noexcept;
```
`KhSessionOptions` / `KhTlsOptions` 字段见 [配置项](configuration.md)。

### 请求构造

```cpp
NTSTATUS KhHttpRequestCreate(KH_SESSION, KH_REQUEST* out) noexcept;
void     KhHttpRequestRelease(KH_REQUEST) noexcept;
NTSTATUS KhHttpRequestSetUrl(KH_REQUEST, const char* url, SIZE_T urlLen) noexcept;
NTSTATUS KhHttpRequestSetMethod(KH_REQUEST, KhHttpMethod) noexcept;
NTSTATUS KhHttpRequestSetHeader(KH_REQUEST, const char* name, SIZE_T nLen, const char* value, SIZE_T vLen) noexcept;
NTSTATUS KhHttpRequestSetBody(KH_REQUEST, const UCHAR* body, SIZE_T len) noexcept;
NTSTATUS KhHttpRequestSetBodyMode(KH_REQUEST, KhRequestBodyMode) noexcept;
NTSTATUS KhHttpRequestClearBody(KH_REQUEST) noexcept;
NTSTATUS KhHttpRequestSetTextBody(KH_REQUEST, const char* text, SIZE_T len, const char* ct, SIZE_T ctLen) noexcept;
NTSTATUS KhHttpRequestSetRawBody(KH_REQUEST, const UCHAR* data, SIZE_T len, const char* ct, SIZE_T ctLen) noexcept;
NTSTATUS KhHttpRequestSetUrlEncodedBody(KH_REQUEST, const KhNameValuePair* pairs, SIZE_T count) noexcept;
NTSTATUS KhHttpRequestSetMultipartFormDataBody(KH_REQUEST, const KhMultipartFormDataPart* parts, SIZE_T count) noexcept;
NTSTATUS KhHttpRequestSetFileBody(KH_REQUEST, const char* path, SIZE_T pathLen, const char* ct, SIZE_T ctLen) noexcept;
NTSTATUS KhHttpRequestSetTlsOptions(KH_REQUEST, const KhTlsOptions*) noexcept;
NTSTATUS KhHttpRequestSetConnectionPolicy(KH_REQUEST, KhConnectionPolicy) noexcept;
NTSTATUS KhHttpRequestSetAddressFamily(KH_REQUEST, KhAddressFamily) noexcept;
```

### 发送

```cpp
NTSTATUS KhHttpSendSync(KH_SESSION, KH_REQUEST, const KhHttpSendOptions*, KH_RESPONSE* resp) noexcept;
NTSTATUS KhHttpSendAsync(KH_SESSION, KH_REQUEST, const KhHttpSendOptions*, KH_ASYNC_OPERATION* op) noexcept;
```
`KhHttpSendOptions` 字段：`MaxResponseBytes`、`Flags`、`MaxRedirects`、`HeaderCallback`、`BodyCallback`、`CallbackContext`、`CompletionCallback`、`CompletionContext`。

### 响应访问

```cpp
NTSTATUS KhResponseGetView(KH_RESPONSE, KhResponseView* view) noexcept;   // { StatusCode, Body, BodyLength }
NTSTATUS KhResponseGetHeader(KH_RESPONSE, const char* name, SIZE_T nLen, const char** value, SIZE_T* vLen) noexcept;
SIZE_T   KhResponseHeaderCount(KH_RESPONSE) noexcept;
NTSTATUS KhResponseGetHeaderAt(KH_RESPONSE, SIZE_T index, const char** name, SIZE_T* nLen, const char** value, SIZE_T* vLen) noexcept;
SIZE_T   KhResponseTrailerCount(KH_RESPONSE) noexcept;
NTSTATUS KhResponseGetTrailer(...) noexcept;  NTSTATUS KhResponseGetTrailerAt(...) noexcept;
void     KhResponseRelease(KH_RESPONSE) noexcept;
```

### WebSocket（底层）

```cpp
NTSTATUS KhWebSocketConnectSync(KH_SESSION, const KhWebSocketConnectOptions*, KH_WEBSOCKET* out) noexcept;
NTSTATUS KhWebSocketConnectAsync(KH_SESSION, const KhWebSocketConnectOptions*, KH_ASYNC_OPERATION* op) noexcept;
NTSTATUS KhWebSocketSendTextSync(KH_WEBSOCKET, const char* text, SIZE_T len, const KhWebSocketSendOptions*) noexcept;
NTSTATUS KhWebSocketSendBinarySync(KH_WEBSOCKET, const UCHAR* data, SIZE_T len, const KhWebSocketSendOptions*) noexcept;
NTSTATUS KhWebSocketSendContinuationSync(KH_WEBSOCKET, const UCHAR* data, SIZE_T len, const KhWebSocketSendOptions*) noexcept;
NTSTATUS KhWebSocketSendPingSync(KH_WEBSOCKET, const UCHAR* payload, SIZE_T len) noexcept;
NTSTATUS KhWebSocketSendPongSync(KH_WEBSOCKET, const UCHAR* payload, SIZE_T len) noexcept;
NTSTATUS KhWebSocketReceiveSync(KH_WEBSOCKET, const KhWebSocketReceiveOptions*, KhWebSocketMessage* msg) noexcept;
NTSTATUS KhWebSocketCloseSync(KH_WEBSOCKET) noexcept;
NTSTATUS KhWebSocketCloseExSync(KH_WEBSOCKET, USHORT statusCode, const UCHAR* reason, SIZE_T reasonLen) noexcept;
NTSTATUS KhWebSocketSelectedSubprotocol(KH_WEBSOCKET, const char** sub, SIZE_T* subLen) noexcept;
```

### 异步操作

```cpp
NTSTATUS KhAsyncCancel(KH_ASYNC_OPERATION) noexcept;
NTSTATUS KhAsyncWait(KH_ASYNC_OPERATION, ULONG timeoutMs) noexcept;
NTSTATUS KhAsyncGetHttpResponse(KH_ASYNC_OPERATION, KH_RESPONSE* resp) noexcept;
NTSTATUS KhAsyncGetWebSocket(KH_ASYNC_OPERATION, KH_WEBSOCKET* ws) noexcept;
void     KhAsyncRelease(KH_ASYNC_OPERATION) noexcept;
```

### 引擎生命周期

```cpp
NTSTATUS KhEngineDrainAsync() noexcept;        // 等待所有在飞异步操作（卸载前必调）
void     KhEngineCloseActiveHandles() noexcept;// 强制关闭所有活跃句柄
```

### 典型流程

```cpp
KH_SESSION s = nullptr;
KhSessionOptions opt = {};                 // 注意：字段须显式设，无 Default 工厂
opt.Tls.MinVersion = KhTlsVersion::Tls13;
opt.Tls.CertificatePolicy = KhCertificatePolicy::Verify;
KhSessionCreate(&wskClient, &opt, &s);

KH_REQUEST req = nullptr;
KhHttpRequestCreate(s, &req);
KhHttpRequestSetUrl(req, url, urlLen);
KhHttpRequestSetMethod(req, KhHttpMethod::Get);

KH_RESPONSE resp = nullptr;
if (NT_SUCCESS(KhHttpSendSync(s, req, nullptr, &resp))) {
    KhResponseView v = {};
    KhResponseGetView(resp, &v);           // v.StatusCode / v.Body / v.BodyLength
    KhResponseRelease(resp);
}
KhHttpRequestRelease(req);
KhSessionClose(s);
```

### 测试钩子（仅 `KERNEL_HTTP_USER_MODE_TEST`）

`KhTestSetHttpTransport` / `KhTestSetWebSocketTransport`（注入 mock 传输）、`KhTestSetAsyncAutoRun` / `KhTestRunAsyncOperation`（手动驱动异步）、`KhTestSetCurrentIrql` / `KhTestResetCurrentIrql`（模拟 IRQL）。用于确定性单元测试，不进内核构建。

---

## English

Namespace `KernelHttp::engine`: functions are `Kh`-prefixed, handles `KH_`-prefixed. This is the stable ABI layer that `khttp`/`kws` wrap. Full signatures, enums, and option structs are in the Chinese section above (code is language-neutral).

Entry points: `KhSessionCreate`/`KhSessionClose`; `KhHttpRequestCreate` + setters (`SetUrl`/`SetMethod`/`SetHeader`/`Set*Body`/`SetTlsOptions`/`SetConnectionPolicy`/`SetAddressFamily`); `KhHttpSendSync`/`KhHttpSendAsync`; response via `KhResponseGetView`/`KhResponseGetHeader`/...; WebSocket `KhWebSocketConnectSync`/`...SendTextSync`/`...ReceiveSync`/`...CloseSync`; async `KhAsyncWait`/`KhAsyncCancel`/`KhAsyncGetHttpResponse`/`KhAsyncGetWebSocket`/`KhAsyncRelease`; lifecycle `KhEngineDrainAsync` (mandatory before unload after async) and `KhEngineCloseActiveHandles`.

Note: `KhSessionOptions` has no Default factory — zero-initialize and set fields explicitly. Test-only hooks under `KERNEL_HTTP_USER_MODE_TEST` allow mock transport injection and manual async driving.
