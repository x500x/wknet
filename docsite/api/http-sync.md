# 同步 HTTP

命名空间：`wknet::http`  
头文件：`wknet/http/Http.h` · `wknet/http/Options.h` · `wknet/http/Types.h`

阻塞 HTTP 发送：`Send` / `SendEx`、按方法发送接口、`SendOptions`。

## Send / SendEx

### 签名（Session）

```cpp
NTSTATUS Send(
    _In_ Session* session,
    Method method,
    _In_z_ const char* url,
    _In_opt_ const Headers* headers,
    _In_opt_ const Body* body,
    _In_opt_ const SendOptions* options,
    _Out_ Response** response) noexcept;

NTSTATUS SendEx(
    _In_ Session* session,
    Method method,
    _In_reads_bytes_(urlLength) const char* url,
    SIZE_T urlLength,
    _In_opt_ const Headers* headers,
    _In_opt_ const Body* body,
    _In_opt_ const SendOptions* options,
    _Out_ Response** response) noexcept;
```

### 签名（Request）

同形参，首参为 `Request*` 的 `Send` / `SendEx` 重载。

### 参数

| 参数 | 说明 |
|------|------|
| `session` / `request` | 会话或已创建请求 |
| `method` | `Method::Get` … `Trace` |
| `url` / `urlLength` | 目标 URL；`Send` 要求 NUL 结尾 |
| `headers` | 可选请求头 |
| `body` | 可选请求体 |
| `options` | 可选；`nullptr` 用默认发送选项 |
| `response` | 成功时输出；调用方 `ResponseRelease` |

### 返回

| 状态 | 含义 |
|------|------|
| `STATUS_SUCCESS` | 完成；`*response` 有效（含 4xx/5xx HTTP 状态） |
| `STATUS_INVALID_PARAMETER` | 参数非法 |
| `STATUS_INVALID_DEVICE_REQUEST` | 非 `PASSIVE_LEVEL` |
| 其它 | 网络 / TLS / 协议失败 |

HTTP 状态码经 `ResponseStatusCode` 读取，不映射为 `NTSTATUS` 失败（除非库在传输层失败）。

## 按方法发送

`Get` / `Post` 等为固定方法的 `Send` 重载，均提供 `Session*` 与 `Request*` 形式：

| 方法 | `*Ex` | 请求体 |
|------|-------|--------|
| `Get` / `Head` / `Options` / `Trace` / `Delete` | `*Ex(..., headers, options, response)` | 无 |
| `Post` / `Put` / `Patch` | `*Ex(..., headers, body, options, response)` | 有 |

另有按 URL 长度的重载（无 `Headers` / `SendOptions`），例如：

```cpp
NTSTATUS Get(_In_ Session* session,
    _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength,
    _Out_ Response** response) noexcept;
NTSTATUS Post(_In_ Session* session,
    _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength,
    _In_reads_bytes_opt_(bodyLength) const UCHAR* body, SIZE_T bodyLength,
    _Out_ Response** response) noexcept;
// Put / Patch / Delete / Head / Options / Trace 同理
```

`Trace` 需通过 `*Ex` 的 `options` 设置 `SendFlagAllowTrace`。

## SendOptionsCreate / Release

```cpp
NTSTATUS SendOptionsCreate(_Out_ SendOptions** options) noexcept;
void SendOptionsRelease(_In_opt_ SendOptions* options) noexcept;
SendOptions DefaultSendOptions() noexcept; // Types.h，值语义
```

`SendOptions` 构造函数私有：堆路径用 `SendOptionsCreate`，值路径用 `DefaultSendOptions()`。

## SendOptions 字段

```cpp
struct SendOptions final {
    SIZE_T MaxResponseBytes;
    ULONG Flags;
    ULONG MaxRedirects;
    ULONG ExpectContinueTimeoutMs;
    ULONG ResponseHeaderTimeoutMs; // 0 = 库默认
    ULONG BodyReadTimeoutMs;       // 0 = 库默认（单次底层 body 读）
    ULONG BodyIdleTimeoutMs;       // 0 = 禁用 body 字节空闲超时
    HeaderCallback OnHeader;
    BodyCallback OnBody;
    void* CallbackContext;
    TlsConfig Tls;
    bool HasTlsOverride;
    ConnPolicy ConnectionPolicy;
    AddressFamily Family;
    Http2CleartextMode Http2CleartextMode;
    const AcceptEncodingPreference* AcceptEncodingPreferences;
    SIZE_T AcceptEncodingPreferenceCount;
    const CodingDecodeMaterials* ContentCodingMaterials;
    const Http2Priority* Http2Priority;
    Cache* Cache;
};
```

| 字段 | 默认（Create / Default） | 说明 |
|------|--------------------------|------|
| `MaxResponseBytes` | `0` | `0`=本次不设调用方聚合上限 |
| `Flags` | `SendFlagNone` | 见下表 |
| `MaxRedirects` | `0` | **`0` → 使用 `DefaultMaxRedirects`（10）**；用尽后**直接返回该 3xx 响应**（不报错） |
| `ExpectContinueTimeoutMs` | `0`（Create） | `SendFlagExpectContinue` 时等待 `100 Continue`；库侧默认超时常量 `DefaultExpectContinueTimeoutMs` (1000) |
| `ResponseHeaderTimeoutMs` | `0` | `0`=库默认；等待响应头完成 |
| `BodyReadTimeoutMs` | `0` | `0`=库默认；**单次**底层 body 读超时 |
| `BodyIdleTimeoutMs` | `0` | `0`=禁用；body 字节间空闲超时（长流 / SSE 友好） |
| `OnHeader` | `nullptr` | 响应头回调；失败中止并传播 |
| `OnBody` | `nullptr` | 响应体**增量**回调：可按到达顺序**多次**调用；仅最后一次 `finalChunk=true`。未设置时仍聚合完整 body |
| `CallbackContext` | `nullptr` | 传给上述回调 |
| `Tls` / `HasTlsOverride` | 默认 TLS / `false` | `HasTlsOverride==true` 时覆盖会话 TLS |
| `ConnectionPolicy` | `ReuseOrCreate` | `ReuseOrCreate` / `ForceNew` / `NoPool` |
| `Family` | `Any` | `Any` / `Ipv4` / `Ipv6` |
| `Http2CleartextMode` | `Disabled` | 仅 `http://`：`Disabled` / `PriorKnowledge` / `Upgrade` |
| `AcceptEncodingPreferences` / `Count` | `nullptr` / `0` | 协商 `Accept-Encoding` |
| `ContentCodingMaterials` | `nullptr` | 解码字典 / AES-GCM 材料 |
| `Http2Priority` | `nullptr` | H2 首 HEADERS priority；H1 忽略 |
| `Cache` | `nullptr` | 覆盖会话缓存 |

### SendFlags

```cpp
enum SendFlags : ULONG {
    SendFlagNone = 0,
    SendFlagAggregateWithCallbacks = 0x00000001,
    SendFlagDisableAutoRedirect = 0x00000002,
    SendFlagExpectContinue = 0x00000004,
    SendFlagAllowTrace = 0x00000008,
    SendFlagBypassCache = 0x00000010,
    SendFlagNoCacheStore = 0x00000020,
    SendFlagOnlyIfCached = 0x00000040
};
```

| 标志 | 说明 |
|------|------|
| `AggregateWithCallbacks` | 有 `OnBody`/`OnHeader` 时**同时**保留聚合响应体；未设且仅回调时，`ResponseBody` 可能为空 |
| `DisableAutoRedirect` | 禁用自动重定向，返回 3xx |
| `ExpectContinue` | 有 body 的 HTTP/1.1 发 `Expect: 100-continue` |
| `AllowTrace` | 允许 TRACE |
| `BypassCache` | 跳过读缓存，仍可写 |
| `NoCacheStore` | 禁止写缓存 |
| `OnlyIfCached` | 仅缓存命中；否则 `STATUS_NOT_FOUND` |

### Accept-Encoding / Http2Priority

```cpp
struct AcceptEncodingPreference final {
    AcceptCoding Coding = AcceptCoding::Identity;
    USHORT QValue = AcceptEncodingQValueMax; // 1000
};

struct Http2Priority final {
    ULONG StreamDependency = 0;
    USHORT Weight = 16;
    bool Exclusive = false;
};

struct CodingDecodeMaterials final {
    const CodingExternalMaterial* Items = nullptr;
    SIZE_T ItemCount = 0;
    CodingMaterialCallback Callback = nullptr;
    void* CallbackContext = nullptr;
};
```

`AcceptCoding` / `ContentCoding` 枚举见 `Types.h`（Identity、Gzip、Deflate、Brotli、Compress、Zstd、字典变体、Aes128Gcm、Exi、Pack200Gzip、Any、Extension）。

### 回调类型

```cpp
typedef NTSTATUS (*HeaderCallback)(void* context,
    const char* name, SIZE_T nameLength,
    const char* value, SIZE_T valueLength);
typedef NTSTATUS (*BodyCallback)(void* context,
    const UCHAR* data, SIZE_T dataLength, bool finalChunk);
typedef NTSTATUS (*RequestBodyReadCallback)(void* context,
    UCHAR* buffer, SIZE_T bufferCapacity,
    SIZE_T* bytesRead, bool* endOfBody);
```

`OnBody` 语义（流式修正）：

- 有 `OnBody` 时，H1/H2/H3 在 transfer-decode 后的应用 body 字节按到达顺序**多次**回调。
- `finalChunk=true` 只在响应体真正结束（含空尾包）时出现一次。
- 返回失败状态会中止发送并向上传播。
- 不要假设「整 body 只回调一次」；需要整包请勿设 `OnBody`，或加 `SendFlagAggregateWithCallbacks`。
- SSE 产品 API 见 [SSE](sse.md)，内部同样消费此增量路径。

## Method 枚举

```cpp
enum class Method : ULONG {
    Get = 0, Post = 1, Put = 2, Patch = 3, Delete = 4,
    Head = 5, Options = 6, Connect = 7, Trace = 8
};
```

## 相关链接

- [请求与响应](request-response.md)
- [异步 HTTP](http-async.md)
- [会话与配置](session-config.md)
- [证书与 TLS](tls-options.md)
- [Cookbook](../cookbook.md)
