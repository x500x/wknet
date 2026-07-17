# 会话与配置

命名空间：`wknet::http`  
头文件：`wknet/http/Session.h` · `wknet/http/Types.h` · `wknet/http/Cache.h`

`Session` 生命周期与 `SessionConfig`（含 `Http3`、代理、TLS、连接池、cache）。

## SessionCreate / SessionClose

### 签名

```cpp
NTSTATUS SessionCreate(_Out_ Session** session) noexcept;
NTSTATUS SessionCreate(
    _In_opt_ const SessionConfig* config,
    _Out_ Session** session) noexcept;
void SessionClose(_In_opt_ Session* session) noexcept;
```

### 参数

| 参数 | 说明 |
|------|------|
| `config` | 可选；`nullptr` 等价于 `DefaultSessionConfig()` 语义 |
| `session` | 输出句柄；失败时置 `nullptr` |

### 返回

| 状态 | 含义 |
|------|------|
| `STATUS_SUCCESS` | 创建成功 |
| `STATUS_INVALID_PARAMETER` | `session == nullptr` 或配置非法 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败 |
| 其它 | 初始化 / 校验失败 |

### 备注

- 必须在 `PASSIVE_LEVEL` 调用。
- `SessionClose(nullptr)` 安全。
- 关闭前应结束依赖该会话的请求 / WebSocket / 异步操作。

## DefaultSessionConfig

```cpp
SessionConfig DefaultSessionConfig() noexcept; // 返回 SessionConfig{}
```

## SessionConfig

头文件：`Types.h`

```cpp
struct SessionConfig final {
    PoolType ResponsePool = PoolType::NonPaged;
    SIZE_T RequestBufferBytes = DefaultRequestBufferBytes;
    SIZE_T MaxResponseBytes = DefaultMaxResponseBytes; // 0 = 不设调用方聚合上限
    ULONG PoolCapacity = DefaultPoolCapacity;
    ULONG MaxConnsPerHost = DefaultMaxConnsPerHost;
    ULONG IdleTimeoutMs = DefaultIdleTimeoutMs;
    bool EnableHttp11Pipeline = false;
    ULONG Http11PipelineMaxDepth = DefaultHttp11PipelineMaxDepth;
    ULONG Http11PipelineMethodMask = DefaultHttp11PipelineMethodMask;
    Http2KeepAliveConfig Http2KeepAlive = {};
    Http3Config Http3 = {};
    TlsConfig Tls = {};
    ProxyConfig Proxy = {};
    Cache* Cache = nullptr;
};
```

| 字段 | 默认 | 说明 |
|------|------|------|
| `ResponsePool` | `NonPaged` | 响应缓冲池；内核路径当前仅 `NonPaged`；`Paged` 为保留 ABI，会拒收 |
| `RequestBufferBytes` | `DefaultRequestBufferBytes` (16 KiB) | 请求构造缓冲 |
| `MaxResponseBytes` | `0` | `0` 表示调用方不设 buffered 上限 |
| `PoolCapacity` | `8` | 连接池总容量 |
| `MaxConnsPerHost` | `2` | 每主机连接上限 |
| `IdleTimeoutMs` | `30000` | 空闲回收 |
| `EnableHttp11Pipeline` | `false` | HTTP/1.1 pipeline 开关 |
| `Http11PipelineMaxDepth` | `4` | pipeline 在途深度 |
| `Http11PipelineMethodMask` | GET/HEAD/OPTIONS | 允许 pipeline 的方法位掩码 |
| `Http2KeepAlive` | disabled | 见下 |
| `Http3` | `Auto` 等 | **会话含 HTTP/3 配置**；见下 |
| `Tls` | `DefaultTlsConfig()` | 会话默认 TLS；单次发送可覆盖 |
| `Proxy` | disabled | 见下 |
| `Cache` | `nullptr` | 会话默认 RFC 9111 缓存；`nullptr` 不自动缓存 |

### Http11 pipeline 方法掩码

`Types.h`：`Http11PipelineMethodGet = 0x1` … `Http11PipelineMethodTrace = 0x100`。  
`DefaultHttp11PipelineMethodMask = Get | Head | Options`。

## ProxyConfig

```cpp
struct ProxyConfig final {
    bool Enabled = false;
    const char* Host = nullptr;
    SIZE_T HostLength = 0;
    USHORT Port = 0;
    AddressFamily Family = AddressFamily::Any;
    const char* Authority = nullptr;
    SIZE_T AuthorityLength = 0;
    const char* AuthHeader = nullptr;
    SIZE_T AuthHeaderLength = 0;
};
```

| 字段 | 说明 |
|------|------|
| `Enabled` | `true` 时启用代理 |
| `Host` / `HostLength` | 代理主机名或地址字节 |
| `Port` | 代理端口 |
| `Family` | `Any` / `Ipv4` / `Ipv6` |
| `Authority` / `AuthorityLength` | 代理 authority（如 `proxy.example:8080`）；HTTPS CONNECT 与明文 absolute-form 使用 |
| `AuthHeader` / `AuthHeaderLength` | 可选 `Proxy-Authorization` 值，仅发给代理 |

备注：`https://` 目标走 CONNECT 隧道；`http://` 目标发 absolute-form，不建 CONNECT。指针在 `Session` 存活期内须有效（或由调用方保证在使用期间有效）。

## Http2KeepAliveConfig

```cpp
struct Http2KeepAliveConfig final {
    bool Enabled = false;
    ULONG IdleMs = DefaultHttp2KeepAliveIdleMs;           // 30000
    ULONG IntervalMs = DefaultHttp2KeepAliveIntervalMs;   // 30000
    ULONG AckTimeoutMs = DefaultHttp2KeepAliveAckTimeoutMs; // 5000
};
```

## Http3Config

```cpp
struct Http3Config final {
    Http3ConnectMode Mode = Http3ConnectMode::Auto;
    Http3RaceMode Race = Http3RaceMode::DelayedTcpFallback;
    ULONG RaceWindowMs = DefaultHttp3RaceWindowMs;             // 250
    ULONG QuicProbeTimeoutMs = DefaultHttp3QuicProbeTimeoutMs; // 1500
    ULONG AltSvcMaxEntries = DefaultHttp3AltSvcMaxEntries;     // 64
    ULONG AltSvcMaxAgeSec = DefaultHttp3AltSvcMaxAgeSec;       // 604800
};
```

| 枚举 | 值 | 含义 |
|------|----|------|
| `Http3ConnectMode::Auto` | 0 | 默认；从已认证响应学习 `h3` Alt-Svc |
| `Http3ConnectMode::Disabled` | 1 | 不使用 H3 |
| `Http3ConnectMode::Required` | 2 | 强制 H3，无 TCP 自动回落 |
| `Http3RaceMode::DelayedTcpFallback` | 0 | 竞速窗口后可回落 TCP |
| `Http3RaceMode::SequentialPreferHttp3` | 1 | 顺序优先 H3 |

语义细节见 [HTTP/3 与 QUIC](../http3-quic.md)。

## TlsConfig（摘要）

完整字段见 [证书与 TLS 选项](tls-options.md)。会话侧常用：

| 字段 | 默认 |
|------|------|
| `MinVersion` | `TlsVersion::Tls12` |
| `MaxVersion` | `TlsVersion::Tls13` |
| `Certificate` | `CertPolicy::Verify` |
| `Store` | `nullptr` |
| `PreferHttp2` | `true` |
| `HandshakeTimeoutMs` | `DefaultTlsHandshakeTimeoutMs` |
| `MaxTls12Renegotiations` | `DefaultMaxTls12Renegotiations` (1) |

## Cache 与 CacheOptions

```cpp
NTSTATUS CacheCreate(_Out_ Cache** cache) noexcept;
NTSTATUS CacheCreate(_In_opt_ const CacheOptions* options, _Out_ Cache** cache) noexcept;
void CacheRelease(_In_opt_ Cache* cache) noexcept;
NTSTATUS CacheClear(_In_ Cache* cache) noexcept;
NTSTATUS CacheGetStats(_In_ Cache* cache, _Out_ CacheStats* stats) noexcept;

struct CacheOptions final {
    SIZE_T MaxBytes = 16 * 1024 * 1024;
    SIZE_T MaxEntries = 256;
    CacheMode Mode = CacheMode::Private; // Private | Shared
};
```

将 `Cache*` 赋给 `SessionConfig.Cache` 或 `SendOptions.Cache`。

## 相关默认常量（`Types.h`）

| 常量 | 值 |
|------|----|
| `DefaultRequestBufferBytes` | 16 KiB |
| `DefaultMaxResponseBytes` | 0 |
| `DefaultPoolCapacity` | 8 |
| `DefaultMaxConnsPerHost` | 2 |
| `DefaultIdleTimeoutMs` | 30000 |
| `DefaultMaxRedirects` | **10**（用于 `SendOptions.MaxRedirects==0`） |
| `DefaultHttp2KeepAliveIdleMs` / `IntervalMs` | 30000 |
| `DefaultHttp2KeepAliveAckTimeoutMs` | 5000 |
| `DefaultHttp11PipelineMaxDepth` | 4 |
| `DefaultHttp3RaceWindowMs` | 250 |
| `DefaultHttp3QuicProbeTimeoutMs` | 1500 |
| `DefaultHttp3AltSvcMaxEntries` | 64 |
| `DefaultHttp3AltSvcMaxAgeSec` | 604800 |

## 示例

### 默认会话 + 默认请求头 / Bearer

```cpp
#include <wknet/Wknet.h>

NTSTATUS SessionWithDefaults()
{
    using namespace wknet::http;

    Session* session = nullptr;
    Response* response = nullptr;
    NTSTATUS status = SessionCreate(&session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SessionSetDefaultHeader(session, "User-Agent", "my-driver/1.0");
    if (NT_SUCCESS(status)) {
        static const char kToken[] = "demo-token";
        status = SessionSetBearerAuth(session, kToken, sizeof(kToken) - 1);
    }
    if (NT_SUCCESS(status)) {
        status = Get(session, "https://example.com/api/me", &response);
    }

    ResponseRelease(response);
    SessionClearAuth(session);
    SessionClearDefaultHeaders(session);
    SessionClose(session);
    return status;
}
```

### 自定义连接池与 HTTP/3

```cpp
SessionConfig config = DefaultSessionConfig();
config.PoolCapacity = 16;
config.MaxConnsPerHost = 4;
config.IdleTimeoutMs = 60000;
config.Http3.Mode = Http3ConnectMode::Auto; // 或 Disabled / Required
// config.Tls.Store = trustStore;            // 生产路径应提供信任锚

Session* session = nullptr;
NTSTATUS status = SessionCreate(&config, &session);
// ... Get / Post ...
SessionClose(session);
```

### 会话级 Cache

```cpp
Cache* cache = nullptr;
CacheOptions cacheOpts = {};
cacheOpts.MaxBytes = 4 * 1024 * 1024;
cacheOpts.MaxEntries = 128;
cacheOpts.Mode = CacheMode::Private;

NTSTATUS status = CacheCreate(&cacheOpts, &cache);
if (NT_SUCCESS(status)) {
    SessionConfig config = DefaultSessionConfig();
    config.Cache = cache;
    Session* session = nullptr;
    status = SessionCreate(&config, &session);
    // 发送期间 Cache* 须保持有效
    SessionClose(session);
    CacheRelease(cache);
}
```

## 相关链接

- [API 总览](overview.md)
- [同步 HTTP · SendOptions](http-sync.md)
- [证书与 TLS](tls-options.md)
- [HTTP/3 与 QUIC](../http3-quic.md)
- [第一个请求](../first-request.md)
