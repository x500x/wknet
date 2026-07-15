# Session & Config

Namespace: `wknet::http`  
Headers: `wknet/http/Session.h` · `wknet/http/Types.h` · `wknet/http/Cache.h`

## Role

Create/close `Session` and document session-level `SessionConfig` (including `Http3`, proxy, TLS summary, pool, and cache pointer).

## SessionCreate / SessionClose

### Signatures

```cpp
NTSTATUS SessionCreate(_Out_ Session** session) noexcept;
NTSTATUS SessionCreate(
    _In_opt_ const SessionConfig* config,
    _Out_ Session** session) noexcept;
void SessionClose(_In_opt_ Session* session) noexcept;
```

### Parameters

| Param | Meaning |
|-------|---------|
| `config` | Optional; `nullptr` matches `DefaultSessionConfig()` semantics |
| `session` | Out handle; set to `nullptr` on failure |

### Returns

| Status | Meaning |
|--------|---------|
| `STATUS_SUCCESS` | Created |
| `STATUS_INVALID_PARAMETER` | Null out-param or invalid config |
| `STATUS_INSUFFICIENT_RESOURCES` | Allocation failure |
| Other | Init / validation failure |

### Notes

- Call at `PASSIVE_LEVEL`.
- `SessionClose(nullptr)` is safe.
- Finish requests / WebSockets / async ops that use the session before close.

## DefaultSessionConfig

```cpp
SessionConfig DefaultSessionConfig() noexcept; // returns SessionConfig{}
```

## SessionConfig

Header: `Types.h`

```cpp
struct SessionConfig final {
    PoolType ResponsePool = PoolType::NonPaged;
    SIZE_T RequestBufferBytes = DefaultRequestBufferBytes;
    SIZE_T MaxResponseBytes = DefaultMaxResponseBytes; // 0 = no caller aggregate cap
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

| Field | Default | Notes |
|-------|---------|-------|
| `ResponsePool` | `NonPaged` | Kernel path requires `NonPaged`; `Paged` is reserved ABI and rejected |
| `RequestBufferBytes` | 16 KiB | Request build buffer |
| `MaxResponseBytes` | `0` | `0` = no caller-imposed buffered limit |
| `PoolCapacity` | `8` | Pool size |
| `MaxConnsPerHost` | `2` | Per-host cap |
| `IdleTimeoutMs` | `30000` | Idle reclaim |
| `EnableHttp11Pipeline` | `false` | HTTP/1.1 pipeline switch |
| `Http11PipelineMaxDepth` | `4` | In-flight pipeline depth |
| `Http11PipelineMethodMask` | GET/HEAD/OPTIONS | Method bitmask |
| `Http2KeepAlive` | disabled | See below |
| `Http3` | `Auto` … | **Session includes HTTP/3 config** |
| `Tls` | `DefaultTlsConfig()` | Session default TLS; per-send override possible |
| `Proxy` | disabled | See below |
| `Cache` | `nullptr` | Session RFC 9111 cache; null disables auto-cache |

### Http11 pipeline method mask

`Types.h`: `Http11PipelineMethodGet = 0x1` … `Http11PipelineMethodTrace = 0x100`.  
`DefaultHttp11PipelineMethodMask = Get | Head | Options`.

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

| Field | Notes |
|-------|-------|
| `Enabled` | Enable proxy when `true` |
| `Host` / `HostLength` | Proxy host bytes |
| `Port` | Proxy port |
| `Family` | `Any` / `Ipv4` / `Ipv6` |
| `Authority` / `AuthorityLength` | Proxy authority (e.g. `proxy.example:8080`) for CONNECT / absolute-form |
| `AuthHeader` / `AuthHeaderLength` | Optional `Proxy-Authorization` value (proxy only) |

Notes: `https://` targets use CONNECT; `http://` targets use absolute-form without CONNECT. Pointers must remain valid while used by the session.

## Http2KeepAliveConfig

```cpp
struct Http2KeepAliveConfig final {
    bool Enabled = false;
    ULONG IdleMs = DefaultHttp2KeepAliveIdleMs;             // 30000
    ULONG IntervalMs = DefaultHttp2KeepAliveIntervalMs;     // 30000
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

| Enum | Value | Meaning |
|------|-------|---------|
| `Http3ConnectMode::Auto` | 0 | Default; learn `h3` Alt-Svc from authenticated responses |
| `Http3ConnectMode::Disabled` | 1 | Never use H3 |
| `Http3ConnectMode::Required` | 2 | Require H3; no automatic TCP fallback |
| `Http3RaceMode::DelayedTcpFallback` | 0 | Race window then may fall back |
| `Http3RaceMode::SequentialPreferHttp3` | 1 | Sequential prefer H3 |

See [HTTP/3 & QUIC](../http3-quic.en.md) for behavior.

## TlsConfig (summary)

Full fields: [TLS options](tls-options.en.md). Common session defaults:

| Field | Default |
|-------|---------|
| `MinVersion` | `TlsVersion::Tls12` |
| `MaxVersion` | `TlsVersion::Tls13` |
| `Certificate` | `CertPolicy::Verify` |
| `Store` | `nullptr` |
| `PreferHttp2` | `true` |
| `HandshakeTimeoutMs` | `DefaultTlsHandshakeTimeoutMs` |
| `MaxTls12Renegotiations` | `DefaultMaxTls12Renegotiations` (1) |

## Cache and CacheOptions

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

Assign `Cache*` to `SessionConfig.Cache` or `SendOptions.Cache`.

## Related defaults (`Types.h`)

| Constant | Value |
|----------|-------|
| `DefaultRequestBufferBytes` | 16 KiB |
| `DefaultMaxResponseBytes` | 0 |
| `DefaultPoolCapacity` | 8 |
| `DefaultMaxConnsPerHost` | 2 |
| `DefaultIdleTimeoutMs` | 30000 |
| `DefaultMaxRedirects` | **10** (when `SendOptions.MaxRedirects == 0`) |
| `DefaultHttp2KeepAliveIdleMs` / `IntervalMs` | 30000 |
| `DefaultHttp2KeepAliveAckTimeoutMs` | 5000 |
| `DefaultHttp11PipelineMaxDepth` | 4 |
| `DefaultHttp3RaceWindowMs` | 250 |
| `DefaultHttp3QuicProbeTimeoutMs` | 1500 |
| `DefaultHttp3AltSvcMaxEntries` | 64 |
| `DefaultHttp3AltSvcMaxAgeSec` | 604800 |

## See also

- [API Overview](overview.en.md)
- [Sync HTTP · SendOptions](http-sync.en.md)
- [TLS options](tls-options.en.md)
- [HTTP/3 & QUIC](../http3-quic.en.md)
