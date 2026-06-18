# 配置项与常量 / Configuration & Constants

[English](#english) | 简体中文

---

## 简体中文

### 高层会话配置 `khttp::SessionConfig`

用 `khttp::DefaultSessionConfig()` 取默认值后按需覆盖：

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `ResponsePool` | `PoolType` | `NonPaged` | 响应缓冲池类型；内核仅 NonPaged |
| `RequestBufferBytes` | `SIZE_T` | 16 KiB | 请求行+头+body 构造缓冲 |
| `MaxResponseBytes` | `SIZE_T` | 1 MiB | 响应上限；0=不限制 |
| `PoolCapacity` | `ULONG` | 8 | 连接池总容量 |
| `MaxConnsPerHost` | `ULONG` | 2 | 单主机最大连接 |
| `IdleTimeoutMs` | `ULONG` | 30000 | 空闲回收时间 |
| `Tls` | `TlsConfig` | 见下 | TLS 子配置 |

### 高层 TLS 配置 `khttp::TlsConfig`（`DefaultTlsConfig()`）

| 字段 | 类型 | 默认 |
|------|------|------|
| `MinVersion` | `TlsVersion` | `Tls12` |
| `MaxVersion` | `TlsVersion` | `Tls13` |
| `Certificate` | `CertPolicy` | `Verify` |
| `Store` | `const tls::CertificateStore*` | `nullptr` |
| `ServerName` / `ServerNameLength` | `const char*` / `SIZE_T` | `nullptr` / 0（SNI） |
| `Alpn` / `AlpnLength` | `const char*` / `SIZE_T` | `nullptr` / 0 |
| `PreferHttp2` | `bool` | `true` |
| `Policy` | `tls::TlsPolicy` | `{}`（ModernDefault） |
| `ClientCredential` | `const tls::TlsClientCredential*` | `nullptr`（mTLS） |
| `HandshakeTimeoutMs` | `ULONG` | 120000 |

### 底层会话配置 `engine::KhSessionOptions`

底层无 Default 工厂，需零初始化后显式设值。比高层多出三项：

| 字段 | 默认 | 说明 |
|------|------|------|
| `MaxResponseHeaders` | 64 | 响应头数量上限（可配置最大 256） |
| `Http2MaxHeaderBlockBytes` | 32 KiB | HTTP/2 头块上限（最大 256 KiB） |
| 其余字段名 | | 同高层语义（`ConnectionPoolCapacity`/`MaxConnectionsPerHost`/`IdleTimeoutMilliseconds`/`RequestBufferBytes`/`MaxResponseBytes`/`ResponsePoolType`/`Tls`） |

### 连接策略与地址族（按请求）

```cpp
khttp::RequestSetConnPolicy(req, khttp::ConnPolicy::ReuseOrCreate); // 复用或新建（默认）
khttp::RequestSetConnPolicy(req, khttp::ConnPolicy::ForceNew);      // 强制新建
khttp::RequestSetConnPolicy(req, khttp::ConnPolicy::NoPool);        // 不进连接池
khttp::RequestSetAddressFamily(req, khttp::AddressFamily::Ipv4);    // Any / Ipv4 / Ipv6
```

### 单次发送覆盖 `khttp::SendOptions`

见 [高层 API](high-level-api.md)：`MaxResponseBytes`、`Flags`、`MaxRedirects`、`OnHeader`/`OnBody`（流式）、`OnComplete`。

### 全局常量（`KernelHttpConfig.h`）

| 名称 | 值 | 含义 |
|------|----|------|
| `KERNEL_HTTP_POOL_TAG` | `'ptHK'` | 全部内核池分配的池标记 |
| `WskProviderCaptureTimeoutMilliseconds` | 3000 | 捕获 WSK provider NPI 超时 |
| `WskOperationTimeoutMilliseconds` | 30000 | WSK 连接/收发默认超时 |
| `WskCloseTimeoutMilliseconds` | 3000 | 关闭 WSK socket 超时 |
| `TlsHandshakeReceiveTimeoutMilliseconds` | 120000 | TLS 握手接收总期限 |
| `KhMinRsaModulusBits` | 2048 | 接受的最小 RSA 模数位数 |
| `KhHttpMaxHeaderLineBytes` | 8192 | 单条 HTTP 头行上限 |
| `KhHttpMaxHeaderBytes` | 65536 | HTTP 头部总大小上限 |
| `KhHttpMaxHeaders` | 200 | HTTP 头数量上限 |
| `KhHttpMaxChunks` | 8192 | chunked body 最大块数 |
| `KhHttpMaxTrailers` | 256 | trailer 字段上限 |
| `KhHttpMaxChunkSizeLineBytes` | 32 | chunk-size 行上限 |
| `KhWsMaxControlFramesPerReceive` | 100 | 单次接收处理控制帧上限（抗洪泛） |
| `KhTlsMaxPostHandshakeMessagesPerRecord` | 8 | 单记录 TLS 握手后消息上限（抗洪泛） |

### 引擎默认常量（`engine/Engine.h`）

`KhDefaultRequestBufferBytes`=16 KiB、`KhDefaultMaxResponseBytes`=1 MiB、`KhDefaultMaxResponseHeaders`=64、`KhMaxConfigurableResponseHeaders`=256、`KhDefaultHttp2MaxHeaderBlockBytes`=32 KiB、`KhMaxHttp2HeaderBlockBytes`=256 KiB、`KhDefaultConnectionPoolCapacity`=8、`KhDefaultConnectionsPerHost`=2、`KhDefaultIdleTimeoutMilliseconds`=30000、`KhDefaultMaxRedirects`=10。

### 性能调优

```cpp
config.PoolCapacity     = 32;            // 高并发增大池
config.MaxConnsPerHost  = 8;
config.IdleTimeoutMs    = 120000;        // 延长空闲超时减少重连
config.MaxResponseBytes = 4*1024*1024;   // 大响应
```

---

## English

Use `khttp::DefaultSessionConfig()` / `DefaultTlsConfig()` / `DefaultSendOptions()` and override fields. The full field tables and default values are in the Chinese section (language-neutral). Highlights: response cap 1 MiB (0 = unlimited), request buffer 16 KiB, pool capacity 8, max 2 connections per host, 30 s idle timeout, TLS 1.2–1.3 with `Verify`, 120 s handshake timeout, ALPN prefers HTTP/2.

The low-level `KhSessionOptions` has **no** Default factory (zero-init and set explicitly) and adds `MaxResponseHeaders` (64, configurable up to 256) and `Http2MaxHeaderBlockBytes` (32 KiB, up to 256 KiB).

Global constants (`KernelHttpConfig.h`) include the pool tag `'ptHK'`, WSK timeouts (3 s capture / 30 s op / 3 s close), TLS handshake deadline 120 s, minimum RSA modulus 2048 bits, and anti-flood/parse limits (max header line 8192, header section 65536, 200 headers, 8192 chunks, 256 trailers, 100 control frames per receive). Engine defaults mirror these in `engine/Engine.h`.
