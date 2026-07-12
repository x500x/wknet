# 配置项与常量

### 高层会话配置 `wknet::http::SessionConfig`

用 `wknet::http::DefaultSessionConfig()` 取默认值后按需覆盖：

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `ResponsePool` | `PoolType` | `NonPaged` | 响应缓冲池类型；内核仅 NonPaged |
| `RequestBufferBytes` | `SIZE_T` | 16 KiB | 请求行+头+body 构造缓冲 |
| `MaxResponseBytes` | `SIZE_T` | 0 | 响应聚合上限；0=不限制，按需使用堆内存增长 |
| `PoolCapacity` | `ULONG` | 8 | 连接池总容量 |
| `MaxConnsPerHost` | `ULONG` | 2 | 单主机最大连接 |
| `IdleTimeoutMs` | `ULONG` | 30000 | 空闲回收时间 |
| `EnableHttp11Pipeline` | `bool` | false | HTTP/1.1 pipeline 显式开关；默认关闭 |
| `Http11PipelineMaxDepth` | `ULONG` | 4 | 单条 HTTP/1.1 pipeline 最大在途深度，硬上限 64 |
| `Http11PipelineMethodMask` | `ULONG` | GET/HEAD/OPTIONS | pipeline 允许的方法 mask；默认仅安全方法 |
| `Http2KeepAlive` | `Http2KeepAliveConfig` | disabled | HTTP/2 池化连接后台 PING 保活；`Enabled=true` 显式开启，`IdleMs`/`IntervalMs` 默认 30000，`AckTimeoutMs` 默认 5000 |
| `Tls` | `TlsConfig` | 见下 | TLS 子配置 |
| `Proxy` | `ProxyConfig` | disabled | 显式 HTTP 代理配置；HTTPS 使用 CONNECT，明文 HTTP 使用 absolute-form |

### 高层 TLS 配置 `wknet::http::TlsConfig`（`DefaultTlsConfig()`）

| 字段 | 类型 | 默认 |
|------|------|------|
| `MinVersion` | `TlsVersion` | `Tls12` |
| `MaxVersion` | `TlsVersion` | `Tls13` |
| `Certificate` | `CertPolicy` | `Verify` |
| `Store` | `const wknet::http::CertificateStore*` | `nullptr` |
| `ServerName` / `ServerNameLength` | `const char*` / `SIZE_T` | `nullptr` / 0（SNI） |
| `Alpn` / `AlpnLength` | `const char*` / `SIZE_T` | `nullptr` / 0 |
| `PreferHttp2` | `bool` | `true` |
| `Policy` | `tls::TlsPolicy` | `{}`（ModernDefault） |
| `ClientCredential` | `const wknet::http::TlsClientCredential*` | `nullptr`（mTLS） |
| `HandshakeTimeoutMs` | `ULONG` | 120000 |

### 内部会话配置

底层无 Default 工厂，需零初始化后显式设值。比高层多出三项：

| 字段 | 默认 | 说明 |
|------|------|------|
| `MaxResponseHeaders` | 64 | 响应头数量上限（可配置最大 200） |
| `Http2MaxHeaderBlockBytes` | 32 KiB | HTTP/2 头块上限（最大 64 KiB） |
| 其余字段名 | | 同高层语义（`ConnectionPoolCapacity`/`MaxConnectionsPerHost`/`IdleTimeoutMilliseconds`/`RequestBufferBytes`/`MaxResponseBytes`/`ResponsePoolType`/`EnableHttp11Pipeline`/`Http11PipelineMaxDepth`/`Http11PipelineMethodMask`/`Http2KeepAlive`/`Tls`/`Proxy`） |

### 连接策略与地址族（单次发送）

```cpp
wknet::http::SendOptions* options = nullptr;
wknet::http::SendOptionsCreate(&options);
options->ConnectionPolicy = wknet::http::ConnPolicy::ReuseOrCreate; // 复用或新建（默认）
options->ConnectionPolicy = wknet::http::ConnPolicy::ForceNew;      // 强制新建
options->ConnectionPolicy = wknet::http::ConnPolicy::NoPool;        // 不进连接池
options->Family = wknet::http::AddressFamily::Ipv4;                 // Any / Ipv4 / Ipv6
wknet::http::SendOptionsRelease(options);
```

### 单次发送覆盖 `wknet::http::SendOptions`

见 [高层 API](high-level-api.md)：`MaxResponseBytes`、`Flags`、`MaxRedirects`、`OnHeader`/`OnBody`（流式）、TLS 覆盖、连接策略、地址族、h2c 显式模式与 HTTP/2 per-request priority。HTTP/1.1 pipeline 是 session 级策略，不在单次发送选项中。异步完成回调在 `AsyncOptions` 中。

### 全局常量（`WknetConfig.h`）

| 名称 | 值 | 含义 |
|------|----|------|
| `WKNET_POOL_TAG` | `'tenW'` | 全部内核池分配的池标记 |
| `WskProviderCaptureTimeoutMilliseconds` | 3000 | 捕获 WSK provider NPI 超时 |
| `WskOperationTimeoutMilliseconds` | 30000 | WSK 连接/收发默认超时 |
| `WskCloseTimeoutMilliseconds` | 3000 | 关闭 WSK socket 超时 |
| `TlsHandshakeReceiveTimeoutMilliseconds` | 120000 | TLS 握手接收总期限 |
| `MinRsaModulusBits` | 2048 | 接受的最小 RSA 模数位数 |
| `HttpMaxHeaderLineBytes` | 8192 | 单条 HTTP 头行上限 |
| `WKNET_HARD_MAX_HEADER_SECTION` | 65536 | HTTP 头部总大小上限 |
| `WKNET_HARD_MAX_HEADERS` | 200 | HTTP 头数量上限 |
| `HttpMaxChunks` | 8192 | chunked body 最大块数 |
| `HttpMaxTrailers` | 256 | trailer 字段上限 |
| `HttpMaxChunkSizeLineBytes` | 32 | chunk-size 行上限 |
| `WsMaxControlFramesPerReceive` | 100 | 单次接收处理控制帧上限 |
| `TlsMaxPostHandshakeMessagesPerRecord` | 8 | 单记录 TLS 握手后消息上限 |

### 会话默认常量

公共默认值定义于 `wknet::http::Types.h`：请求缓冲 16 KiB、`MaxResponseBytes=0`（调用方不设聚合上限）、WebSocket 消息 1 MiB、连接池容量 8、每主机 2、空闲 30000ms、pipeline 深度 4、HTTP/2 keepalive idle/interval 30000ms、ACK timeout 5000ms、最大重定向 10。

### 其它实测限制

- 异步：内部工作线程 4、队列深度 256。
- 解压：decoded aggregate 跟随响应/调用方容量，单级膨胀比 ≤64。
- 请求头：每请求 ≤16 头、名 ≤128、值 ≤512；URL path ≤8000、host ≤255、scheme ≤5、ALPN ≤16。
- **redirect 达最大跳数（默认 10）不报错，直接返回该 3xx 响应**。

### 性能调优

```cpp
config.PoolCapacity     = 32;            // 高并发增大池
config.MaxConnsPerHost  = 8;
config.IdleTimeoutMs    = 120000;        // 延长空闲超时减少重连
config.EnableHttp11Pipeline = true;      // 显式开启 HTTP/1.1 pipeline
config.MaxResponseBytes = 4*1024*1024;   // 大响应
config.Proxy.Enabled    = true;          // HTTP 代理：HTTPS CONNECT，明文 HTTP absolute-form
```
