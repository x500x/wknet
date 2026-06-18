# 连接池 / Connection Pool

`engine/ConnectionPool.h`，`KernelHttp::engine`。每个 `KhSession` 拥有一个 `KhConnectionPool`。

[English](#english) | 简体中文

---

## 简体中文

### 结构

- 固定容量数组 `Entries`/`Capacity`，`FAST_MUTEX` 保护；`ActiveCount` 记录在用槽位，`NextConnectionId` 从 1 起分配 ID。
- 每槽 `KhPooledConnection` 缓存完整传输栈：`WskSocket`、`WskTransport`、`ITransport`、`TlsConnection`、可选 `Http2Connection`，以及 `InUse`/`Connected`/`LastUsedTime`/`Key`。
- 从 `KhSessionOptions` 初始化：`ConnectionPoolCapacity`(默认 8)、`MaxConnectionsPerHost`(默认 2)、`IdleTimeoutMilliseconds`(默认 30000)。

### 连接键 `KhConnectionPoolKey`

匹配维度：scheme、host（≤255）、port、address family、min/max TLS 版本、证书策略、证书库指针、客户端凭据、TLS policy、SNI（≤255）、ALPN（≤16）、`AutomaticAlpn`。
- 严格相等：`KhConnectionPoolKeysEqual`（ALPN 精确匹配）
- 自动 ALPN 放宽：`KhConnectionPoolKeysEqualForAutoAlpnAcquire`

> 键包含 TLS 全部安全参数，因此不同 TLS 配置/证书策略的连接不会被错误复用；h2 与 h1 连接通过 ALPN 区分。

### 主要函数

```cpp
NTSTATUS KhConnectionPoolInitialize(pool, capacity, maxPerHost, idleTimeoutMs);
void     KhConnectionPoolShutdown(pool);                       // 关闭全部连接、释放存储
NTSTATUS KhConnectionPoolAcquire(pool, key, policy, &conn, &reused);  // 复用或新建，报告是否复用
void     KhConnectionPoolRelease(pool, conn, reusable);        // 归还；reusable=false 标记销毁
void     KhConnectionPoolClose(pool, conn);                    // 销毁单个连接并释放槽位
```

### 连接策略 `KhConnectionPolicy`

| 策略 | 行为 |
|------|------|
| `ReuseOrCreate` | 命中则复用，否则新建（默认） |
| `ForceNew` | 总是新建一条全新连接 |
| `NoPool` | 完全绕过连接池 |

按请求设置：`khttp::RequestSetConnPolicy` / `KhHttpRequestSetConnectionPolicy`。

### 复用与回收规则

- `MaxConnectionsPerHost` 限制单主机并发连接数。
- `IdleTimeoutMilliseconds` 配合 `LastUsedTime` 做空闲驱逐。
- **不回池**：close-delimited HTTP/1.x 响应、`101 Switching Protocols` 升级响应。
- **HTTP/2**：当前不复用 h2 连接——每请求新建并以 GOAWAY 关闭（设计/性能限制）。
- **Stale 重试**：reused stale 连接失败只对 `GET`/`HEAD`/`OPTIONS` 安全/幂等请求自动 fresh retry；POST/PUT/PATCH/DELETE 不自动重放。

### 调优

```cpp
config.PoolCapacity    = 32;
config.MaxConnsPerHost = 8;
config.IdleTimeoutMs   = 120000;   // 长连接场景延长，减少重连
```

---

## English

Each `KhSession` owns one `KhConnectionPool`: a fixed-capacity array under a `FAST_MUTEX`, with `ActiveCount` and `NextConnectionId` (from 1). Each `KhPooledConnection` caches the full transport stack (WskSocket, WskTransport, ITransport, TlsConnection, optional Http2Connection) plus in-use/connected/last-used/key. Initialized from `KhSessionOptions` (capacity 8, max 2 per host, 30 s idle).

`KhConnectionPoolKey` matches on scheme, host, port, address family, TLS min/max versions, certificate policy/store, client credential, TLS policy, SNI, ALPN, and automatic-ALPN — so connections with different TLS configs are never wrongly reused, and h2/h1 stay separate. Functions: `Initialize`, `Acquire` (reuse or create, reports `reused`), `Release` (optionally mark non-reusable), `Close`, `Shutdown`. Policies: `ReuseOrCreate` (default), `ForceNew`, `NoPool`.

`MaxConnectionsPerHost` caps per-host concurrency; idle eviction via timeout + last-used. Close-delimited and `101` upgrade responses do not return to the pool. HTTP/2 connections are not reused (new connection per request, closed with GOAWAY). Stale reused-connection failures retry fresh only for safe/idempotent GET/HEAD/OPTIONS.
