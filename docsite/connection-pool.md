# 连接池

### 结构与默认

- 数组 `Entries`/`Capacity`；每槽 `PooledConnection` 缓存完整传输栈（`WskSocket`/`WskTransport`/`ITransport`/`TlsConnection`/可选 `Http2Connection`），并记录 HTTP/2 stream 租约计数。
- 默认容量 8、最大 1024（`session::MaxConnectionPoolCapacity`）、每主机 2、空闲 30000ms。

### 连接键匹配

`ConnectionPoolKeysEqual` 比较 scheme、host、port、地址族、TLS 版本、证书身份、完整策略、SNI、ALPN 和代理身份。自动 ALPN 请求可复用握手后已回写协商 ALPN 的同源连接。

### Acquire / Release / 重试

- `ConnectionPoolAcquire`：`ForceNew`/`NoPool` 跳过普通复用扫描；否则优先取 connected、空闲、键匹配的槽。HTTP/2 stream 租约未达上限时可共享活动连接。
- **每主机配额**键更粗（仅 scheme+host+port+family，忽略 TLS/ALPN）：超限先尝试关一个同主机空闲连接，仍超 → `STATUS_INSUFFICIENT_RESOURCES`。
- 新槽优先空槽；无空槽且策略≠`NoPool` 时驱逐任一非在用槽。**`NoPool` 从不挤掉活跃连接**。
- **可回池条件**（`canReturnToPool`）：成功 + 连接可复用 + 策略 `ReuseOrCreate`。故 `ForceNew`/`NoPool` 连接 release 时总是关闭。
- **可复用判定**：状态 101、`BodyEndsOnConnectionClose`、`Connection: close`、字节未吃完、major≠1 → 不可复用（**close-delimited 与 101 永不回池**）。HTTP/1.0 须显式 keep-alive；HTTP/2 由 `Http2Connection::IsReusable()` 与 stream 租约账本决定，可在同源连接上承载多个活动 stream。
- **空闲驱逐**：仅 `IdleTimeoutMilliseconds≠0`，在 acquire 时惰性判断（无定时器）。
- **Stale fresh retry**：失败 + 复用连接 + `ReuseOrCreate` + 方法 ∈ {GET,HEAD,OPTIONS} + 状态 ∈ {连接关闭族, `STATUS_RETRY`, `STATUS_IO_TIMEOUT`} 时，关旧连接、以 `ForceNew` 重建请求**重试恰好一次**。POST/PUT/PATCH/DELETE 从不自动重放。

### 策略

| `wknet::http::ConnPolicy` | 行为 |
|------|------|
| `ReuseOrCreate` | 复用或新建（默认）；可回池 |
| `ForceNew` | 总是新建；release 时关闭 |
| `NoPool` | 绕过池；不挤占活跃连接；release 时关闭 |

单次发送通过 `wknet::http::SendOptions::ConnectionPolicy` 设置；请求对象也可用 `RequestSetConnPolicy` 设置默认值。
