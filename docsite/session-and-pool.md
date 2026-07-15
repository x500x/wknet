# 会话与连接池

`Session` 是请求的策略与资源所有者：TLS 默认值、代理、HTTP/2 保活、HTTP/3、连接池配额，以及（可选）RFC 9111 内存缓存都挂在 session 上。单次发送可通过 `SendOptions` 覆盖 TLS、连接策略、重定向上限等，但不另建生命周期。

## Session 默认值（调用方视角）

| 项 | 默认 | 说明 |
|----|------|------|
| `PoolCapacity` | 8 | 池槽上限（硬顶见实现常量） |
| `MaxConnsPerHost` | 2 | 每主机并发连接配额 |
| `IdleTimeoutMs` | 30000 | 空闲驱逐；`0` 表示不按空闲驱逐 |
| `EnableHttp11Pipeline` | false | 需显式开启 |
| `Http2KeepAlive.Enabled` | false | 需显式开启 |
| `Http3.Mode` | **Auto** | 从已认证 Alt-Svc 学习后优先 H3 |
| `Tls` | TLS 1.2–1.3，`CertPolicy::Verify` | 信任锚由 `Tls.Store` 提供 |
| `Proxy.Enabled` | false | 显式配置 Host/Port/Authority/AuthHeader |
| `Cache` | nullptr | 需调用方挂入内存 cache 对象 |

`ResponsePool` 当前仅接受 `NonPaged`；`Paged` 为保留 ABI，创建时拒绝。

## 连接键与配额

池匹配键包含 scheme、host、port、地址族、TLS 版本/策略/证书身份、SNI、ALPN 与代理身份。自动 ALPN 请求可复用握手后已回写协商 ALPN 的同源连接。

**每主机配额**键更粗（scheme+host+port+family，忽略 TLS/ALPN）：超限时先尝试关闭同主机空闲连接，仍超则 `STATUS_INSUFFICIENT_RESOURCES`。

## Acquire / Release

| `ConnPolicy` | 行为 |
|--------------|------|
| `ReuseOrCreate`（默认） | 优先复用；成功且可复用则回池 |
| `ForceNew` | 总是新建；release 时关闭 |
| `NoPool` | 绕过池；**从不挤掉活跃连接**；release 时关闭 |

- HTTP/2：同源连接可按本地/peer 并发上限共享多个 stream 租约。
- HTTP/3：连接池不跨 origin 合并。alternative 仅用于 DNS/UDP；SNI、证书与 `:authority` 仍绑定原 origin。
- 下列响应不回池：close-delimited body、状态 **101**、`Connection: close`、未读完的字节、非 keep-alive 的 HTTP/1.0，以及协议判定不可复用的 H2/H3 连接。
- 空闲驱逐仅在 `IdleTimeoutMs ≠ 0` 时于 acquire 惰性判断（无后台定时器）。

## 安全重试与重定向

**Stale 连接重试**（恰好一次，`ForceNew` 重建）：

- 方法仅限 **`GET` / `HEAD` / `OPTIONS`**
- 失败发生在复用连接上，且策略为 `ReuseOrCreate`
- 状态属于连接关闭族、`STATUS_RETRY` 或 `STATUS_IO_TIMEOUT`
- `POST` / `PUT` / `PATCH` / `DELETE` **从不**自动重放

**HTTP/2 GOAWAY / `REFUSED_STREAM`**：未处理 stream 可返回 `STATUS_RETRY`；高层同样只对安全方法 fresh retry 一次。

**Redirect**（`MaxRedirects` 默认 **10**，可用 `SendFlagDisableAutoRedirect` 关闭）：

- 301/302：仅 POST→GET；303：除 HEAD 外→GET；307/308：保留方法与 body
- 跨源清理 `Authorization` / `Cookie` / `Proxy-Authorization`
- **HTTPS→HTTP 默认拒绝**
- **跳数用尽不报错**，直接返回当前 3xx，由调用方处理 `Location`

## 代理

`ProxyConfig`：`Host` / `Port` / `Family` / `Authority` / `AuthHeader`。

- HTTPS：HTTP/1.1 **CONNECT** 隧道后再 TLS
- 明文 HTTP over proxy：absolute-form request-target，不建 CONNECT
- `Proxy-Authorization` 只来自显式配置的 opaque 值
- 启用代理时，HTTP/3 Auto 不会选用 H3

## HTTP/3 与池的关系

默认 `Http3ConnectMode::Auto`：

1. 没有先验时，首次 HTTPS 使用 TCP TLS
2. 只有通过证书与 TLS 策略校验的响应中的精确 `h3` Alt-Svc 会被缓存
3. 同一安全身份的后续请求可以优先 H3；probe 失败时，仅当请求尚未发送或满足一次安全重放规则才回落 TCP

`Disabled` 关闭学习与使用；`Required` 表示 prior-knowledge，不读取 Alt-Svc，也不自动回落。细节见 [HTTP/3 与 QUIC](http3-quic.md)。
