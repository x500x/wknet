# HTTP/3 与 QUIC 协议指南

HTTP/3 是 HTTPS 的 **主路径候选**（默认 `Auto`）：WSK Datagram + QUIC v1 + TLS 1.3 over QUIC + HTTP/3 + QPACK，不依赖 MsQuic / SChannel / WinHTTP / WinINet。公开请求入口仍是 `wknet::http::Send*`。

配置见 [会话配置](api/session-config.md)；能力边界见 [能力边界](capability-matrix.md)。

## 结论

| 主题 | 行为 |
|------|------|
| 默认模式 | `Http3ConnectMode::Auto`：先 TCP，再从**已认证**响应学习精确 `h3` Alt-Svc |
| `Disabled` | 不学习、不查询、不使用 Alt-Svc；始终 TCP H1/H2 |
| `Required` | prior-knowledge 直接 H3；不读 Alt-Svc；**不**自动回落 TCP |
| 身份边界 | alternative 只改 DNS/UDP；SNI / 证书 / `:authority` 绑原 origin |
| Race / 回落 | 仅在未发送或一次安全重放规则满足时转 TCP；**从不**双提交 |
| 尚未支持 | QUIC v2、0-RTT 应用数据、迁移、多路径、ECN、DPLPMTUD、WebTransport、Datagram、WS over H3 |

```cpp
wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
config.Http3.Mode = wknet::http::Http3ConnectMode::Auto;
config.Http3.Race = wknet::http::Http3RaceMode::DelayedTcpFallback;
config.Http3.RaceWindowMs = 250;          // DelayedTcpFallback 探测窗
config.Http3.QuicProbeTimeoutMs = 1500;   // SequentialPreferHttp3
config.Http3.AltSvcMaxEntries = 64;
config.Http3.AltSvcMaxAgeSec = 604800;
```

## 选用条件

HTTP/3 仅用于 HTTPS origin。在 `Auto` 下，需要同一安全身份的 `h3` Alt-Svc 缓存命中；`Required` 则按 prior-knowledge 直接使用 H3。

以下请求继续走 TCP 上的 HTTP/1.1 或 HTTP/2：明文 HTTP、h2c、HTTP 代理、WebSocket、显式非 HTTP ALPN，以及设置了 `SendOptions.Http2Priority` 的请求。`CertPolicy::NoVerify` 的响应不学习、也不自动使用 Alt-Svc。

## Alt-Svc 与身份

缓存键包含：origin scheme/host/port、effective TLS ServerName、证书策略与 store、TLS policy、client credential、地址族策略。有界 parser 处理 `clear`、`ma=0`、过期、跨主机 alternative、IPv6 literal、`persist`、多 candidate。

连接 alternative 时：

| 维度 | 使用值 |
|------|--------|
| DNS / UDP | alternative host/port |
| SNI + 证书校验 | 原 effective TLS ServerName |
| HTTP `:authority` | 原 origin |
| 连接池合并 | **不**跨 origin 合并 H3 |

因此 alternative 主机不能替换已认证请求身份。

## Race、回落与重放

| Race 模式 | 超时 |
|-----------|------|
| `DelayedTcpFallback`（默认） | `RaceWindowMs`（默认 250）作为 QUIC probe 窗 |
| `SequentialPreferHttp3` | `QuicProbeTimeoutMs`（默认 1500） |

H3 失败后转 TCP 的条件：

1. 请求**可证明尚未发送**，或  
2. 满足**一次**安全重放规则  

**默认可自动重放**：`GET` / `HEAD` / `OPTIONS`，且响应未开始、body 未消费或可 rewind、调用方未禁止重试。  
**默认不重放**：`POST` / `PUT` / `PATCH` / `DELETE` / `CONNECT`。  
请求**不会**同时提交到 H3 与 TCP。

### Alt-Svc broken 状态

- 作用域：candidate + 地址族  
- 网络失败：1–60 s 指数退避  
- 协议 / 证书 / SNI / ALPN 失败：当前 entry 生命周期内禁用 candidate  
- 取消、本地资源不足：**不**污染缓存  
- 网络配置变化：清除 broken 状态  

## 协议与资源边界

- QUIC packet 固定上限 1200 字节。
- 连接、stream、ACK range、sent-packet、CRYPTO/STREAM 稀疏重组、CID、token、command queue、HTTP/3 field section、QPACK 动态表与 blocked bytes、Alt-Svc entry/candidate 均有 NonPaged 硬上限。
- HTTP/3：control/QPACK 关键单向流、SETTINGS、HEADERS/DATA、1xx、HEAD/204/304/CONNECT body 语义、请求/响应 trailer、GOAWAY 与取消；server push 会被拒绝。
- QPACK：static/dynamic table、blocked field section、双向 instruction streams。

日志不暴露 packet/header/body 原文、URL query、密钥/IV/nonce、ticket、Retry/NEW_TOKEN、reset token、完整 CID、完整 origin/alternative authority、证书原文或凭据。

## 尚未支持

当前实现不包含：QUIC **v2**、**0-RTT application data**、主动**迁移**、**多路径**、**ECN**、**DPLPMTUD**、**WebTransport**、QUIC **Datagram**、Extended CONNECT over H3、**WebSocket over HTTP/3**。

TLS 1.3 0-RTT 若在 TLS 层单独开启，也不等于 HTTP/3 应用数据 0-RTT。
