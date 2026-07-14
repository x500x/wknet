# HTTP/3 与 QUIC

wknet 的 HTTP/3 客户端主路径由 WSK Datagram、QUIC v1、TLS 1.3 over QUIC、HTTP/3 和 QPACK 组成，不依赖 MsQuic、SChannel、WinHTTP 或 WinINet。公开请求入口仍是 `wknet::http::Send*`。

## 连接模式

`SessionConfig.Http3.Mode` 支持三种模式：

- `Auto`：默认模式。首次没有先验的 HTTPS 请求使用 TCP TLS；只有已完成证书和 TLS 策略验证的响应中的精确 `h3` Alt-Svc 才会被缓存。后续同一安全身份的请求可优先使用 H3。
- `Disabled`：不学习、不查询、不使用 Alt-Svc，始终保留现有 TCP HTTP/1.1 或 HTTP/2 路径。
- `Required`：直接要求 HTTPS origin 使用 H3，适用于明确 prior-knowledge。它不读取 Alt-Svc，也不会自动回落 TCP。

```cpp
wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
config.Http3.Mode = wknet::http::Http3ConnectMode::Auto;
config.Http3.Race = wknet::http::Http3RaceMode::DelayedTcpFallback;
config.Http3.RaceWindowMs = 250;
config.Http3.QuicProbeTimeoutMs = 1500;
config.Http3.AltSvcMaxEntries = 64;
config.Http3.AltSvcMaxAgeSec = 604800;
```

明文 HTTP、h2c、HTTP proxy、WebSocket、显式非 HTTP ALPN 和 `SendOptions.Http2Priority` 不进入 H3。`CertPolicy::NoVerify` 响应默认不学习或自动使用 Alt-Svc。

## Alt-Svc 与身份边界

缓存键包含 origin scheme/host/port、effective TLS ServerName、证书策略与 store、TLS policy、client credential 和地址族策略。`clear`、`ma=0`、过期、跨主机 alternative、IPv6 literal、`persist` 和多 candidate 均按有界 parser 处理。

连接 alternative endpoint 时：

- DNS/UDP 使用 alternative host/port；
- SNI 与证书校验继续使用原 effective TLS ServerName；
- HTTP `:authority` 继续使用原 origin；
- 连接池不跨 origin 合并 H3 连接。

因此 alternative 主机不能改变请求的认证身份。

## 回落与重放

`DelayedTcpFallback` 使用 `RaceWindowMs` 控制 QUIC probe 窗口；`SequentialPreferHttp3` 使用独立的 `QuicProbeTimeoutMs`。H3 失败时，只有请求仍可证明未发送，或符合一次安全重放规则，才允许转到 TCP。

默认可自动重放的方法是 `GET`、`HEAD` 和 `OPTIONS`，并且要求响应尚未开始、body 未消费或能够明确 rewind、调用方未禁止重试。`POST`、`PUT`、`PATCH`、`DELETE` 和 `CONNECT` 默认不自动重放。请求不会同时提交到 H3 和 TCP。

Alt-Svc broken 状态绑定 candidate 与地址族：网络失败采用 1–60 秒指数退避；协议、证书、SNI 或 ALPN 失败在当前 entry 生命周期内禁用 candidate；取消和本地资源不足不污染缓存。网络配置变化会清除 broken 状态。

## 资源与安全边界

QUIC packet 固定不超过 1200 字节。连接、stream、ACK range、sent-packet metadata、CRYPTO/STREAM 稀疏重组、CID、token、command queue、HTTP/3 field section、QPACK dynamic table、blocked streams/bytes、Alt-Svc entry/candidate 均有 NonPaged 硬上限和故障注入测试。

日志不会记录 packet/header/body 原文、URL query、密钥、IV、nonce、ticket、Retry/NEW_TOKEN、reset token、完整 CID、完整 origin/alternative authority、证书原文或凭据。

关键诊断事件包括：

- `quic.connection.*`、`quic.handshake.*`、`quic.loss.detected`、`quic.pto.fired`
- `http3.connection.*`、`http3.stream.*`、`qpack.*`
- `http.altsvc.stored/cleared/expired/rejected/broken`
- `http.protocol.select`、`http.connection.retry`、`http.request.failed`

## 当前非目标

当前主路径不实现 QUIC v2、0-RTT application data、主动迁移、多路径、ECN、DPLPMTUD、WebTransport、QUIC Datagram、Extended CONNECT over H3 或 WebSocket over HTTP/3。

