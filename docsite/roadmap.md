# 路线图与非目标 / Roadmap & Non-Goals

[English](#english) | 简体中文

---

## 简体中文

明确划清边界有助于正确使用。以下为**有意不做**或**延期**的能力，以及未来改进方向。

### 明确的非目标

**HTTP/1.1**
- `Expect: 100-continue`（主动拒绝）
- HTTP 管线化（串行请求/响应，刻意不实现）
- CONNECT / 代理支持
- 流式请求体上传（chunked 一次性编码）
- 发送 request trailer
- 流式响应回调（响应先缓冲再交付）
- `obs-fold` 折行（拒绝而非规范化）

**HTTP/2**
- 多路复用 / 并发流（单流串行模型）
- HTTP/2 连接复用（每请求新建并 GOAWAY 关闭——设计/性能取舍；仅广告 `MAX_CONCURRENT_STREAMS`）
- 发送 PRIORITY 帧（合法地省略）
- 主动 PING 保活
- 高层 khttp 暴露 h2c（仅底层 `Http2Client`）

**WebSocket**
- permessage-deflate（RFC 7692）
- WebSocket over HTTP/2（RFC 8441）
- 自定义 opening handshake headers
- 握手 redirect / 401 跟随
- 接收分片回调式逐帧暴露

**TLS**
- TLS 1.2 renegotiation（仅信令，未实现）
- 在线撤销抓取（OCSP/CRL 网络拉取）——内核态刻意省略，支持静态撤销条目
- 0-RTT / early data（已实现，默认关闭，需显式 replay-safe）

**其它**
- HTTP/3 / QUIC
- HTTP 服务端 / 入站 request parser

### 默认关闭、可显式开启

- TLS 1.2 RSA key exchange / CBC / renegotiation / SHA-1 签名（需 `TlsPolicy` + `CompatibilityExplicit`）
- Post-handshake client auth
- 强制撤销检查
- TLS 1.3 0-RTT

### 未来改进方向（持续）

- 建立独立于调用方容量的**每调用 / 每记录 / 每连接资源硬上限**。
- 热路径减少重复分配（分配复用 / lookaside 式池化）。

> 这些是对**当前公开行为**的描述，便于评估适用性；不代表内部审计细节。能力现状见 [能力边界](capability-matrix.md)。

---

## English

Explicit boundaries help correct usage. The following are intentionally **out of scope** or **deferred**, plus ongoing improvement directions.

**Non-goals.** HTTP/1.1: `Expect: 100-continue` (rejected), pipelining, CONNECT/proxy, streaming upload, request trailers, streaming response callbacks, obs-fold (rejected). HTTP/2: multiplexing/concurrent streams, h2 connection reuse (new connection per request + GOAWAY; `MAX_CONCURRENT_STREAMS` advertised only), PRIORITY frames, proactive PING, h2c at high-level khttp. WebSocket: permessage-deflate (RFC 7692), WebSocket over HTTP/2 (RFC 8441), custom opening headers, handshake redirect/401 following, fragment callbacks. TLS: TLS 1.2 renegotiation (signaling only), online OCSP/CRL fetch (omitted in kernel; static entries supported), 0-RTT (implemented, off by default). Other: HTTP/3·QUIC, server/inbound request parsing.

**Off by default, explicitly enable.** TLS 1.2 RSA kx / CBC / renegotiation / SHA-1 (via `TlsPolicy` + `CompatibilityExplicit`), post-handshake client auth, required revocation check, TLS 1.3 0-RTT.

**Future directions.** Per-call / per-record / per-connection resource hard limits independent of caller capacities; reducing repeated allocations on hot paths (allocation reuse / lookaside pooling).

This describes current public behavior for fit assessment; see [Capability Matrix](capability-matrix.md) for the current state.
