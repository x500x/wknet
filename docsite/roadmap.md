# 路线图与非目标

明确划清边界有助于正确使用。以下为**有意不做**或**延期**的能力，以及未来改进方向。

### 明确的非目标

**HTTP/1.1**
- `Expect: 100-continue`（主动拒绝）
- HTTP 管线化（串行请求/响应，刻意不实现）
- TRACE 方法
- 流式请求体上传（chunked 一次性编码）
- 真流式响应交付（完全不聚合；当前 `OnBody` 提供增量回调，响应仍可聚合）
- `obs-fold` 折行（拒绝而非规范化）

**HTTP/2**
- 发送 PRIORITY 帧（合法地省略）
- 后台自动 PING 保活策略（低层已提供显式 `SendPing`，不默认启动定时器）
- 高层 khttp 暴露 h2c（仅底层 `Http2Client`）

**WebSocket**（注：分片发送 `kws::SendContinuation` 与接收分片回调 `ReceiveOptions.OnMessage` **已支持**）
- permessage-deflate（RFC 7692）
- 高层 `kws` 默认自动选择 WebSocket over HTTP/2（RFC 8441 已支持显式 opt-in，默认仍保持 HTTP/1.1 Upgrade）
- 握手 redirect / 401 跟随

**代理**
- 明文 HTTP over proxy（HTTPS CONNECT 代理隧道已支持高层 Session 显式配置与低层 `HttpsClient` 选项）

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

- 继续扩展协议安全边界上的有界账本，例如更细的超时、取消、帧/控制信令与恶意输入防护；普通 buffered response 默认不设置低位库级总量硬顶。
- 继续减少热路径重复分配，优先复用 Workspace / lookaside / 连接生命周期常驻缓冲。
- 评估 WebSocket over HTTP/2 从显式 opt-in 走向自动选择的 API 与兼容性策略。

> 这些是对**当前公开行为**的描述，便于评估适用性；不代表内部审计细节。能力现状见 [能力边界](capability-matrix.md)。
