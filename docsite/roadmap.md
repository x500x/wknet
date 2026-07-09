# 路线图与非目标

明确划清边界有助于正确使用。以下为**有意不做**、**安全拒绝**或**需显式开启**的能力，以及未来改进方向。

### 明确的非目标

**HTTP/1.1**
- 入站 request parser / server role
- `obs-fold` 折行（安全拒绝而非规范化）
- 调用方手写 `Transfer-Encoding` / `TE`（安全拒绝，framing 由库生成）

**HTTP/2**
- server push（客户端 `ENABLE_PUSH=0`，收到 `PUSH_PROMISE` 安全拒绝）

**WebSocket**（注：分片发送 `kws::SendContinuation` 与显式接收分片 `ReceiveOptions.DeliverFragments=true` **已支持**）
- 握手 redirect / 401 / 407 跟随（当前安全拒绝为 `STATUS_NOT_SUPPORTED`；未来若做必须显式 opt-in）

**TLS**
- 在线撤销抓取（OCSP/CRL 网络拉取）——内核态刻意省略，支持静态撤销条目

**其它**
- HTTP/3 / QUIC

### 默认关闭、可显式开启

- TLS 1.2 RSA key exchange / CBC / SHA-1 签名（需 `TlsPolicy` + `CompatibilityExplicit`）
- TLS 1.2 真重协商（服务器 `HelloRequest` 或低层客户端主动发起；需 `CompatibilityExplicit` + `EnableTls12Renegotiation`，次数由 `MaxTls12Renegotiations` 限制）
- Post-handshake client auth
- 强制撤销检查
- TLS 1.3 0-RTT
- `Expect: 100-continue`（`SendFlagExpectContinue` + `ExpectContinueTimeoutMs`）
- HTTP/1.1 pipeline（session `EnableHttp11Pipeline=true`，默认仅 `GET`/`HEAD`/`OPTIONS`，深度和方法 mask 可配置）
- 高层 h2c prior knowledge / Upgrade（`SendOptions.Http2CleartextMode`）
- HTTP/2 后台 PING 保活（session `Http2KeepAlive.Enabled=true`，默认关闭）
- HTTP/2 per-request priority（`SendOptions.Http2Priority` / `KhHttpSendOptions.Http2Priority`）
- WebSocket permessage-deflate（`ConnectConfig.PerMessageDeflate.Enable=true`，默认关闭）

### 未来改进方向（持续）

- 继续扩展协议安全边界上的有界账本，例如更细的超时、取消、帧/控制信令与恶意输入防护；普通 buffered response 默认不设置低位库级总量硬顶。
- 继续减少热路径重复分配，优先复用 Workspace / lookaside / 连接生命周期常驻缓冲。
- 保持明文 HTTP over proxy 的 absolute-form 路径与 HTTPS CONNECT 隧道路径分离，继续审计代理鉴权 opaque 透传边界。

> 这些是对**当前公开行为**的描述，便于评估适用性；不代表内部审计细节。能力现状见 [能力账本](capability-matrix.md)。
