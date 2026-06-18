# 能力边界 / Capability Matrix

[English](#english) | 简体中文

> KernelHttp 以 Windows kernel 主路径实现协议能力：传输层优先 WSK，密码学优先 CNG/BCrypt，不依赖 WinHTTP、WinINet 或 SChannel。**默认启用能力**与**显式兼容能力**分开记录。

---

## 简体中文

### 已实现 / 已验证能力

**HTTP/1.1（RFC 9110/9112）**
- `Content-Length`、显式 chunked 请求体、响应 `Transfer-Encoding` 链（`chunked`/`gzip`/`deflate`/`compress`，最多 4 级）
- `Content-Encoding` 解码：`gzip`/`deflate`/`br`（Brotli）/`compress`（LZW）/`identity`，带解压上限
- close-delimited 响应、HEAD/101/无 body 状态码、中间 1xx 跳过
- chunked trailer 语法/禁止字段校验 + 只读 trailer API
- 自动 redirect：301/302/303/307/308，跨源清理敏感头、拒绝 HTTPS→HTTP 降级（默认 10 跳）
- keep-alive 连接池复用

**HTTP/2（RFC 9113 + HPACK RFC 7541）**
- 连接前导、SETTINGS 交换、完整帧矩阵（DATA、HEADERS/CONTINUATION、RST_STREAM、SETTINGS、PING ACK、GOAWAY、WINDOW_UPDATE）
- 完整 HPACK（Huffman + 动态表）、伪头与流控校验
- 三种传输模式：TLS-ALPN `h2`、h2c prior knowledge、h2c Upgrade

**WebSocket（RFC 6455）**
- ws/wss 握手校验（Sec-WebSocket-Accept、子协议协商）
- 客户端帧掩码、分片状态机、控制帧 + 自动 Pong、UTF-8 校验、close 握手

**TLS 1.2（RFC 5246）/ 1.3（RFC 8446）**
- 完整握手与会话恢复（Session ID + Session Ticket）；TLS 1.3 含 HelloRetryRequest、KeyUpdate、NewSessionTicket
- AEAD：AES-GCM、ChaCha20-Poly1305、AES-CCM；TLS 1.2 强制 EMS、安全重协商指示、CBC 的 Encrypt-then-MAC
- X25519 默认 key share；CertificateVerify / Finished 校验
- ALPN 默认 offer `h2, http/1.1`，平滑回退；TLS1.3→1.2 通过重连回退；连接池区分 h2/h1

**证书校验**
- 内核内 X.509 链构建与验证；SAN dNSName/iPAddress 主机匹配（含通配符 RFC 6125）
- EKU/KU、basic constraints、Name Constraints、certificatePolicies
- 调用方注入信任库 + SPKI pin；OCSP stapling 解析；OCSP/CRL 撤销缓存

完整协议详情见 [HTTP/1.1](http1.md)、[HTTP/2](http2.md)、[WebSocket](websocket.md)、[TLS 与证书](tls-and-certificates.md)。

### 能力边界速查表

| 协议 | 已支持 | 当前边界 |
|------|--------|----------|
| HTTP/1.1 | 见上 | 拒绝用户设置请求 `Transfer-Encoding`；无 request trailer；无入站 parser/server；无 proxy/CONNECT/TRACE；`Range`/条件请求仅透传；`br` 仅作 `Content-Encoding`；响应先缓冲再交付（无流式回调上传） |
| HTTP/2 | 见上 | 单流串行模型，无多路复用；不复用 h2 连接（每请求新建并 GOAWAY 关闭）；不发 PRIORITY/主动 PING；高层 khttp 不暴露 h2c（仅底层 `Http2Client`） |
| WebSocket | 见上 | 主路径 HTTP/1.1 Upgrade；无自定义 opening headers、无扩展协商、无接收分片回调；不支持 permessage-deflate、RFC 8441 |
| TLS | 见上 | 默认策略不启用 TLS 1.2 RSA kx / CBC / renegotiation / SHA-1 签名（需 `CompatibilityExplicit`）；不在线抓取 OCSP/CRL；0-RTT 默认关闭 |

### 默认关闭、需显式开启的能力

| 能力 | 启用方式 |
|------|----------|
| TLS 1.2 RSA key exchange | `TlsPolicy::EnableTls12RsaKeyExchange = true`（+ `CompatibilityExplicit`） |
| TLS 1.2 CBC | `TlsPolicy::EnableTls12Cbc = true` |
| TLS 1.2 renegotiation | `TlsPolicy::EnableTls12Renegotiation = true` |
| TLS 1.2 SHA-1 签名 | `TlsPolicy::EnableTls12Sha1Signatures = true` |
| Post-handshake client auth | `TlsPolicy::EnablePostHandshakeClientAuth = true` |
| 强制撤销检查 | `TlsPolicy::RequireRevocationCheck = true` |
| TLS 1.3 0-RTT | 连接选项 `EnableEarlyData = true` 且 `EarlyDataReplaySafe = true` |

### 明确的非目标

HTTP/3·QUIC、HTTP 服务端/入站解析、HTTP 代理/CONNECT、HTTP 管线化、`Expect: 100-continue`、流式请求体上传、request trailer、WebSocket permessage-deflate / over HTTP/2、在线 OCSP/CRL 抓取。详见 [路线图与非目标](roadmap.md)。

### 关键默认行为

- **Redirect**：拒绝 HTTPS→HTTP 降级；跨 scheme/host/port 清理 `Authorization`/`Cookie`/`Proxy-Authorization`；301/302 把 POST→GET，303 除 HEAD 外→GET，307/308 保留方法和 body。
- **Stale 重试**：reused stale 连接失败只对 `GET`/`HEAD`/`OPTIONS` 自动 fresh retry；POST/PUT/PATCH/DELETE 不自动重放。
- **连接池**：close-delimited 与 `101` 升级响应不回到普通连接池。
- **IRQL**：同步 HTTP、WebSocket、TLS、证书验证路径要求 `PASSIVE_LEVEL`。
- **TLS 版本协商**：ALPN 必须来自 client offer；TLS1.2 选择需 TLS1.3 路径取得可验证版本协商证据后才允许。
- **证书主机校验**：IP literal 只匹配 iPAddress SAN，不回退 dNSName/CN。

---

## English

### Implemented / verified

- **HTTP/1.1**: Content-Length, explicit chunked bodies, response `Transfer-Encoding` chains (chunked/gzip/deflate/compress, up to 4), `Content-Encoding` decode (gzip/deflate/br/compress/identity), close-delimited responses, 1xx skipping, chunked trailers, redirects (301/302/303/307/308 with sensitive-header stripping and HTTPS→HTTP downgrade rejection, 10-hop default), keep-alive pooling.
- **HTTP/2**: preface + SETTINGS, full frame matrix, complete HPACK (Huffman + dynamic table), pseudo-header & flow-control validation, modes TLS-ALPN h2 / h2c prior-knowledge / h2c upgrade.
- **WebSocket**: handshake validation, client masking, fragmentation state machine, control frames + auto-Pong, UTF-8 validation, close handshake, ws & wss.
- **TLS 1.2/1.3**: full handshake + resumption, AEAD suites (AES-GCM/ChaCha20-Poly1305/AES-CCM), EMS + secure-reneg indication + Encrypt-then-MAC for CBC, HelloRetryRequest, KeyUpdate, NewSessionTicket, X25519 default, ALPN with fallback.
- **Certificate validation**: in-kernel X.509 chain build/verify, SAN dNSName/iPAddress + wildcards, EKU/KU/basic-constraints/name-constraints/certificate-policies, injected trust store + SPKI pinning, OCSP stapling parse, OCSP/CRL cache.

### Boundaries

- HTTP/1.1: rejects user `Transfer-Encoding`; no request trailers; no server role; no proxy/CONNECT/TRACE; `Range`/conditional pass-through only; `br` only as Content-Encoding; responses buffered (no streaming upload).
- HTTP/2: single-stream serial; no multiplexing; no h2 connection reuse (new connection per request, closed with GOAWAY); no PRIORITY/proactive PING; h2c only via low-level `Http2Client`.
- WebSocket: HTTP/1.1 Upgrade only; no custom opening headers / extension negotiation / fragment callbacks; no permessage-deflate or RFC 8441.
- TLS: default policy disables TLS 1.2 RSA kx / CBC / renegotiation / SHA-1 (need `CompatibilityExplicit`); no online OCSP/CRL fetch; 0-RTT off by default.

### Off-by-default switches

TLS 1.2 RSA kx / CBC / renegotiation / SHA-1 signatures, post-handshake client auth, required revocation check — all via `TlsPolicy` flags with `CompatibilityExplicit`. TLS 1.3 0-RTT via `EnableEarlyData` + `EarlyDataReplaySafe`.

### Non-goals

HTTP/3·QUIC, server role, HTTP proxy/CONNECT, pipelining, `Expect: 100-continue`, streaming upload, request trailers, WebSocket permessage-deflate / over HTTP/2, online OCSP/CRL fetch. See [Roadmap](roadmap.md).
