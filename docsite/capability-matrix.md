# 能力边界 / Capability Matrix

[English](#english) | 简体中文

> 本页严格依据 `src/KernelHttpLib/` 实际实现编写。KernelHttp 以 Windows kernel 主路径实现协议：传输优先 WSK，密码学优先 CNG/BCrypt（部分算法为内核内自实现软件），不依赖 WinHTTP/WinINet/SChannel。

---

## 简体中文

### 已实现 / 已验证能力

**HTTP/1.1（RFC 9110/9112）**
- 请求体 `Content-Length` 或显式 chunked（构建器自动生成；用户手设 `Transfer-Encoding`/`TE`/`Trailer` 一律 `STATUS_NOT_SUPPORTED`）。
- 响应解析：状态行仅接受 HTTP/1.0、1.1；头行 ≤8 KiB、头段 ≤64 KiB、头数 ≤200；**拒绝 obs-fold 折行**；多个 `Content-Length`、`TE`+`CL` 冲突 → `STATUS_INVALID_NETWORK_RESPONSE`。
- body 框定：Content-Length / chunked / close-delimited；**无 body 状态**：1xx、204、**205**、304，及 HEAD 响应。
- chunked：块数 ≤8192、chunk-size 行 ≤32、严格 chunk 扩展语法校验；trailer 校验并拒绝禁止字段（`Content-Length`/`Transfer-Encoding`/`Host`/`Authorization`/`Proxy-Authorization`/`Cookie`/`Set-Cookie`）。
- `Content-Encoding` 解码：`gzip`（校验 CRC32+ISIZE+头 CRC16）、`deflate`（自动识别 zlib 包装并校验 Adler-32，底层用内核 `RtlDecompressBufferEx`，带运行时探测）、`br`（内置 Brotli）、`compress`（完整 LZW `.Z`）、`identity`；最多 2 级链，反序解码。
- **解压炸弹防护**：绝对上限 16 MiB（`MaxDecodedBytes`），单级膨胀比 ≤64（`MaxDecodeExpansionRatio`）。
- 中间 1xx（除 101）静默吞掉重解析；自动 redirect、keep-alive 连接池复用。

**HTTP/2（RFC 9113 + HPACK RFC 7541）**
- 连接前导 + SETTINGS 交换；客户端发全 6 项 SETTINGS、立即发 ACK 不阻塞等服务端 ACK。
- SETTINGS 校验：`ENABLE_PUSH != 0` 拒绝、窗口/帧大小越界拒绝；缺 ACK 且后续读超时 → GOAWAY `SETTINGS_TIMEOUT`。
- 完整帧矩阵；伪头/流控/连接专属头校验；`:status` 必须先于普通头。
- **CONTINUATION 洪泛防护**：≤64 帧、≤4 空帧（CVE-2024-27316 类）。
- DATA 流控：连接级 WINDOW_UPDATE 阈值为初始窗口一半（32767）；越界 GOAWAY `FLOW_CONTROL_ERROR`。
- 1xx interim 处理（拒绝 `:status 101` 与 interim+END_STREAM）；PUSH_PROMISE 一律协议错误。
- 三模式：TLS-ALPN `h2`、h2c prior knowledge、h2c Upgrade（Upgrade 模式禁请求体、重放 101 后残留字节、用 stream 1）。

**HPACK**：整数续字节 ≤5、Huffman（拒绝 >30 bit 码/EOS/非法 padding）、动态表大小更新仅限块首且 ≤协商值、header-list 大小按 `name+value+32` 计；**编码端对 `authorization`/`cookie`/`proxy-authorization` 强制 Never-Indexed**。

**WebSocket（RFC 6455）**
- ws/wss 握手；`Sec-WebSocket-Accept` **常量时间**比对；**拒绝任何 `Sec-WebSocket-Extensions`**；子协议协商。
- 客户端帧**始终掩码**（每帧新随机键）；收到**被掩码的服务端帧**→协议错误 1002。
- **分片发送**：`kws::SendContinuation` + `SendOptions{FinalFragment}`，自动按帧缓冲分块；跨片增量 UTF-8 校验。
- **接收分片回调**：`ReceiveOptions.OnMessage` 逐消息/分片回调；也可默认聚合完整消息。
- 控制帧：自动 Pong（可关）、单次接收控制帧 ≤100（超限 close 1008）；文本/close payload UTF-8 校验（非法 1007）；超 `MaxMessageBytes` close 1009。
- close 握手：主动（发 close 后等 peer close，3s 超时）与被动（echo 后关）。

**TLS 1.2（RFC 5246）/ 1.3（RFC 8446）**
- 客户端只走单版本路径（1.3 在范围内优先）；**无握手内自动降级**——失败时分类为 `VersionNegotiation` 由上层显式重连 1.2。
- 下游 cipher/group/sig 分「默认启用 / 可选 / 兼容(Legacy)」三档（详见 [TLS 与证书](tls-and-certificates.md)）。默认套件为 ECDHE-RSA/ECDSA 的 AES-GCM 与 ChaCha20-Poly1305 + TLS1.3 三件套；默认群 X25519/P-256/P-384/P-521；默认签名 RSA-PSS/ECDSA/Ed25519。
- TLS1.2 强制 Extended Master Secret、安全重协商指示、CBC 必须 Encrypt-then-MAC，否则失败。
- TLS1.3：HelloRetryRequest（binder 重算）、KeyUpdate（仅在服务端请求时被动 rekey）、NewSessionTicket、record padding、`signature_algorithms_cert`、OCSP stapling 解析。
- 会话恢复绑定 policy 身份 + SNI + ALPN + cipher + 版本（1.2/1.3 各最多 4 条缓存）。
- 记录层：AES-GCM(1.2/1.3)、AES-CBC EtM（MAC 常量时间先验后解）、ChaCha20-Poly1305；序列号溢出保护；多项抗洪泛记录上限。

**证书校验**（在扩展内核栈上运行）
- 链 ≤8；按 DN 精确链接重排；逐链签名验证、有效期、basic constraints/pathLen、KU（keyCertSign）、EKU serverAuth（可选）、Name Constraints、certificatePolicies、信任锚。
- 解析期**拒绝重复扩展与未知 critical 扩展**。
- 主机名：SAN dNSName 通配仅限**单个最左标签**；IP literal **只匹配 iPAddress SAN**；**从不回退 CN**（CN 仅用于 name-constraint）；IDNA/punycode。
- 撤销：纯离线、表驱动（OCSP stapling 由调用方解析入表 + OCSP/CRL 缓存）；`OnlineRequired` 下查不到 → **fail-closed**（`STATUS_TRUST_FAILURE`）。
- SPKI pin：对**已配置 pin 的主机**强校验叶证书 SPKI；未配置 pin 的主机 fail-open。
- mTLS：私钥不入库，经 `TlsClientCredential.Sign` 回调签名。

**密码学**：SHA-1/256/384/512、HMAC、HKDF；AES-GCM（CNG）、**ChaCha20-Poly1305 / AES-CCM / X25519 / X448 / FFDHE2048-8192 为内核内软件实现**；NIST 曲线走 CNG ECDH；签名验证 RSA-PKCS1/RSA-PSS(salt=摘要长)/ECDSA；最小 RSA 模数 2048 位；FFDHE 公钥范围校验；密钥材料统一 `RtlSecureZeroMemory` 清零。

### 重要边界

| 协议 | 当前边界 |
|------|----------|
| HTTP/1.1 | 拒绝用户设置 `Transfer-Encoding`；无 request trailer；无入站 parser/server；无 proxy/CONNECT/TRACE；`Range`/条件请求仅透传；响应先缓冲（无流式上传）；`Expect:100-continue` 带 body 被拒；`br` 仅 Content-Encoding（TE 中 `br` → `STATUS_NOT_SUPPORTED`） |
| HTTP/2 | 单流串行，无多路复用；**不复用 h2 连接**（每请求新建，结束 GOAWAY）；不发 PRIORITY/主动 PING；高层 khttp 不暴露 h2c（仅 `Http2Client`） |
| WebSocket | HTTP/1.1 Upgrade only；无自定义 opening headers；无扩展协商（permessage-deflate 等拒绝）；不支持 RFC 8441；不跟随握手 redirect/401 |
| TLS | 默认不启用 TLS1.2 RSA kx/CBC/renegotiation/SHA-1（需 `CompatibilityExplicit`）；Ed25519 验签为内核内软件实现；Ed448 验签未实现且不主动宣称；不在线抓取 OCSP/CRL；0-RTT 默认关闭 |

### 默认关闭、需显式开启

`TlsPolicy`（须 `Profile=CompatibilityExplicit`）：`EnableTls12RsaKeyExchange`、`EnableTls12Cbc`、`EnableTls12Renegotiation`（仅信令，不真重协商）、`EnableTls12Sha1Signatures`、`EnablePostHandshakeClientAuth`、`RequireRevocationCheck`。TLS1.3 0-RTT：连接选项 `EnableEarlyData`+`EarlyDataReplaySafe`，且需 ticket 通告 `max_early_data_size`。

### 明确非目标

HTTP/3·QUIC、服务端/入站解析、HTTP 代理/CONNECT、管线化、`Expect:100-continue`、流式请求体上传、request trailer、WebSocket permessage-deflate / over HTTP/2、在线 OCSP/CRL 抓取、Ed448 验签。详见 [路线图与非目标](roadmap.md)。

### 关键默认行为

- **Redirect**：301/302 仅 POST→GET；303 除 HEAD 外→GET；307/308 保留方法和 body；跨源清理 `Authorization`/`Cookie`/`Proxy-Authorization`；拒绝 HTTPS→HTTP 降级。**达到最大跳数（默认 10）时不报错，直接返回该 3xx 响应**。
- **Stale 重试**：仅 `GET`/`HEAD`/`OPTIONS`，且复用连接、`ReuseOrCreate`、失败状态属连接关闭族/`STATUS_RETRY`/`STATUS_IO_TIMEOUT` 时，以 `ForceNew` **重试恰好一次**。
- **连接池**：close-delimited 与 101 响应不回池；`NoPool` 从不挤掉活跃连接，`ForceNew`/`ReuseOrCreate` 会驱逐空闲槽。
- **IRQL**：同步 HTTP/WS/TLS/证书路径要求 `PASSIVE_LEVEL`，否则 `STATUS_INVALID_DEVICE_REQUEST`/`STATUS_INVALID_DEVICE_STATE`。

---

## English

This page is grounded in the actual `src/KernelHttpLib/` implementation.

**HTTP/1.1**: Content-Length or builder-generated chunked request bodies (user `Transfer-Encoding`/`TE`/`Trailer` → `STATUS_NOT_SUPPORTED`); response parsing accepts only HTTP/1.0–1.1, header line ≤8 KiB, section ≤64 KiB, ≤200 headers, rejects obs-fold, rejects duplicate Content-Length and TE+CL conflict; no-body for 1xx/204/**205**/304 and HEAD; chunked ≤8192 chunks with strict extension grammar and forbidden-trailer rejection; Content-Encoding gzip (CRC32/ISIZE verified), deflate (zlib autodetect + Adler-32, via kernel `RtlDecompressBufferEx` with runtime probe), br (bundled Brotli), compress (full LZW), identity, up to 2 codings reverse-decoded; **decompression-bomb guards 16 MiB absolute + 64× per-step**; 1xx skipping; redirects; keep-alive pooling.

**HTTP/2**: preface + SETTINGS (all 6 sent, ACK sent immediately, not awaited), SETTINGS validation (ENABLE_PUSH!=0 rejected, window/frame bounds), **CONTINUATION flood guards (64 / 4 empty)**, flow control with half-window WINDOW_UPDATE threshold, 1xx interim handling, PUSH_PROMISE always a protocol error, three modes (TLS-ALPN h2 / h2c prior-knowledge / h2c upgrade — upgrade forbids a body, replays post-101 bytes, uses stream 1). HPACK: continuation-byte ≤5, Huffman (rejects >30-bit codes/EOS/bad padding), table-size-update only at block start, **never-indexed forced for authorization/cookie/proxy-authorization**.

**WebSocket**: handshake with **constant-time** accept comparison, **rejects any Sec-WebSocket-Extensions**, subprotocol negotiation; client frames always masked (masked server frame → 1002); **fragment send (`kws::SendContinuation` + `FinalFragment`)** with incremental cross-fragment UTF-8 validation; **receive-fragment callback (`ReceiveOptions.OnMessage`)** or aggregated whole-message; auto-Pong (toggleable), ≤100 control frames per receive (1008), UTF-8 validation (1007), max-message (1009); active and passive close handshakes.

**TLS 1.2/1.3**: single-version path (no in-handshake fallback — failures classified as `VersionNegotiation` for an explicit caller retry at 1.2); cipher/group/sig split into default / optional / legacy; TLS1.2 enforces EMS + secure-reneg indication + Encrypt-then-MAC for CBC; TLS1.3 HelloRetryRequest, reactive-only KeyUpdate, NewSessionTicket, record padding, `signature_algorithms_cert`, OCSP stapling parse; resumption bound to policy identity + SNI + ALPN + cipher + version. Certificate validation (on an expanded kernel stack): chain ≤8, exact-DN linking, signature/validity/basic-constraints/pathLen/KU/EKU/name-constraints/cert-policies/trust-anchor; rejects duplicate and unknown-critical extensions; hostname match with single-label wildcard, IP literals match iPAddress SAN only, **never falls back to CN**; revocation offline + table-driven, **fail-closed** when required-but-absent; SPKI pinning (fail-open for un-pinned hosts); mTLS via caller `Sign` callback (private key never enters the library). Crypto: ChaCha20-Poly1305/AES-CCM/X25519/X448/FFDHE/Ed25519 verification are in-kernel **software**; min RSA modulus 2048; Ed448 verification is not implemented and is not advertised.

**Boundaries / non-goals**: single-stream HTTP/2 with no connection reuse; no proxy/CONNECT/pipelining/streaming upload/request trailers; WebSocket HTTP/1.1-Upgrade only (no extensions, no RFC 8441); TLS 1.2 RSA-kx/CBC/renegotiation/SHA-1 off by default (`CompatibilityExplicit`); no online OCSP/CRL fetch; 0-RTT off by default; HTTP/3·QUIC and server role out of scope. Redirect exhaustion returns the 3xx response (no error). See [Roadmap](roadmap.md).
