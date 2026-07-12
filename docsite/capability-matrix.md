# 能力账本

### 已实现 / 已验证能力

**HTTP/1.1（RFC 9110/9112）**
- 请求体支持 `Content-Length`、库生成 chunked 与真流式上传：高层 `BodyCreateStream` / 底层 `KhHttpRequestSetBodySource` 按块读取；用户手设 `Transfer-Encoding`/`TE` 仍安全拒绝；`Trailer` 头仅在 chunked 请求 trailer 场景允许。
- 请求 trailer：`KhHttpRequestAddTrailer` / `wknet::http::RequestAddTrailer` 在 `Chunked` body 模式下发送终止块后的 trailer 字段，并拒绝禁止字段与 CRLF 注入。
- 响应解析：状态行仅接受 HTTP/1.0、1.1；头行 ≤8 KiB、头段 ≤64 KiB、头数 ≤200；**拒绝 obs-fold 折行**；多个 `Content-Length`、`TE`+`CL` 冲突 → `STATUS_INVALID_NETWORK_RESPONSE`。
- body 框定：Content-Length / chunked / close-delimited；**无 body 状态**：1xx、204、**205**、304，及 HEAD 响应。
- chunked：块数 ≤8192、chunk-size 行 ≤32、严格 chunk 扩展语法校验；trailer 校验并拒绝禁止字段（`Content-Length`/`Transfer-Encoding`/`Host`/`Authorization`/`Proxy-Authorization`/`Cookie`/`Set-Cookie`）。
- `206 Partial Content` / `Content-Range` 提供只读解析（`HttpResponse::IsPartialContent` / `GetContentRange`）；请求侧提供 `Range` 与条件请求 typed helper。绑定 RFC 9111 cache 后，Range 请求与 `206` 响应参与自动验证、切片命中和 partial 合并。
- `Content-Encoding`：`gzip`、`deflate`、`br`、`compress`、`zstd`、`dcz`、`aes128gcm`、`exi`、`pack200-gzip`、`identity`；最多 2 级，反序解码。EXI 支持无外部 Schema 的四种 alignment、Options、保真项、内建类型和 `xsi:type`/`xsi:nil`；Pack200 支持 Java 5–8 稳定格式及 JAR 语义重建。外部 Schema/strict EXI 返回 `STATUS_NOT_SUPPORTED`。
- `Accept-Encoding`：默认自动发送 `gzip, deflate, br, zstd, identity`（deflate 运行时不可用则 `br, identity`）；typed preferences 支持 qvalue、`identity;q=0`、`*;q=0`、重复项拒绝，并驱动响应 `Content-Encoding` fail-closed 校验。
- **解压炸弹防护**：decoded aggregate 跟随响应/调用方容量，单级膨胀比 ≤64（`MaxDecodeExpansionRatio`）。
- 中间 1xx（除 101）静默吞掉重解析；`SendFlagExpectContinue` 显式开启 `Expect: 100-continue`，覆盖 100 后发送 body、final/417 不发送 body、超时后发送 body 与断连错误；自动 redirect、keep-alive 连接池复用。
- HTTP proxy：HTTPS 走 CONNECT 隧道；明文 HTTP over proxy 使用 absolute-form request target，`Proxy-Authorization` 只来自显式代理配置。
- HTTP/1.1 pipeline：session `EnableHttp11Pipeline=true` 显式开启，默认关闭；连接池按 FIFO 绑定响应，默认仅允许 `GET`/`HEAD`/`OPTIONS`，深度和方法 mask 可配置；带 body、`Expect:100-continue`、redirect 重放/重排不进入 pipeline。

**HTTP/2（RFC 9113 + HPACK RFC 7541）**
- 连接前导 + SETTINGS 交换；客户端发 7 项 SETTINGS（含 `ENABLE_CONNECT_PROTOCOL`）、立即发 ACK 不阻塞等服务端 ACK。
- SETTINGS 校验：`ENABLE_PUSH != 0` 拒绝、`ENABLE_CONNECT_PROTOCOL` 仅接受 0/1、窗口/帧大小越界拒绝；缺 ACK 且后续读超时 → GOAWAY `SETTINGS_TIMEOUT`。
- 完整帧矩阵；伪头/流控/连接专属头校验；`:status` 必须先于普通头。
- **CONTINUATION 洪泛防护**：≤64 帧、≤4 空帧（CVE-2024-27316 类）。
- 活动 stream 表 + `BeginRequest` / `ReceiveResponse(streamId)` 两阶段接口；HEADERS/DATA/WINDOW_UPDATE/RST_STREAM 按 streamId 交错分发。
- 高层 `khttp` 连接池接入 HTTP/2 stream 租约，同源 H2 连接可按本地/peer 并发上限承载多个活动请求；连接级错误广播给活动流。
- DATA 流控：连接级 + per-stream 窗口；连接级 WINDOW_UPDATE 阈值为初始窗口一半（32767）；初始窗口 SETTINGS 更新会同步调整活动 stream；越界 GOAWAY `FLOW_CONTROL_ERROR`。
- 1xx interim 处理（拒绝 `:status 101` 与 interim+END_STREAM）；PUSH_PROMISE 一律协议错误。
- RFC 8441 extended CONNECT：`CONNECT` + `:protocol: websocket` 需对端 `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`；低层 `SendStreamData` / `ReceiveStreamData` 可承载 WebSocket frame bytes，高层 `kws` 对 `wss` 默认自动选择该路径，必要时可用 `Http11Only` 强制 HTTP/1.1。
- 三模式：TLS-ALPN `h2`、显式 h2c prior knowledge、显式 h2c Upgrade（Upgrade 模式禁请求体、重放 101 后残留字节、用 stream 1）；高层通过 `SendOptions.Http2CleartextMode` opt-in，默认 HTTP/1.1。
- HTTP/2 请求 body 由 body source 驱动，按连接/stream 流控和 peer `MAX_FRAME_SIZE` 切 DATA；请求 trailers 以 final HEADERS + END_STREAM 发送并拒绝 trailer 伪头。
- 显式 per-request priority：`SendOptions.Http2Priority` / `KhHttpSendOptions.Http2Priority` 可在首个 HEADERS 帧携带 priority 字段；底层支持独立 PRIORITY frame 编解码，收到 peer PRIORITY 只校验语义，不改变安全边界。
- 后台 PING 保活：session 通过 `Http2KeepAlive.Enabled=true` 显式开启，默认关闭；只扫描 idle 且可复用的池化 H2 连接，ACK 超时或协议错误会关闭该 idle 连接。
- GOAWAY/RST 高层重试语义：clean GOAWAY 或 `REFUSED_STREAM` 表示未处理 stream 时返回 `STATUS_RETRY`，高层只对安全方法 fresh retry 一次，非幂等请求不自动重放。

**HPACK**：整数续字节 ≤5、Huffman（拒绝 >30 bit 码/EOS/非法 padding）、动态表大小更新仅限块首且 ≤协商值、header-list 大小按 `name+value+32` 计；**编码端对 `authorization`/`cookie`/`proxy-authorization` 强制 Never-Indexed**。

**WebSocket（RFC 6455）**
- ws/wss 握手；`Sec-WebSocket-Accept` **常量时间**比对；`permessage-deflate` 显式 opt-in（默认关闭），未请求/未知/非法扩展拒绝；子协议协商。
- 支持调用方提供 opening-handshake headers（如 `Origin`、`Authorization`、`Cookie`），拒绝库受控头（`Host`、`Connection`、`Upgrade`、`Sec-WebSocket-*` 等）和非法头文本。
- HTTP/1.1 Upgrade 路径客户端帧**始终掩码**（每帧新随机键）；RFC 8441 over HTTP/2 路径按规范发送无掩码帧；收到**被掩码的服务端帧**→协议错误 1002。
- `wss` 默认自动 offer `h2,http/1.1` 并在协商到 h2 时使用 RFC 8441；peer 未启用 `SETTINGS_ENABLE_CONNECT_PROTOCOL` 时按 Auto 规则回到 HTTP/1.1，`ws://` 不隐式走 h2c。
- **分片发送**：`wknet::websocket::SendContinuation` + `SendOptions{FinalFragment}`，自动按帧缓冲分块；跨片增量 UTF-8 校验。
- **接收分片回调**：默认聚合完整消息；显式 `ReceiveOptions.DeliverFragments=true` 时，`ReceiveOptions.OnMessage` 或返回式按 wire fragment 交付并暴露真实 `finalFragment`。
- 控制帧：自动 Pong（可关）、单次接收控制帧 ≤100（超限 close 1008）；文本/close payload UTF-8 校验（非法 1007）；超 `MaxMessageBytes` close 1009。
- close 握手：主动（发 close 后等 peer close，3s 超时）与被动（echo 后关）。

**TLS 1.2（RFC 5246）/ 1.3（RFC 8446）**
- 客户端只走单版本路径（1.3 在范围内优先）；**无握手内自动降级**——失败时分类为 `VersionNegotiation` 由上层显式重连 1.2。
- 下游 cipher/group/sig 分「默认启用 / 可选 / 兼容(Legacy)」三档（详见 [TLS 与证书](tls-and-certificates.md)）。默认套件为 ECDHE-RSA/ECDSA 的 AES-GCM 与 ChaCha20-Poly1305 + TLS1.3 三件套；默认群 X25519/P-256/P-384/P-521；默认签名 RSA-PSS/ECDSA/Ed25519/Ed448。
- TLS1.2 强制 Extended Master Secret、安全重协商指示、CBC 必须 Encrypt-then-MAC，否则失败。
- TLS1.3：HelloRetryRequest（binder 重算）、KeyUpdate（仅在服务端请求时被动 rekey）、NewSessionTicket、record padding、`signature_algorithms_cert`、OCSP stapling 解析。
- 会话恢复绑定 policy 身份 + SNI + ALPN + cipher + 版本（1.2/1.3 各最多 4 条缓存）。
- 记录层：AES-GCM(1.2/1.3)、AES-CBC EtM（MAC 常量时间先验后解）、ChaCha20-Poly1305；序列号溢出保护；多项抗洪泛记录上限。

**证书校验**（在扩展内核栈上运行）
- 链 ≤8；有界候选路径搜索按 subject/issuer、AKI/SKI 与签名可验证性选择链，覆盖多中间与交叉签名；逐链签名验证、有效期、basic constraints/pathLen、KU（keyCertSign）、EKU serverAuth（可选）、Name Constraints、certificatePolicies、信任锚。
- 解析期**拒绝重复扩展与未知 critical 扩展**。
- 主机名：SAN dNSName 通配仅限**单个最左标签**；IP literal **只匹配 iPAddress SAN**；**从不回退 CN**（CN 仅用于 name-constraint）；IDNA/punycode。
- 撤销：纯离线、证据驱动（OCSP stapling、静态条目与 provider callback）；OCSP/CRL DER evidence 会校验签名、issuer/serial、thisUpdate/nextUpdate 与状态；`OnlineRequired` / `RequireRevocationCheck` 下查不到或证据无效 → **fail-closed**（`STATUS_TRUST_FAILURE`）。
- SPKI pin：对**已配置 pin 的主机**强校验叶证书 SPKI；未配置 pin 的主机 fail-open。
- mTLS：私钥不入库，经 `TlsClientCredential.Sign` 回调签名。

**密码学**：SHA-1/256/384/512、HMAC、HKDF；AES-GCM（CNG）、**ChaCha20-Poly1305 / AES-CCM / X25519 / X448 / FFDHE2048-8192 为内核内软件实现**；NIST 曲线走 CNG ECDH；签名验证 RSA-PKCS1/RSA-PSS(salt=摘要长)/ECDSA；最小 RSA 模数 2048 位；FFDHE 公钥范围校验；密钥材料统一 `RtlSecureZeroMemory` 清零。

### 默认关闭、需显式开启

| 能力 | 开启方式 / 说明 |
|------|-----------------|
| `Expect: 100-continue` | `SendFlagExpectContinue` 显式开启 |
| HTTP/1.1 pipeline | session `EnableHttp11Pipeline=true`；`Http11PipelineMaxDepth` / `Http11PipelineMethodMask` 可配置，默认仅 `GET`/`HEAD`/`OPTIONS` |
| h2c prior knowledge / Upgrade | `SendOptions.Http2CleartextMode` 显式开启；默认不走明文 HTTP/2 |
| HTTP/2 后台 PING 保活 | session `Http2KeepAlive.Enabled=true`；默认关闭 |
| HTTP/2 per-request priority | `SendOptions.Http2Priority` / `KhHttpSendOptions.Http2Priority` |
| WebSocket permessage-deflate | `ConnectConfig.PerMessageDeflate.Enable=true`；默认不协商 |
| TLS1.2 RSA kx / CBC / SHA-1 | `TlsPolicy.Profile=CompatibilityExplicit` 后分别开启 `EnableTls12RsaKeyExchange`、`EnableTls12Cbc`、`EnableTls12Sha1Signatures` |
| TLS1.2 真重协商 | `CompatibilityExplicit` + `EnableTls12Renegotiation`，次数由 `MaxTls12Renegotiations` 限制 |
| TLS1.3 0-RTT | 连接选项 `EnableEarlyData` + `EarlyDataReplaySafe`，且 ticket 通告 `max_early_data_size` |
| TLS1.3 post-handshake client auth | `EnablePostHandshakeClientAuth`；开启后经 mTLS 回调签名，私钥不进入库 |
| 强撤销要求 | `RequireRevocationCheck`；查不到调用方提供或 provider 返回的可验证 OCSP/CRL DER 证据时 fail-closed |

### 安全拒绝 / 策略约束

这些是有意的安全或协议策略，不表示缺少实现。

| 行为 | 处理 |
|------|------|
| 用户手写请求 `Transfer-Encoding` / `TE` | 拒绝；请求 framing 由库生成和校验 |
| HTTP/1.1 request trailer | 仅允许 chunked 请求路径 |
| HTTP `br` Transfer-Encoding | 拒绝；`br` 仅作为 `Content-Encoding` 支持 |
| HTTP/2 `PUSH_PROMISE` | server push 禁用，收到后视为协议错误 |
| WebSocket 服务端返回未请求扩展 | 拒绝；permessage-deflate 仅显式启用后协商 |
| WebSocket 握手 redirect / 401 / 407 | 不自动跟随或认证，返回 `STATUS_NOT_SUPPORTED` |
| TLS 1.3 到 TLS 1.2 | 不做握手内自动降级；只有可验证的版本协商证据才允许上层显式重连 1.2 |
| 证书主机名 | IP literal 只匹配 iPAddress SAN；域名不回退 CN |
| HTTPS redirect 到 HTTP | 默认拒绝降级 |
| RFC 9111 cache | 提供显式内存内内核缓存 API；支持 fresh hit、验证、`Vary`、private/shared 规则、unsafe method 失效、Range/206 partial 合并 |

### 明确未实现 / 非目标

这些能力当前不提供；已经实现但默认关闭的能力只记录在上一节，不放在这里。

| 能力 | 当前结论 |
|------|----------|
| HTTP 入站 request parser / server role | 非目标；当前项目定位为客户端协议栈 |
| 磁盘持久化 HTTP cache | 非目标；RFC 9111 cache 为显式内存内 NonPaged 对象，不跨重启持久化 |
| HTTP/2 复杂本地 priority tree 调度 | 非目标；不维护本地依赖树，不实现带宽调度器 |
| 除 `permessage-deflate` 外的 WebSocket extensions | 非目标；不协商其它扩展 |
| 在线 OCSP/CRL 抓取 | 非目标；调用方通过外部 trust/cert/revocation 数据或已缓存条目驱动强撤销判定 |
| HTTP/3 / QUIC | 非目标 |

### 实现策略和信任模型

- 传输层主路径使用 WSK；TLS、HTTP、证书校验按内核自实现路线推进。
- 密码学优先使用内核态 CNG/BCrypt；ChaCha20-Poly1305、AES-CCM、X25519、X448、FFDHE、Ed25519/Ed448 验签等由内核内软件实现补齐。
- 不把 WinHTTP、WinINet、SChannel 作为内核主路径。
- 库层不硬编码系统 CA；信任锚、CA 包、撤销缓存和 pin 由调用方显式提供。

### 关键默认行为

- **Redirect**：301/302 仅 POST→GET；303 除 HEAD 外→GET；307/308 保留方法和 body；跨源清理 `Authorization`/`Cookie`/`Proxy-Authorization`；拒绝 HTTPS→HTTP 降级。**达到最大跳数（默认 10）时不报错，直接返回该 3xx 响应**。
- **Stale 重试**：仅 `GET`/`HEAD`/`OPTIONS`，且复用连接、`ReuseOrCreate`、失败状态属连接关闭族/`STATUS_RETRY`/`STATUS_IO_TIMEOUT` 时，以 `ForceNew` **重试恰好一次**。
- **连接池**：close-delimited 与 101 响应不回池；`NoPool` 从不挤掉活跃连接，`ForceNew`/`ReuseOrCreate` 会驱逐空闲槽。
- **IRQL**：同步 HTTP/WS/TLS/证书路径要求 `PASSIVE_LEVEL`，否则 `STATUS_INVALID_DEVICE_REQUEST`/`STATUS_INVALID_DEVICE_STATE`。
