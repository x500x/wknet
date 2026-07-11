# 协议完整性账本

本文用于执行 `docs/plans/2026-07-02-protocol-completeness-plan.md`。每个协议能力必须落入一个明确状态，后续实现只能把 `待补全` 迁移为 `已实现/已验证`、`安全拒绝` 或 `明确非目标`，不能用模糊措辞隐藏缺口。

## 状态定义

| 状态 | 含义 |
|------|------|
| 已实现/已验证 | 当前代码已有实现，并有用户态协议测试或集成测试覆盖。 |
| 已实现/待补测 | 当前代码看起来已有实现，但测试覆盖不足，需要补测试后才能宣传为已验证。 |
| 待补全 | 属于客户端主路径完整性，应按计划补实现与测试。 |
| 安全拒绝 | RFC 允许或历史兼容存在，但本库出于安全/内核边界选择拒绝，并需测试证明拒绝稳定。 |
| 默认关闭 | 能力存在，但只有调用方显式配置后启用。 |
| 明确非目标 | 不符合本项目定位，不作为内核客户端主路径实现。 |

## 主路径边界

- 主路径：客户端 HTTP/1.1、HTTP/2、HPACK、TLS 1.2/1.3、X.509 证书校验、WebSocket、HTTP 代理。
- 内核方向：传输层优先 WSK，密码学优先内核态 CNG/BCrypt，HTTP/TLS/证书校验按内核自实现路线推进。
- 非主路径：HTTP/3/QUIC、服务端/入站 request parser、WinHTTP/WinINet/SChannel 作为内核主路径、在线 OCSP/CRL 抓取。
- 资源原则：普通 buffered response 默认不设置低位总量硬上限；安全上限放在 header section、帧、消息、解压膨胀比、超时、取消与分配失败边界。

## HTTP/1.1 账本

| 条目 | RFC 级别 | 状态 | 代码入口 | 测试入口 | 备注 |
|------|----------|------|----------|----------|------|
| 请求行与常用方法 GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH | MUST | 已实现/已验证 | `src/KernelHttpLib/http/HttpRequest.cpp` | `tests/http_parser_tests.cpp`、`tests/khttp_tests.cpp` | 常用方法默认可用。 |
| TRACE 显式 opt-in | MAY/诊断 | 已实现/已验证 | `HttpRequest.cpp`、`HttpEngine.cpp`、`khttp/Http.cpp` | `tests/http_parser_tests.cpp`、`tests/khttp_tests.cpp` | 需 `SendFlagAllowTrace`；body、trailer、敏感头与带代理凭据路径拒绝。 |
| Range / 条件请求 typed helper | MAY | 已实现/已验证 | `engine/Engine.cpp`、`khttp/Request.cpp` | `tests/khttp_tests.cpp` | 只生成请求 header；不做分片合并、缓存合并或 RFC9111 cache。 |
| CONNECT 请求构建 | MUST for proxy/tunnel clients | 已实现/已验证 | `HttpRequestBuilder`、`client/ProxyTunnel.cpp` | `tests/http_parser_tests.cpp`、`tests/khttp_tests.cpp` | HTTPS 代理隧道已接入。 |
| Host 首发与 header 文本校验 | MUST | 已实现/已验证 | `HttpRequest.cpp`、`engine/Engine.cpp` | `tests/http_parser_tests.cpp` | 拒绝 CRLF 注入和库受控头篡改。 |
| 用户设置 `Transfer-Encoding`/`TE` | MAY | 安全拒绝 | `HttpRequest.cpp`、`HttpEngine.cpp` | `tests/http_parser_tests.cpp` | 调用方不能破坏 framing，库自己生成 chunked。 |
| 请求 `Content-Length` body | MUST | 已实现/已验证 | `HttpRequest.cpp`、`HttpEngine.cpp` | `tests/http_parser_tests.cpp` | 小 body 当前一次性写入。 |
| 请求 chunked body 与 trailer | MUST when chunked | 已实现/已验证 | `HttpRequest.cpp`、`Engine.cpp` | `tests/http_parser_tests.cpp`、`tests/khttp_tests.cpp` | trailer 禁止字段已拒绝。 |
| 真流式请求体上传 | SHOULD for large clients | 已实现/已验证 | `HttpEngine.cpp`、`khttp/Body.cpp`、`khttp/Http.cpp` | `tests/khttp_tests.cpp`、`tests/high_level_api_tests.cpp` | `BodyCreateStream` / `KhHttpRequestSetBodySource` 按块读取；已知长度走 `Content-Length`，未知长度走库生成 chunked。 |
| `Expect: 100-continue` | SHOULD | 已实现/已验证 | `HttpRequest.cpp`、`HttpParser.cpp`、`HttpEngine.cpp` | `tests/http_parser_tests.cpp`、`tests/khttp_tests.cpp` | 显式 opt-in；默认关闭；覆盖 100 后发 body、final/417 不发 body、超时后发 body、断连错误。 |
| 响应状态行与 HTTP/1.0/1.1 版本 | MUST | 已实现/已验证 | `HttpParser.cpp` | `tests/http_parser_tests.cpp` | 拒绝非 1.x 与非法状态码。 |
| header section、单行、头数量上限 | MUST/安全边界 | 已实现/已验证 | `HttpParser.cpp` | `tests/http_parser_tests.cpp` | 64 KiB header section、8 KiB 单行、≤200 headers。 |
| obs-fold | OBSOLETE | 安全拒绝 | `HttpParser.cpp` | `tests/http_parser_tests.cpp` | 拒绝而非规范化。 |
| `Content-Length`/`Transfer-Encoding` 冲突 | MUST reject | 已实现/已验证 | `HttpParser.cpp`、`HttpTransferCoding.cpp` | `tests/http_parser_tests.cpp` | 多 CL、TE+CL 冲突拒绝。 |
| response body framing：CL/chunked/close-delimited/no-body | MUST | 已实现/已验证 | `HttpParser.cpp` | `tests/http_parser_tests.cpp` | 1xx/204/205/304/HEAD 无 body。 |
| 响应 trailer 解析与查询 | MUST when chunked | 已实现/已验证 | `HttpParser.cpp`、`Engine.cpp` | `tests/http_parser_tests.cpp`、`tests/khttp_tests.cpp` | 禁止 trailer 字段拒绝。 |
| Content-Encoding gzip/deflate/br/compress/zstd/dcz/aes128gcm/identity | MAY | 已实现/已验证 | `HttpContentEncoding.cpp`、`HttpCoding.cpp`、`third_party/zstd` | `tests/http_parser_tests.cpp`、`tests/khttp_tests.cpp` | dcz/aes128gcm 需要调用方提供解码材料；缺材料、认证失败或膨胀超限 fail-closed。 |
| Content-Encoding exi | MAY | 已实现/已验证 | `HttpContentEncoding.cpp`、`HttpExiDecoder.cpp`、`HttpExiOptions.cpp`、`HttpExiValueDecoder.cpp` | `tests/exi_decoder_tests.cpp`、`tests/http_parser_tests.cpp` | W3C EXI 1.0 Second Edition 无外部 Schema 流：四种 alignment、Options、保真项、内建 XML Schema 类型、`xsi:type`、`xsi:nil`；输出 Infoset 等价 XML。外部 Schema/strict grammar 返回 `STATUS_NOT_SUPPORTED`；EXIficient 语料带 SHA-256/provenance。 |
| Content-Encoding pack200-gzip | MAY | 已实现/已验证 | `HttpContentEncoding.cpp`、`HttpPack200Decoder.cpp`、`HttpPack200AttributeLayout.cpp`、`HttpPack200ClassWriter.cpp` | `tests/pack200_decoder_tests.cpp`、`tests/http_parser_tests.cpp` | Java 5–8 格式 `150.7`/`160.1`/`170.1`/`171.0`：裸/gzip、多 segment、class/file/bytecode、自定义 attribute layout（四 context、replication/union/callable）、overflow index、常量池与 BCI relocation；输出语义等价 JAR。真实语料由 `SHA256SUMS` 与 provenance 审计。 |
| Transfer-Encoding gzip/deflate/compress/chunked | MAY | 已实现/已验证 | `HttpTransferCoding.cpp` | `tests/http_parser_tests.cpp` | `br` 作为 TE 安全拒绝。 |
| Redirect 安全规则 | MAY | 已实现/已验证 | `HttpEngine.cpp` | `tests/khttp_tests.cpp` | HTTPS 降级拒绝、跨源清理敏感头。 |
| Stale 连接安全重试 | MAY | 已实现/已验证 | `HttpEngine.cpp` | `tests/khttp_tests.cpp` | 仅安全方法，ForceNew 一次。 |
| 明文 HTTP over proxy | SHOULD for client completeness | 已实现/已验证 | `HttpEngine.cpp`、`ConnectionPool.cpp` | `tests/khttp_tests.cpp` | 使用 absolute-form target，Host 保持 origin，`Proxy-Authorization` 仅来自显式 proxy config；HTTPS CONNECT 保持现状。 |
| HTTP 管线化 | MAY | 默认关闭/已验证 | `ConnectionPool.cpp`、`HttpEngine.cpp`、`Session.cpp` | `tests/khttp_tests.cpp` | session `EnableHttp11Pipeline=true` 显式开启；FIFO 响应绑定；默认仅 `GET`/`HEAD`/`OPTIONS`，深度和方法 mask 可配置；带 body、`Expect:100-continue`、redirect 重放/重排不进入 pipeline。 |
| HTTP 服务端/入站 request parser | N/A | 明确非目标 | N/A | N/A | 项目定位为客户端协议栈。 |

## HTTP/2 与 HPACK 账本

| 条目 | RFC 级别 | 状态 | 代码入口 | 测试入口 | 备注 |
|------|----------|------|----------|----------|------|
| 客户端连接前导与 SETTINGS 交换 | MUST | 已实现/已验证 | `src/KernelHttpLib/http2/Http2Connection.cpp` | `tests/http2_client_tests.cpp` | 首帧校验、立即 ACK。 |
| SETTINGS 参数校验 | MUST | 已实现/已验证 | `Http2Frame.cpp`、`Http2Connection.cpp` | `tests/http2_frame_tests.cpp`、`tests/http2_client_tests.cpp` | `ENABLE_PUSH != 0` 拒绝。 |
| HEADERS/CONTINUATION 序列 | MUST | 已实现/已验证 | `Http2Connection.cpp`、`Hpack.cpp` | `tests/http2_client_tests.cpp`、`tests/hpack_tests.cpp` | CONTINUATION 洪泛防护。 |
| HPACK 整数/Huffman/动态表/header-list 上限 | MUST | 已实现/已验证 | `Hpack.cpp`、`HpackHuffman.cpp` | `tests/hpack_tests.cpp` | 敏感头 never-indexed。 |
| 响应伪头与连接专属头校验 | MUST | 已实现/已验证 | `Http2Connection.cpp` | `tests/http2_client_tests.cpp` | `te` 仅允许 `trailers`。 |
| DATA 流控与 WINDOW_UPDATE | MUST | 已实现/已验证 | `Http2Stream.cpp`、`Http2Connection.cpp` | `tests/http2_client_tests.cpp` | 连接级与 stream 级均覆盖。 |
| 多活动 stream 分发 | SHOULD | 已实现/已验证 | `Http2Connection.cpp`、`ConnectionPool.cpp` | `tests/http2_client_tests.cpp`、`tests/khttp_tests.cpp` | 高层连接池已用 stream lease。 |
| HTTP/2 响应 trailers | MUST | 已实现/已验证 | `Http2Connection.cpp` | `tests/http2_client_tests.cpp` | trailer 伪头拒绝。 |
| HTTP/2 请求 trailers | SHOULD | 已实现/已验证 | `Http2Connection.cpp`、`HttpEngine.cpp` | `tests/http2_client_tests.cpp`、`tests/khttp_tests.cpp` | body 结束后发送 final HEADERS + END_STREAM；不使用 chunked，拒绝 trailer 伪头。 |
| HTTP/2 流式请求 DATA | SHOULD | 已实现/已验证 | `Http2Connection.cpp` | `tests/http2_client_tests.cpp` | body source 驱动，按连接/stream 窗口和 peer `MAX_FRAME_SIZE` 切块。 |
| RFC 8441 extended CONNECT | MAY | 已实现/已验证 | `Http2Connection.cpp`、`WebSocketClient.cpp` | `tests/http2_client_tests.cpp`、`tests/websocket_client_tests.cpp` | `wss` 显式 opt-in。 |
| h2 TLS ALPN 高层路径 | SHOULD | 已实现/已验证 | `HttpEngine.cpp`、`TlsConnection.cpp` | `tests/khttp_tests.cpp` | 自动 offer `h2,http/1.1`。 |
| h2c prior knowledge / Upgrade 低层路径 | MAY | 已实现/已验证 | `client/Http2Client.cpp` | `tests/http2_client_tests.cpp` | Upgrade 禁请求体并重放 101 后残留字节。 |
| h2c 高层显式入口 | MAY | 默认关闭/已验证 | `HttpEngine.cpp`、`client/Http2Client.cpp` | `tests/khttp_tests.cpp`、`tests/http2_client_tests.cpp` | `SendOptions.Http2CleartextMode` 显式开启；pool key 区分 HTTP/1.1、prior knowledge 与 Upgrade。 |
| GOAWAY/RST_STREAM 高层重试语义 | SHOULD | 已实现/已验证 | `Http2Connection.cpp`、`HttpEngine.cpp` | `tests/http2_client_tests.cpp`、`tests/khttp_tests.cpp` | `NO_ERROR`/未处理 stream 返回 `STATUS_RETRY`；高层只对安全方法 fresh retry 一次，非幂等请求不自动重放。 |
| PRIORITY 发送 | MAY | 已实现/已验证 | `Http2Frame.cpp`、`Http2Connection.cpp`、`client/Http2Client.cpp` | `tests/http2_frame_tests.cpp`、`tests/http2_client_tests.cpp` | 显式 per-request priority；支持 HEADERS priority 字段与独立 PRIORITY frame 编解码，收到 peer PRIORITY 只校验/记录语义，不改变安全边界。 |
| server push | MAY/deprecated | 安全拒绝 | `Http2Connection.cpp` | `tests/http2_client_tests.cpp` | 客户端 `ENABLE_PUSH=0`，`PUSH_PROMISE` 协议错误。 |
| 后台自动 PING 保活 | MAY | 默认关闭/已验证 | `ConnectionPool.cpp`、`Http2Connection.cpp` | `tests/khttp_tests.cpp`、`tests/http2_client_tests.cpp` | session `Http2KeepAlive.Enabled=true` 显式开启；只扫描 idle 可复用池化 H2 连接，ACK 超时关闭该 idle 连接；低层保留显式 `SendPing`。 |

## TLS 1.2/1.3 账本

| 条目 | RFC 级别 | 状态 | 代码入口 | 测试入口 | 备注 |
|------|----------|------|----------|----------|------|
| TLS 1.3 优先、失败分类后显式 TLS 1.2 重连 | SHOULD | 已实现/已验证 | `TlsConnection.cpp`、`HttpEngine.cpp` | `tests/tls_handshake_tests.cpp`、`tests/khttp_tests.cpp` | 无握手内自动降级。 |
| 降级哨兵检测 | MUST | 已实现/已验证 | `TlsHandshake13.cpp`、`TlsConnection.cpp` | `tests/tls_handshake_tests.cpp` | 攻击硬失败。 |
| TLS 1.2 EMS 与安全重协商指示 | SHOULD/MUST by policy | 已实现/已验证 | `TlsConnection.cpp`、`TlsHandshake12.cpp` | `tests/tls_handshake_tests.cpp` | 缺失按本库策略拒绝。 |
| TLS 1.2 CBC Encrypt-then-MAC | SHOULD | 默认关闭/安全拒绝 | `TlsPolicy.cpp`、`TlsRecord.cpp` | `tests/tls_record_tests.cpp` | CBC 需兼容档开启且必须 EtM。 |
| TLS 1.3 HRR、binder 重算、NST、KeyUpdate 被动回应 | MUST/SHOULD | 已实现/已验证 | `TlsConnection.cpp`、`TlsHandshake13.cpp` | `tests/tls_record_tests.cpp`、`tests/tls_interop_matrix_tests.cpp` | 默认不主动 rekey；服务端请求 KeyUpdate 时被动回应并 rekey。 |
| TLS 1.3 early data | MAY | 默认关闭 | `TlsConnection.cpp` | `tests/tls_handshake_tests.cpp` | 需 replay-safe 且 ticket 允许。 |
| 会话恢复绑定 policy/SNI/ALPN/cipher/version | SHOULD | 已实现/已验证 | `TlsConnection.cpp` | `tests/tls_handshake_tests.cpp` | 1.2/1.3 各最多 4 条。 |
| ALPN h2/http1 | SHOULD | 已实现/已验证 | `TlsHandshake13.cpp`、`TlsConnection.cpp` | `tests/tls_handshake_tests.cpp`、`tests/khttp_tests.cpp` | 高层仅接受支持的 ALPN。 |
| AES-GCM/AES-CBC EtM/ChaCha20-Poly1305 record | MUST for offered suites | 已实现/已验证 | `TlsRecord.cpp`、`crypto/Aead.cpp` | `tests/tls_record_tests.cpp`、`tests/tls_crypto_tests.cpp` | 序列号溢出保护。 |
| X25519/X448/FFDHE/NIST ECDH | MUST for offered groups | 已实现/已验证 | `crypto/KeyExchange.cpp`、`CngProvider.cpp` | `tests/tls_crypto_tests.cpp` | NIST 曲线走 CNG，部分软件实现。 |
| RSA-PSS/ECDSA/Ed25519/Ed448 验签 | MUST for offered sigalgs | 已实现/已验证 | `crypto/CngProvider.cpp`、`Ed25519.cpp`、`Ed448.cpp` | `tests/tls_crypto_tests.cpp` | legacy SHA-1 默认关闭。 |
| post-handshake client auth | MAY | 默认关闭/已验证 | `TlsPolicy.cpp`、`TlsConnection.cpp` | `tests/tls_record_tests.cpp`、`tests/tls_interop_matrix_tests.cpp` | 开启后走 mTLS 回调，不持有私钥；默认策略关闭。 |
| TLS 1.2 renegotiation | MAY | 默认关闭/已验证 | `TlsConnection.cpp`、`TlsHandshake12.cpp` | `tests/tls_record_tests.cpp`、`tests/khttp_tests.cpp`、`tests/integration/tls_matrix.ps1` | 需 `CompatibilityExplicit` + `EnableTls12Renegotiation`，次数由 `MaxTls12Renegotiations` 限制；支持服务器 `HelloRequest` 与低层客户端主动全量重协商；不支持 abbreviated/session resumption；ALPN 按本次重协商结果更新，非空结果必须来自本次 offer。 |
| SChannel 主路径 | N/A | 明确非目标 | N/A | N/A | 不符合内核自实现方向。 |

## X.509 证书校验账本

| 条目 | RFC/PKIX 级别 | 状态 | 代码入口 | 测试入口 | 备注 |
|------|---------------|------|----------|----------|------|
| 链深上限、DER/PEM 输入界限 | MUST/安全边界 | 已实现/已验证 | `CertificateValidator.cpp`、`CertificateStore.cpp` | `tests/tls_handshake_tests.cpp` | 链 ≤8。 |
| subject/issuer DN 链接与签名验证 | MUST | 已实现/已验证 | `CertificateValidator.cpp` | `tests/tls_record_tests.cpp` | 多候选与交叉签名路径有 fixture 覆盖。 |
| AKI/SKI 辅助路径选择 | SHOULD | 已实现/已验证 | `CertificateValidator.cpp` | `tests/tls_record_tests.cpp` | 路径候选按 AKI/SKI、issuer/subject 与签名可验证性选择。 |
| basic constraints/pathLen/KU/EKU | MUST | 已实现/已验证 | `CertificateValidator.cpp` | `tests/tls_handshake_tests.cpp` | serverAuth 可选策略。 |
| Name Constraints | MUST if present | 已实现/已验证 | `CertificateValidator.cpp` | `tests/tls_record_tests.cpp` | 覆盖允许/拒绝子树、IDNA 与 malformed DER。 |
| certificatePolicies | SHOULD | 已实现/已验证 | `CertificateValidator.cpp` | `tests/tls_record_tests.cpp` | 覆盖 non-critical、critical 与 malformed DER。 |
| 重复扩展与未知 critical 扩展 | MUST reject | 已实现/已验证 | `CertificateValidator.cpp` | `tests/tls_handshake_tests.cpp` | 解析期拒绝。 |
| 主机名 SAN/IP/IDNA | MUST | 已实现/已验证 | `CertificateValidator.cpp` | `tests/tls_handshake_tests.cpp` | 不回退 CN。 |
| SPKI pin | MAY | 已实现/已验证 | `CertificateStore.cpp`、`CertificateValidator.cpp` | `tests/tls_handshake_tests.cpp` | 配置 pin 的主机强校验。 |
| 离线撤销证据 | MAY | 已实现/已验证 | `CertificateStore.cpp`、`CertificateValidator.cpp`、`TlsConnection.cpp` | `tests/tls_record_tests.cpp`、`tests/tls_interop_matrix_tests.cpp` | OCSP stapling、静态条目与 revocation provider 都必须提供可验证 DER evidence；校验签名、issuer/serial、thisUpdate/nextUpdate 与 OCSP/CRL 状态；`OnlineRequired`/`RequireRevocationCheck` 查不到或证据无效即 fail-closed。 |
| 在线 OCSP/CRL 抓取 | MAY | 明确非目标 | N/A | N/A | 内核态避免网络抓取副作用。 |

## WebSocket 账本

| 条目 | RFC 级别 | 状态 | 代码入口 | 测试入口 | 备注 |
|------|----------|------|----------|----------|------|
| HTTP/1.1 Upgrade opening handshake | MUST | 已实现/已验证 | `WebSocketFrame.cpp`、`WebSocketClient.cpp` | `tests/websocket_frame_tests.cpp`、`tests/websocket_client_tests.cpp` | `Sec-WebSocket-Accept` 常量时间比对。 |
| 自定义 opening headers | MAY | 已实现/已验证 | `WebSocketClient.cpp`、`khttp/WebSocket.cpp` | `tests/websocket_client_tests.cpp` | 库受控头拒绝。 |
| 客户端帧 masking | MUST | 已实现/已验证 | `WebSocketFrame.cpp` | `tests/websocket_frame_tests.cpp` | HTTP/2 RFC 8441 路径按规范无 mask。 |
| 服务端 masked frame | MUST reject | 已实现/已验证 | `WebSocketFrame.cpp`、`WebSocketClient.cpp` | `tests/websocket_frame_tests.cpp` | 关闭码 1002。 |
| 分片发送与默认聚合接收 | MUST | 已实现/已验证 | `WebSocketClient.cpp` | `tests/websocket_client_tests.cpp` | 文本跨片 UTF-8 校验。 |
| wire fragment 回调 | SHOULD for streaming clients | 已实现/已验证 | `WebSocketClient.cpp`、`khttp/WebSocket.cpp` | `tests/websocket_client_tests.cpp` | `ReceiveOptions.DeliverFragments` 显式开启；默认仍聚合完整消息。 |
| control frame 自动 Pong 与洪泛上限 | SHOULD/安全边界 | 已实现/已验证 | `WebSocketClient.cpp` | `tests/websocket_client_tests.cpp` | 单次接收控制帧 ≤100。 |
| close handshake | MUST | 已实现/已验证 | `WebSocketClient.cpp` | `tests/websocket_client_tests.cpp` | 主动/被动 close 已覆盖。 |
| RFC 8441 WebSocket over HTTP/2 | MAY | 默认关闭/已验证 | `Http2Connection.cpp`、`WebSocketClient.cpp` | `tests/http2_client_tests.cpp`、`tests/websocket_client_tests.cpp` | 仅 `wss` 显式 opt-in。 |
| permessage-deflate | MAY | 显式 opt-in 已实现/已验证 | `WebSocketFrame.cpp`、`WebSocketDeflate.cpp`、`WebSocketClient.cpp` | `tests/websocket_frame_tests.cpp`、`tests/websocket_client_tests.cpp` | 默认关闭；未请求扩展、未知扩展、重复/非法参数拒绝；解压受消息大小、输出容量和膨胀比限制。 |
| opening-handshake redirect/401/407 跟随 | MAY | 明确非目标/安全拒绝 | `WebSocketClient.cpp` | `tests/websocket_client_tests.cpp` | 3xx/401/407 返回 `STATUS_NOT_SUPPORTED`；若未来实现必须显式 opt-in 且沿用 HTTP 安全重定向规则。 |

## 代理账本

| 条目 | RFC/实践级别 | 状态 | 代码入口 | 测试入口 | 备注 |
|------|--------------|------|----------|----------|------|
| HTTPS over HTTP proxy CONNECT | SHOULD | 已实现/已验证 | `ProxyTunnel.cpp`、`HttpEngine.cpp`、`HttpsClient.cpp` | `tests/khttp_tests.cpp` | 支持 `Proxy-Authorization` opaque 值。 |
| 明文 HTTP over proxy absolute-form | SHOULD | 已实现/已验证 | `HttpEngine.cpp`、`ConnectionPool.cpp` | `tests/khttp_tests.cpp` | 不建立 CONNECT 隧道；pool key 保留 proxy endpoint 与 origin 身份。 |
| 代理鉴权协议解析 | MAY | 明确非目标 | N/A | N/A | 仅透传调用方提供的 opaque 头值。 |
| SOCKS proxy | MAY | 明确非目标 | N/A | N/A | 当前范围只覆盖 HTTP proxy。 |

## 验证基线

用户态协议测试：

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test http_parser_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test websocket_frame_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test websocket_client_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test http2_frame_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test hpack_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test http2_client_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_crypto_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_handshake_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_record_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_interop_matrix_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test khttp_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test high_level_api_tests -Run
```

构建验证：

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64
```

环境具备 ARM64 WDK 工具链时，再运行 ARM64 Debug/Release。禁止运行会卡住的 `pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild`。

## 迁移结果

本轮计划中的客户端主路径缺口已迁移为 `已实现/已验证`、`默认关闭/已验证`、`安全拒绝` 或 `明确非目标`：

1. HTTP/1.1 真流式请求体、显式 `Expect: 100-continue`、明文 HTTP over proxy 已验证。
2. HTTP/2 请求 trailers、流式 DATA、高层 h2c 显式入口、GOAWAY/RST 高层重试语义、显式 per-request PRIORITY 已验证。
3. WebSocket wire fragment 回调由 `ReceiveOptions.DeliverFragments` 显式开启，默认仍保持聚合消息兼容行为。
4. X.509 AKI/SKI 与交叉签名路径构建、Name Constraints、certificatePolicies 已验证。
5. TLS post-handshake/KeyUpdate 边界已审计；默认关闭项保持显式配置入口。
