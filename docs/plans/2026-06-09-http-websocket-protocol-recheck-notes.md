# HTTP/WebSocket/TLS/HTTP2 全栈协议完整性复核说明

日期：2026-06-09

## 结论

当前项目不能描述为“全量 HTTP/WebSocket/TLS/HTTP2 RFC optional 能力完整无误”的通用协议栈。更准确的定位是：面向 Windows kernel driver 的现代客户端协议子集，内核主路径使用 WSK、自实现 TLS/HTTP/HTTP2/WebSocket 和内核 CNG/BCrypt。

第一轮五个子代理审计后，已确认当前主路径已有相当多的严格性和测试基础，但仍存在需要补齐的协议和内核环境缺口。部分缺口属于已支持子集内的正确性问题，应优先实现；部分属于协议宽度能力，应明确延期或非目标，不能作为隐式能力宣传。

## 审计流程

- 第一轮子代理：
  - Boyle：HTTP/1.1、HTTP 语义、transfer/content coding。
  - Dewey：WebSocket RFC 6455。
  - Avicenna：TLS/证书/CNG。
  - Gauss：HTTP/2 与 HPACK。
  - Kierkegaard：WSK、DNS、Async、连接池、跨层集成。
- 本地复核：代码、测试、现有 README/API 文档、既有 2026-06-08/09 计划文档。
- 外部参照：
  - RFC 9110、9111、9112、6455、8446、9325、5280、9113、7541。
  - RFC 5246 TLS 1.2。
  - curl/libcurl redirect 与 WebSocket API 文档、curl `lib/ws.c`。
  - nghttp2 文档作为 HTTP/2 成熟实现边界参照。

未运行项目禁止的 `pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild`。

## 当前已做得较完整的部分

### HTTP/1.1

- 请求构造支持 method、origin-form request-target、Host、Content-Length、显式 chunked body、Connection，并拒绝用户手写 `Transfer-Encoding`。
- 响应解析覆盖严格 CRLF、状态行、header name/value、重复和逗号 `Content-Length` 一致性、`Transfer-Encoding + Content-Length` 拒绝、HTTP/1.0 TE 拒绝、HEAD/1xx/204/205/304 无 body 规则。
- chunked 解码、chunk extension 基本语法、trailer 暴露和 forbidden trailer 字段拒绝已实现。
- response transfer coding 支持 `chunked/gzip/x-gzip/deflate/compress/x-compress` 链式解码。
- redirect 支持相对 URL，按 301/302/303/307/308 做常见方法改写，跨源清理敏感头，默认拒绝 HTTPS 到 HTTP 降级。
- stale/reused connection 自动重试只限安全/幂等方法。

### WebSocket

- opening handshake 生成和校验覆盖 HTTP/1.1 101、Connection/Upgrade token、Sec-WebSocket-Key/Accept、Version 13、subprotocol 匹配。
- client frame 强制 masking，server masked frame、RSV、unknown/reserved opcode、非法控制帧、非最短长度会拒绝。
- 支持分片聚合、Ping/Pong/Close 控制帧、Ping 自动 Pong、手动 Ping/Pong/CloseEx、Pong 可观察、selected subprotocol 查询。
- 真实 `WebSocketClient` 主路径会校验 text 和 close reason 的 UTF-8；public engine/khttp test transport 路径仍需把出站 text 校验上移，避免语义漂移。
- 未协商扩展时拒绝服务端返回 `Sec-WebSocket-Extensions`。

### TLS/证书

- TLS record 支持 TLS 1.2 AES-GCM、TLS 1.3 outer application_data/inner content type、padding 去除和 sequence overflow 检查。
- TLS 1.2 现代子集支持 ECDHE_RSA/ECDHE_ECDSA + AES-GCM。
- TLS 1.3 full handshake、HRR、PSK binder、NewSessionTicket、key schedule 主路径存在。
- 证书校验支持 DER 解析、SAN dNSName/iPAddress、CN fallback、有效期、KU/EKU、BasicConstraints/pathLen、链签名、外部 trust bundle、SPKI pin。
- CNG/BCrypt 封装要求 PASSIVE_LEVEL。

### HTTP/2/HPACK

- HTTP/2 preface、SETTINGS/ACK、HEADERS/CONTINUATION、DATA、PING、GOAWAY、RST_STREAM、WINDOW_UPDATE 主路径存在。
- ALPN `h2` 主路径存在。
- HPACK integer/string/Huffman、静态表、动态表、table size update、never-indexed 敏感请求头已有实现和测试。
- 响应 header block 校验重复/缺失 `:status`、伪头顺序、大写 header、connection-specific header、`TE` 非 `trailers`、`content-length` 与 DATA 一致性。

### WSK/跨层

- WSK connect/send/receive/close 均要求 PASSIVE_LEVEL，并有 timeout/cancel/late completion cleanup。
- DNS 基础 resolve 与固定 TTL 正向缓存已实现；cache 为全局 16 槽正向缓存，任一 `WskClient::Shutdown()` 会清空，不读取真实 TTL，不提供 negative cache/公共 flush。
- HTTP/WebSocket 按 `ResolveAll` 返回地址顺序逐个尝试连接；当前不实现 Happy Eyeballs 并行竞速。
- 连接池复用 key 包含 scheme、host、port、address family、TLS min/max、证书策略、store、SNI、ALPN；`MaxConnectionsPerHost` 配额按 scheme/host/port/address-family 统计 active + idle。
- URL 基础解析支持 http/https/ws/wss、默认端口、IPv6 bracket、query-only、fragment stripping、userinfo 拒绝。

## 第一轮新增发现的高优先级缺口

### HTTP/2/HPACK

- HPACK 解码错误当前可能只 RST_STREAM；压缩上下文错误应作为连接级 `COMPRESSION_ERROR`。
- HPACK Huffman decode 当前为逐 bit 线性扫描，恶意压缩字段可能造成 CPU 放大；需改为 decode table 或增加有界预算/测试。
- SETTINGS ACK 目前无超时/同步策略；需决定是否实现 `SETTINGS_TIMEOUT` 或文档化单请求子集策略。
- GOAWAY `last_stream_id` 语义需固定：graceful GOAWAY 是否允许完成当前 stream，还是统一断开。
- 接收大响应发送 stream WINDOW_UPDATE 后，stream local window 需要同步回补，否则超过初始窗口可能误判流控错误。
- 等待上传窗口时，非活动 stream 的 WINDOW_UPDATE 不应误增 connection send window。
- `framePayload_` 固定 16KB，peer 合法提高 `SETTINGS_MAX_FRAME_SIZE` 后可能返回 `STATUS_BUFFER_TOO_SMALL`。
- ExtraHeaders 可注入伪头、非法字段名/值或重复伪头，请求侧 header validation 不完整。
- HTTP/2 请求和响应字段名/字段值最小语法校验仍需补齐，包括字段名控制字符、大写、非 ASCII、非法冒号，以及字段值 NUL/CR/LF 和首尾 SP/HTAB。
- `SETTINGS_ENABLE_PUSH=1`、PUSH_PROMISE 在本端 SETTINGS ACK 前后的边界还需要固定。
- HEAD/204/304、interim 1xx、101、1xx END_STREAM、最终响应后非法 HEADERS/DATA 等规则未完整应用到 HTTP/2 DATA/HEADERS 路径。
- HTTP/2 是单请求单流主路径，不是 full multiplexing。

### WebSocket

- 协议错误发送 close 后，底层 transport 未必立即关闭；若调用方不再 `WsClose`，可能到析构/handle close 才释放。
- `AutoReplyPing=true` 时自动 Pong 受应用 output buffer 限制，小 buffer + 125 字节 Ping 可能失败。
- `MaxMessageBytes` 默认 1 MiB，但 engine 发送 scratch 约 16KB；大于 scratch 且小于上限的发送契约不清。
- fragmented send 只按单个 fragment 检查上限，没有累计整个消息长度。
- test transport 路径绕过真实 `WebSocketClient` 的部分校验，需要上移 public API 校验。
- `WsSendText`/`KhWebSocketSendTextSync` 的出站 text UTF-8 校验需要上移到 engine/khttp，避免 test transport 绕过真实路径语义。
- 主动 close handshake 口径需要实现或明确：发送 close 后有界等待 peer close，或文档化为发送 close 后关闭 transport 的客户端简化语义。
- WebSocket 自定义 opening handshake headers（Origin/Authorization/Cookie 等）当前不是公开能力；若要支持，需要单独 header validation、敏感头策略和测试。
- WebSocket over HTTP/2 RFC 8441 extended CONNECT 当前不是能力边界内主路径。

### TLS/证书

- TLS 1.3 ServerHello 未确认 `legacy_version == 0x0303` 与 `legacy_session_id_echo` 等于 ClientHello。
- TLS 1.2 缺 `extended_master_secret` 和 `renegotiation_info` 加固；继续普通 master secret 不符合 RFC 9325 现代部署预期。
- TLS 1.2 ServerHello ALPN 解析偏宽松，未强制 list length 与尾部完全匹配。
- TLS 1.2 resumption 当前只消费 NewSessionTicket，未作为恢复会话能力明确决策。
- 当前 CNG provider 不使用 `BCRYPT_PROV_DISPATCH`，TLS/证书/crypto 不得从 `DISPATCH_LEVEL` 调用 BCrypt。
- 证书 TBSCertificate 内层 `signatureAlgorithm` 与外层 `signatureAlgorithm` 一致性未确认。
- 重复任意 certificate extension OID 均应拒绝，不能只处理 critical 扩展。
- TLS 1.3 KeyUpdate、post-handshake auth、TLS client certificate、OCSP/CRL、IDNA、完整 Name Constraints 仍缺失或非目标。

### HTTP/1.1

- `Transfer-Encoding: chunked;param`、`gzip;param` 当前可能被接受；RFC 9112 建议把 chunked/compression transfer coding 参数当错误处理，本计划统一收紧为拒绝。
- TE list 空成员/尾逗号策略需要固定测试。
- 测试/模拟路径中 `MessageCompleteOnConnectionClose=true` 可能掩盖真实 socket close-delimited 响应必须等 EOF 的问题。
- 入站 HTTP/1.1 request parser/server role 不在当前客户端协议栈内，应显式列为非目标。
- `Expect: 100-continue`、请求 `TE`/`Trailer`、request trailers、CONNECT/TRACE/custom method 高层 API 未完整。
- `Expect: 100-continue` 若不实现状态机，不得作为普通 header 透传并立即发送 body，应在发送前拒绝。
- RFC 9111 cache、条件请求、Range/206/416 语义基本缺失。
- `Accept-Encoding`/内容协商 qvalue 语义缺失；当前仅是默认 header 和 response decoder 子集。
- Content-Encoding `compress/x-compress` 与内部 decoder 能力不一致。
- URL percent-decoding/normalization 行为未明确；path/query 应按字节透传或固定校验策略，不能隐式重写。

### WSK/Async/连接池/内核环境

- 已修复：`KhAsyncOperationIsCanceled` 按 live operation 判断，cancel 后 release 不会阻止 worker 观察取消；callback/free exactly once 有回归测试。
- 已文档化：DNS cache 固定 5 分钟 TTL，不读取 DNS TTL，无 negative cache/公共 flush API；`ResolveAll` 不接 async cancellation token，进入 provider 后不承诺取消。
- 已修复：`MaxConnectionsPerHost` 按 scheme/host/port/address-family host 配额统计，同时完整 TLS 身份 key 仍禁止跨身份复用。
- HTTP/2、WebSocket、TLS、证书和 client 路径仍有大量直接或间接 `new/delete/new[]/delete[]`，即便项目重载到 NonPaged pool，也与当前项目约束冲突。
- WebSocket receive 高频分配 `frameBuffer` 和 `payloadBuffer(maxMessageBytes)`，默认可能造成 nonpaged pool 压力。
- public enum 暴露 `Paged`，但 session/workspace 实现拒绝非 NonPaged，API 契约需要收紧或文档化。
- URL/DNS/SNI/cert host 链路需要在 URL parser 或 connect 前拒绝非 ASCII host；IPv6 zone id 策略需要固定。
- 已文档化：DNS cache 是全局作用域，任一 `WskClient::Shutdown()` 会清空全局缓存。
- WebSocket 普通终端 transport 错误，包括 send/receive timeout、cancel、disconnect、TLS/WSK terminal status，也需要同步 `Connected=false` 并 close exactly once。

## 当前边界与非目标

- 当前是客户端协议栈，不包含服务端 HTTP/WebSocket 角色。
- 入站 HTTP request parser/server role 非目标。
- HTTP proxy/CONNECT 当前非目标。
- WebSocket over HTTP/2 RFC 8441 extended CONNECT 当前非目标或延期。
- WebSocket 自定义 opening handshake headers 当前延期。
- WebSocket extensions/permessage-deflate 当前非目标。
- WebSocket frame metadata/partial receive 当前延期。
- TLS client certificate 当前延期。
- OCSP/CRL 当前非目标；`RequireRevocationCheck` 返回 `STATUS_NOT_SUPPORTED`。
- IDNA 当前非目标；非 ASCII host 拒绝。
- Name Constraints 当前不完整；触发时返回 `STATUS_NOT_SUPPORTED`，不得静默放行。
- CBC/RSA key exchange 非目标；ChaCha20-Poly1305、X25519、EdDSA 等 TLS 宽度能力延期，未作为当前现代子集承诺。
- HTTP/2 full multiplexing 延期；server push 和 priority 当前非目标或受限处理。
- RFC 9111 cache、Range、conditional request 目前不能宣传为完整语义实现。
- URI percent normalization、IPv6 zone id、Accept-Encoding qvalue/content negotiation 需要文档化为受限能力或后续实现。

## 真实内核验证建议

1. 开启 Driver Verifier：Special Pool、Pool Tracking、I/O Verification、Force IRQL Checking、Deadlock Detection。
2. 用测试驱动覆盖 connect/send/receive timeout、caller cancel、late completion、TLS handshake cancel、driver unload 前 session drain/close。
3. 用 PoolMon 观察项目 pool tag，确认协议错误、ping flood、fragment flood、timeout/cancel 后 nonpaged pool 不持续增长。
4. 在 kernel debugger 观察 WSK close paths：`CloseAfterCancelledOperation`、`CloseOwnedSocket`、late completion cleanup，确认 close exactly once。
5. 覆盖 IPv4/IPv6、SNI/ALPN/cert policy/store/pin 变化，确认连接池不跨身份复用。

## 参考资料

- RFC 9110 HTTP Semantics: https://www.rfc-editor.org/rfc/rfc9110.html
- RFC 9111 HTTP Caching: https://www.rfc-editor.org/rfc/rfc9111.html
- RFC 9112 HTTP/1.1: https://www.rfc-editor.org/rfc/rfc9112.html
- RFC 6455 WebSocket: https://www.rfc-editor.org/rfc/rfc6455.html
- RFC 8446 TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446.html
- RFC 5246 TLS 1.2: https://www.rfc-editor.org/rfc/rfc5246.html
- RFC 9325 TLS Recommendations: https://www.rfc-editor.org/rfc/rfc9325.html
- RFC 5280 PKIX: https://www.rfc-editor.org/rfc/rfc5280.html
- RFC 9113 HTTP/2: https://www.rfc-editor.org/rfc/rfc9113.html
- RFC 7541 HPACK: https://www.rfc-editor.org/rfc/rfc7541.html
- libcurl redirect behavior: https://curl.se/libcurl/c/CURLOPT_FOLLOWLOCATION.html
- libcurl redirect auth boundary: https://curl.se/libcurl/c/CURLOPT_UNRESTRICTED_AUTH.html
- libcurl WebSocket receive API: https://curl.se/libcurl/c/curl_ws_recv.html
- curl WebSocket source: https://github.com/curl/curl/blob/master/lib/ws.c
- nghttp2 documentation: https://nghttp2.org/documentation/
