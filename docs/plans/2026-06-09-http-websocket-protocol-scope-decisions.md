# HTTP/WebSocket/TLS/HTTP2 协议范围决策表

日期：2026-06-09

本文档配套：

- `docs/plans/2026-06-09-http-websocket-protocol-recheck-notes.md`
- `docs/superpowers/plans/2026-06-09-http-websocket-protocol-completion-plan.md`

决策口径：已声明支持的客户端协议子集必须严格、可测试；RFC optional、部署宽度能力或服务端角色能力，只有在能给出内核内存上限、明确 API 契约、正/负向测试和真实内核验证路径时才进入实现。否则列为延期或非目标，并返回固定错误或拒绝协商。

## 决策总览

| 缺口 | 决策 | 依据 | API 影响 | 预期错误码/行为 | 测试入口 | 映射 |
|---|---|---|---|---|---|---|
| HPACK 解码错误连接级处理 | 实现 | RFC 9113/RFC 7541：压缩上下文错误影响连接 | 不新增 API | GOAWAY `COMPRESSION_ERROR`，连接不可继续 | `tests/http2_client_tests.cpp`, `tests/hpack_tests.cpp` | Chunk 1.1 |
| HTTP/2 frame stream id 规则 | 实现 | DATA/HEADERS/RST/CONTINUATION 等 stream 0 非法；连接级 frame 规则需集中 | 不新增 API | GOAWAY/RST 按错误类型返回 | `tests/http2_frame_tests.cpp`, `tests/http2_client_tests.cpp` | Chunk 1.1 |
| HTTP/2 接收侧 stream window 回补 | 实现 | 大响应主路径需要正确 flow control | 不新增 API | WINDOW_UPDATE 后继续接收；非法窗口返回 flow-control error | `tests/http2_client_tests.cpp` | Chunk 1.2 |
| 非活动 stream WINDOW_UPDATE 影响 connection send window | 实现修复 | 当前单流子集不能让非目标 stream 改写主流控状态 | 不新增 API | 非目标 stream 按受限策略处理，不误增窗口 | `tests/http2_client_tests.cpp` | Chunk 1.2 |
| HTTP/2 ExtraHeaders 注入伪头/非法字段 | 实现 | 请求侧 header validation 是公开 API 边界 | 不新增 API | `STATUS_INVALID_PARAMETER` | `tests/http2_client_tests.cpp` | Chunk 1.3 |
| HTTP/2 field name/value 最小语法校验 | 实现 | RFC 9113 字段合法性可防请求走私和解析歧义 | 不新增 API | malformed response => RST_STREAM/PROTOCOL_ERROR；请求参数非法 => `STATUS_INVALID_PARAMETER` | `tests/http2_client_tests.cpp` | Chunk 1.3 |
| HTTP/2 HEAD/204/304/1xx body 规则 | 实现 | HTTP 语义适用于 HTTP/2 响应 | 不新增 API | 带 DATA 时协议错误或忽略规则按标准固定 | `tests/http2_client_tests.cpp` | Chunk 1.3 |
| HTTP/2 动态 max frame payload | 实现 | peer 合法提高 `SETTINGS_MAX_FRAME_SIZE` 后不能固定 16KB 误拒 | 内部 buffer 策略 | bounded buffer；超上限协议错误或容量错误 | `tests/http2_client_tests.cpp` | Chunk 1.4 |
| HTTP/2 SETTINGS ACK timeout | 实现决策 | peer 必须确认本端 SETTINGS；不能无限等待或把半初始化连接当成功 | 不新增 API | 缺失 ACK 返回 `STATUS_IO_TIMEOUT` 并发送 GOAWAY `SETTINGS_TIMEOUT` | `tests/http2_client_tests.cpp` | Chunk 1.1 / Chunk 7 |
| HTTP/2 GOAWAY `last_stream_id` / 单请求边界 | 实现决策并文档化 | 当前公共主路径一次只驱动一个请求 stream，不提供完整多流重试/排队语义 | 不新增 API | 收到 GOAWAY 终止当前单请求连接；本端 GOAWAY 使用当前/最后分配 stream id | `tests/http2_client_tests.cpp`, `tests/http2_frame_tests.cpp` | Chunk 1.1 / Chunk 7 |
| SETTINGS_ENABLE_PUSH/PUSH_PROMISE ACK 边界 | 实现决策 | server push 非目标但 SETTINGS ACK 前后语义需固定 | 不新增 API | 收到 `PUSH_PROMISE` => GOAWAY/PROTOCOL_ERROR；本端始终不启用 push | `tests/http2_client_tests.cpp` | Chunk 1.1 / Chunk 1.4 / Chunk 7 |
| HTTP/2 full multiplexing/server push/priority | full multiplexing 延期，server push/priority 非目标或受限处理 | 多流调度、bounded stream table、priority scheduler 和 push authority/cache 都需单独 API 与内存上限 | 后续新增多流 API；当前不新增 | 当前不宣传完整多流语义；push 禁用；priority 不作为公共调度能力 | `tests/http2_client_tests.cpp`, docs | Chunk 7 |
| h2c | 保留 legacy/test path，文档化 | RFC 9113 已移除 h2c；项目已有代码和样例 | 文档说明，不作为 TLS 主路径 | 仅明确配置时使用 | `tests/http2_client_tests.cpp` | Chunk 1.4 |
| WebSocket 协议错误后 transport 关闭 | 实现 | RFC 6455 close 后连接不可继续；内核资源必须及时释放 | 不新增 API | 发送 close 后关闭 TCP/TLS，handle `Connected=false` | `tests/websocket_client_tests.cpp`, `tests/high_level_api_tests.cpp` | Chunk 2.1 |
| WebSocket AutoReplyPing 小 buffer | 实现 | 控制帧处理不应受应用消息输出 buffer 限制 | 不新增 API | 125 字节 Ping 可自动 Pong | `tests/websocket_client_tests.cpp` | Chunk 2.2 |
| WebSocket 大消息发送契约 | 实现决策 | `MaxMessageBytes` 与 16KB scratch 口径冲突 | 可能文档/API 限制 | 自动分片或返回明确容量错误 | `tests/websocket_client_tests.cpp`, `tests/high_level_api_tests.cpp` | Chunk 2.3 |
| WebSocket fragmented send 总长度 | 实现 | 防止绕过 `MaxMessageBytes` | 不新增 API | 超限返回 `STATUS_BUFFER_TOO_SMALL` 或参数错误并关闭/拒发 | `tests/websocket_client_tests.cpp` | Chunk 2.3 |
| WebSocket public 校验一致性 | 实现 | test transport 与真实路径不能语义漂移 | 不新增 API | subprotocol/close code/reason UTF-8 在 engine 层拒绝 | `tests/high_level_api_tests.cpp` | Chunk 2.4 |
| WebSocket 出站 text UTF-8 public 校验 | 实现 | RFC 6455 text message 必须是有效 UTF-8；test transport 不应绕过真实路径语义 | 不新增 API | 无效 UTF-8 返回 `STATUS_INVALID_PARAMETER` 且不发帧 | `tests/high_level_api_tests.cpp`, `tests/websocket_client_tests.cpp` | Chunk 2.4 |
| WebSocket terminal transport error state sync | 实现 | send/receive timeout、cancel、disconnect、TLS/WSK terminal status 后连接不可继续 | 不新增 API | `Connected=false`，transport close exactly once | `tests/websocket_client_tests.cpp`, `tests/high_level_api_tests.cpp` | Chunk 2.1 |
| WebSocket 主动 close handshake | 实现决策并文档化 | RFC 6455 close handshake 与内核资源释放都需要确定口径 | 不新增 API | 主动 close 可发送 close frame 后关闭 transport；收到 peer close 时 echo 后关闭 | `tests/websocket_client_tests.cpp`, `tests/high_level_api_tests.cpp` | Chunk 2 / Chunk 7 |
| WebSocket frame metadata/partial receive | 延期 | 需要稳定 ABI 和 bounded buffering | 后续新增 API | 当前继续完整消息聚合 | `tests/websocket_client_tests.cpp` | Chunk 7 |
| WebSocket permessage-deflate/extensions | 非目标 | 内核内存、CPU、压缩炸弹、context takeover 策略需单独设计 | 不新增 API | 服务端返回扩展即拒绝握手 | `tests/websocket_client_tests.cpp` | Chunk 7 |
| WebSocket custom opening headers | 延期 | Origin/Authorization/Cookie 需要 header validation 和敏感头策略 | 后续新增 API | 当前不作为公开能力 | `tests/websocket_client_tests.cpp` | Chunk 7 |
| WebSocket over HTTP/2 RFC 8441 | 延期/非目标 | 当前 WebSocket 主路径是 HTTP/1.1 Upgrade；extended CONNECT 需 HTTP/2 SETTINGS 与 :protocol 支持 | 后续新增 API | 当前不协商 | `tests/http2_client_tests.cpp`, `tests/websocket_client_tests.cpp` | Chunk 7 |
| TLS 1.3 ServerHello legacy/session id | 实现 | RFC 8446 严格性，防止协商错误 | 不新增 API | 协议错误，handshake 失败 | `tests/tls_record_tests.cpp` | Chunk 3.1 |
| TLS 1.3 KeyUpdate | 实现或明确拒绝 | 当前 post-handshake 支持不完整 | 不新增 API | 若不支持，返回明确错误并关闭 | `tests/tls_record_tests.cpp` | Chunk 3.1 |
| TLS 1.2 EMS/renegotiation_info | 实现 | RFC 9325 现代 TLS 1.2 加固要求 | 不新增 API | 缺 EMS 按策略拒绝或 unsupported | `tests/tls_record_tests.cpp` | Chunk 3.2 |
| TLS 1.2 ALPN 严格解析 | 实现 | ALPN mismatch 不能被宽松解析绕过 | 不新增 API | malformed list 返回协议错误 | `tests/tls_record_tests.cpp` | Chunk 3.3 |
| TLS 1.3 early data 拒绝后语义 | 实现决策 | 0-RTT replay/重发不能静默成功 | 可能影响 HTTP option | 失败或显式重发策略 | `tests/tls_record_tests.cpp`, `tests/khttp_tests.cpp` | Chunk 3.3 |
| TLS 1.2 session resumption | 延期或实现前先设计 | 当前仅消费 NewSessionTicket，未恢复会话；`EnableSessionResumption` 不能暗示 TLS1.2 已支持 | 不新增 API 或补协议版本语义 | 未实现时不缓存/不恢复 TLS1.2 ticket | `tests/tls_record_tests.cpp` | Chunk 3.3 |
| TLS client certificate | 延期 | 需要 kernel private key handle、CertificateVerify、TLS1.2/1.3 transcript 设计 | 后续新增 credential API | 服务器要求时返回不支持或 handshake 失败 | `tests/tls_record_tests.cpp` | Chunk 7 |
| OCSP/CRL | 非目标 | 网络重入、缓存、软/硬失败策略复杂 | 不新增 API | `RequireRevocationCheck` 返回 `STATUS_NOT_SUPPORTED` | `tests/tls_record_tests.cpp` | Chunk 7 |
| IDNA | 非目标 | IDNA2008/UTS #46 选择影响证书匹配安全 | 不新增 API | 非 ASCII host 拒绝 | `tests/tls_record_tests.cpp` | Chunk 7 |
| Name Constraints | 当前明确不完整，触发拒绝；完整实现延期 | RFC 5280 完整策略复杂 | 不新增 API | `STATUS_NOT_SUPPORTED`，不得静默放行 | `tests/tls_record_tests.cpp` | Chunk 3.4 / Chunk 7 |
| TBSCertificate 内外签名算法一致性 | 实现 | PKIX 基础完整性 | 不新增 API | 不一致拒绝链 | `tests/tls_record_tests.cpp` | Chunk 3.4 |
| 重复证书扩展 | 实现 | RFC 5280 禁止同一 certificate extension 出现多个实例 | 不新增 API | 重复任意 extension OID 均拒绝 | `tests/tls_record_tests.cpp` | Chunk 3.4 |
| CNG DISPATCH_LEVEL crypto | 非目标，除非单独设计 | 当前 provider 不使用 `BCRYPT_PROV_DISPATCH`，TLS/证书/crypto 要求 PASSIVE_LEVEL | 不新增 API | DISPATCH_LEVEL 调用返回错误或被入口拒绝 | `tests/tls_record_tests.cpp`, `tests/khttp_tests.cpp` | Chunk 3 / Chunk 6 |
| ChaCha20-Poly1305/X25519/EdDSA | 延期 | 依赖内核 CNG 可用性、互通收益和测试向量 | 后续 cipher/group API | 未 offer/不协商 | `tests/tls_record_tests.cpp` | Chunk 7 |
| CBC/RSA key exchange | 非目标 | 不符合现代安全子集，风险高 | 不新增 API | 不协商 | `tests/tls_record_tests.cpp` | Chunk 7 |
| HTTP transfer-coding 参数/空成员 | 实现收紧 | framing 安全优先，避免宽松解析歧义 | 不新增 API | 协议错误拒绝 | `tests/http_parser_tests.cpp` | Chunk 4.1 |
| close-delimited transfer coding EOF 语义 | 实现测试 | `Transfer-Encoding: gzip` 或 `chunked,gzip` 需等 EOF 并不可复用 | 不新增 API | EOF 前 `STATUS_MORE_PROCESSING_REQUIRED` | `tests/http_parser_tests.cpp`, `tests/khttp_tests.cpp` | Chunk 4.1 |
| Expect: 100-continue | 延期决策 | 需要 send headers/wait/send body 有界状态机；普通透传并立即发 body 语义不安全 | 可能新增 option | 未支持状态机时，带 body 请求发送前返回 `STATUS_NOT_SUPPORTED` | `tests/khttp_tests.cpp` | Chunk 4.2 |
| 请求 TE/Trailer/request trailers | 延期 | request trailer 需要 API 和 forbidden field 规则 | 可能新增 API | 当前不支持返回 `STATUS_NOT_SUPPORTED` | `tests/http_parser_tests.cpp`, `tests/khttp_tests.cpp` | Chunk 4.2 |
| HTTP proxy/CONNECT tunnel | 非目标 | CONNECT 隧道会引入代理认证、absolute-form、authority-form、TLS over tunnel 和连接池身份边界 | 未来如支持需新增 proxy API | 当前不配置代理；CONNECT/代理隧道不作为成功路径 | docs/tests | Chunk 7 |
| CONNECT/TRACE/custom method 高层 API | 非目标或延期 | CONNECT 与 proxy 策略相关，TRACE 安全收益低 | 可能新增 custom method | 当前保持拒绝或文档非目标 | `tests/khttp_tests.cpp` | Chunk 4.2 |
| Content-Encoding compress/x-compress | 决策后实现或拒绝 | decoder 有能力但 content-coding parser 不接受 | 不新增 API | 支持解码或 `STATUS_NOT_SUPPORTED` | `tests/http_parser_tests.cpp` | Chunk 4.3 |
| header 字段合并/Set-Cookie 例外 | 延期实现 | HTTP 字段语义影响 API 行为 | 可能新增 helper API | 当前按名首个/按 index 枚举，文档说明 | `tests/khttp_tests.cpp` | Chunk 4.3 |
| URL path 8000 octets 互通目标 | 实现或文档化 | RFC 9110 建议接收至少 8000 octets URI | 可能调大 buffer | 超出上限返回 `STATUS_BUFFER_TOO_SMALL` | `tests/khttp_tests.cpp` | Chunk 4.4 |
| HTTP request parser/server role | 非目标 | 当前项目定位为客户端协议栈 | 不新增 API | 不提供入站 request parser | docs | Chunk 7 |
| Accept-Encoding qvalue/content negotiation | 延期/文档化 | 当前仅默认发送 header 并按 decoder 子集处理响应 | 不新增 API | 不宣传完整协商语义 | `tests/http_parser_tests.cpp`, docs | Chunk 4.3 / Chunk 7 |
| URI percent/host normalization boundary | 实现决策/文档化 | URL parser 不能隐式重写证书/DNS/HTTP identity | 不新增 API | path/query 按字节透传或固定校验；非 ASCII host 拒绝；IPv6 zone id 拒绝或明确支持 | `tests/khttp_tests.cpp` | Chunk 4.4 |
| RFC 9111 cache | 延期 | 需要 bounded storage 和 revalidation 策略 | 后续新增 cache API | 当前不宣传缓存语义 | docs/tests | Chunk 7 |
| Range/conditional request 语义 | 延期 | 可作为普通 header pass-through；完整语义需响应校验和缓存合并 | 可能新增 helper API | 当前不宣传完整语义 | docs/tests | Chunk 7 |
| Async cancel + release | 实现 | worker 需要可靠观察 cancel；句柄释放不能破坏内部状态 | 不新增 API | callback/free exactly once | `tests/khttp_tests.cpp` 或新增 async tests | Chunk 5.1 |
| DNS resolve 可取消 | 延期/文档 | WSK resolve 边界需单独设计 | 可能新增 cancel token | 已文档化：resolve 进入 provider 后不承诺取消 | `tests/khttp_tests.cpp` | Chunk 5.2 |
| DNS TTL/negative cache/flush | 延期 | 当前固定 TTL 更简单可测 | 可能新增 flush API | 已文档化：固定 5 分钟正向 TTL，无 negative cache/公共 flush | `tests/khttp_tests.cpp` | Chunk 5.2 |
| DNS cache global scope | 实现决策/文档化 | 当前缓存为全局，`Shutdown` 清空语义会影响其他 client | 不新增 API | 已文档化：全局 16 槽缓存，任一 `WskClient::Shutdown()` 清空 | `tests/khttp_tests.cpp` | Chunk 5.2 |
| Happy Eyeballs | 延期 | 并行 IPv4/IPv6 影响 async/timeout/资源预算 | 不新增 API | 已测试/文档化：按 `ResolveAll` 顺序逐个连接 | `tests/khttp_tests.cpp` | Chunk 5.2 |
| MaxConnectionsPerHost 维度 | 实现决策 | 当前按完整 pool key，名称可能误导 | 文档明确 | 已实现：scheme/host/port/address-family host 配额，复用仍按完整 TLS 身份 key | `tests/khttp_tests.cpp` | Chunk 5.3 |
| WSK fake late completion tests | 实现 | 内核 socket 所有权硬边界 | 不新增 API | 已测试：connect/send/receive cancel/timeout close exactly once，取消后不保留 socket | `tests/khttp_tests.cpp` | Chunk 5.4 |
| 直接 new/delete 清理 | 实现 | 项目约束禁止；当前虽重载到 NonPaged pool 仍需显式 allocator | 内部 allocator/pool wrapper | 新代码不得直接 new/delete | 全量测试 + Debug build | Chunk 6 |
| Core/net/engine direct new/delete cleanup | 实现 | allocator 清理不能只覆盖 HTTP/2/TLS/WebSocket | 内部 allocator/pool wrapper | 覆盖 WSK/Async/HandleAlloc/KernelHttpConfig/HeapArray/HttpEngine/Engine | `tests/khttp_tests.cpp` | Chunk 0A / Chunk 6.4 |
| Paged pool public API mismatch | 实现或文档化 | public enum 暴露 `Paged`，但 engine/workspace 只接受 NonPaged | 删除/改名或文档化 | 非 NonPaged 固定 `STATUS_INVALID_PARAMETER` | `tests/khttp_tests.cpp` | Chunk 0A |
| WebSocket receive 高频分配 | 实现 | 默认 1 MiB per receive nonpaged 分配有压力 | 内部 workspace buffer | bounded reuse | `tests/websocket_client_tests.cpp` | Chunk 6.3 |

## 实现顺序

1. 先完成文档复核循环，直到后续子代理不再发现新增遗漏。
2. 先执行 `Chunk 0A` 的 Async 生命周期和 allocator baseline，避免后续协议批次继续扩散旧生命周期/分配模型。
3. 再修已支持子集内会导致协议错误、安全或资源生命周期问题的项：HTTP/2/HPACK、WebSocket close/control、TLS 严格性、HTTP/1.1 framing。
4. 再修 WSK/DNS/连接池和剩余内核内存约束。
5. 最后处理可延期宽度能力或仅文档化非目标。

## 错误码原则

- 调用方参数非法：`STATUS_INVALID_PARAMETER`。
- 能力明确未实现：`STATUS_NOT_SUPPORTED`。
- 对端协议违规：返回现有协议错误 NTSTATUS，并在可用协议层发送 close/RST/GOAWAY/alert。
- 缓冲或配置上限不足：`STATUS_BUFFER_TOO_SMALL` 或现有容量错误，不能截断成功。
- 连接不可继续：设置 handle/connection 状态为 disconnected，底层 transport close exactly once。
