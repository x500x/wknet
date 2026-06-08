# HTTP/WebSocket Protocol Remediation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** 修复 HTTP、WebSocket、WSK/TLS/HTTP2/HPACK 审计中发现的协议正确性与内核所有权缺口，让项目保持明确、可测试的 Windows kernel HTTP/WebSocket 客户端协议子集。

**Architecture:** 先修会造成安全泄露、重复请求、socket 所有权不清或内存越界的 P0 问题，再补 HTTP/2/HPACK/TLS/证书负向语义。所有改动都按现有分层落点推进：HTTP engine、WebSocket codec/client、WSK transport、TLS connection、HTTP2 connection、HPACK、证书校验。

**Tech Stack:** Windows kernel C++ under `/kernel`, WSK, kernel CNG/BCrypt, custom HTTP/1.x parser, custom WebSocket, custom TLS 1.2/1.3, custom HTTP/2+HPACK, MSBuild/user-mode protocol tests through `pwsh`. 不运行被禁止的 `tests/integration/https_smoke.ps1 -SkipDriverBuild`。

---

## 执行规则

- 使用 `pwsh`，不要使用 `powershell`。
- 不要提交；只有用户明确要求时才 git commit。
- 不引入 WinHTTP、WinINet、SChannel 作为内核主路径。
- 不用兜底重试掩盖协议错误；所有 retry、redirect、TLS 版本选择都必须有明确语义。
- 代码变更后必须运行对应测试和 Debug x64 构建；保持最高警告等级与 warning-as-error。
- 不要运行禁止的 integration smoke 命令。

## 执行结果

- 状态：本计划 Task 1-21 已执行完成，所有复选框按最终状态标记为完成。
- 测试：已重新构建并运行全部用户态协议测试：`http_parser_tests`、`websocket_frame_tests`、`websocket_client_tests`、`http2_frame_tests`、`hpack_tests`、`http2_client_tests`、`tls_record_tests`、`high_level_api_tests`、`khttp_tests`，结果均通过。
- 构建：已运行 Debug x64 MSBuild 构建，结果为 0 warning、0 error。
- 禁令：未运行项目禁止的 `pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild`。
- Git：按用户要求未提交。

## 文件地图

- HTTP redirect/retry：`src/KernelHttpLib/engine/HttpEngine.cpp`、`include/KernelHttp/engine/Engine.h`、`include/KernelHttp/engine/HandleTypes.h`、`tests/khttp_tests.cpp`、`tests/high_level_api_tests.cpp`。
- HTTP parser/trailer：`src/KernelHttpLib/http/HttpParser.cpp`、`src/KernelHttpLib/http/HttpTransferCoding.cpp`、`include/KernelHttp/http/HttpResponse.h`、`tests/http_parser_tests.cpp`。
- 连接池：`src/KernelHttpLib/engine/ConnectionPool.cpp`、`include/KernelHttp/engine/ConnectionPool.h`、`tests/khttp_tests.cpp`。
- WebSocket：`src/KernelHttpLib/websocket/WebSocketFrame.cpp`、`include/KernelHttp/websocket/WebSocketFrame.h`、`src/KernelHttpLib/client/WebSocketClient.cpp`、`include/KernelHttp/client/WebSocketClient.h`、`src/KernelHttpLib/engine/WsEngine.cpp`、`tests/websocket_frame_tests.cpp`、`tests/websocket_client_tests.cpp`。
- WSK/TCP：`src/KernelHttpLib/net/WskSync.h`、`src/KernelHttpLib/net/WskSocket.cpp`、`include/KernelHttp/core/WskTransport.h`、`tests/khttp_tests.cpp` 或新增 focused fake WSK 测试。
- TLS：`src/KernelHttpLib/tls/TlsConnection.cpp`、`include/KernelHttp/tls/TlsConnection.h`、`src/KernelHttpLib/tls/TlsHandshake13.cpp`、`include/KernelHttp/tls/TlsHandshake13.h`、`tests/tls_record_tests.cpp`。
- 证书：`src/KernelHttpLib/tls/CertificateValidator.cpp`、`include/KernelHttp/tls/CertificateValidator.h`、`src/KernelHttpLib/tls/CertificateStore.cpp`、`tests/tls_record_tests.cpp`。
- HTTP/2：`src/KernelHttpLib/http2/Http2Connection.cpp`、`include/KernelHttp/http2/Http2Connection.h`、`src/KernelHttpLib/http2/Http2Frame.cpp`、`include/KernelHttp/http2/Http2Frame.h`、`tests/http2_client_tests.cpp`、`tests/http2_frame_tests.cpp`。
- HPACK：`src/KernelHttpLib/http2/Hpack.cpp`、`include/KernelHttp/http2/Hpack.h`、`tests/hpack_tests.cpp`。
- 文档：`docs/api-overview.md`、`docs/high-level-api.md`、`README.md`、`README_en.md`。

## Chunk 1: HTTP Redirect And Retry Safety

### Task 1: 修复 redirect URL 解析

**Files:**
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`
- Modify if API policy is added: `include/KernelHttp/engine/Engine.h`
- Test: `tests/khttp_tests.cpp`

- [x] 添加 failing tests：`Location: next`、`../next`、`?page=2`、`#fragment`、`/abs`、`//other.example/path`、absolute URL。
- [x] 实现 RFC 3986 URI-reference resolver：继承 scheme/authority，合并 path，处理 `.` / `..`，处理 query-only 与 fragment 继承。
- [x] 拒绝非法 scheme；默认只允许 `http`/`https`。
- [x] 对超出 workspace URL 缓冲的结果返回 `STATUS_BUFFER_TOO_SMALL`。
- [x] 运行：`pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`。

### Task 2: 修复 redirect 方法改写规则

**Files:**
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`
- Test: `tests/khttp_tests.cpp`

- [x] 添加 tests：POST/PUT/PATCH/DELETE 在 301、302、303、307、308 下的目标方法和 body。
- [x] 301/302：仅 POST 默认改写为 GET 并清 body。
- [x] 303：除 HEAD 外改写为 GET 并清 body。
- [x] 307/308：保持原方法和 body。
- [x] 若将来增加保留 POST 选项，默认行为仍按上述规则。
- [x] 运行 `khttp_tests.exe`。

### Task 3: 清理跨源 redirect 敏感头

**Files:**
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`
- Modify if options are needed: `include/KernelHttp/engine/Engine.h`
- Test: `tests/khttp_tests.cpp`

- [x] 添加 tests：`Authorization`、`Cookie`、`Proxy-Authorization`、自定义敏感头从 `https://a` redirect 到 `https://b` 或 `http://a`。
- [x] 默认跨 host/scheme/port redirect 清理 `Authorization`、`Cookie`、`Proxy-Authorization`。
- [x] 默认禁止或显式标记 HTTPS 到 HTTP 降级；若保持允许，必须清理敏感头并文档化。
- [x] 若支持自定义敏感头列表，限定最大数量与名称长度，避免内核动态增长。
- [x] 运行 `khttp_tests.exe` 和 `high_level_api_tests.exe`。

### Task 4: 收紧 stale/reused connection 自动重试

**Files:**
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`
- Test: `tests/khttp_tests.cpp`

- [x] 添加 tests：GET reused read failure 可 retry；POST/PUT/PATCH/DELETE reused failure 不自动 retry，除非能证明请求未发送。
- [x] 区分 connect 前失败、send 前失败、send 后失败、已收到部分响应。
- [x] 仅 safe/idempotent 方法或显式 opt-in 的请求可自动 fresh retry。
- [x] 保持 `ForceNew`、`NoPool` 策略语义不变。
- [x] 运行 `khttp_tests.exe`。

### Task 5: 执行 `MaxConnectionsPerHost`

**Files:**
- Modify: `src/KernelHttpLib/engine/ConnectionPool.cpp`
- Modify if state is needed: `include/KernelHttp/engine/ConnectionPool.h`
- Test: `tests/khttp_tests.cpp`

- [x] 添加 tests：同 host 超过 `MaxConnectionsPerHost` 时 acquire 行为受限；不同 host 不互相影响。
- [x] 在 connection pool 中按 key host/port/scheme 统计 active + idle 连接。
- [x] 达到上限时复用 idle、等待/失败策略需明确；同步 API 推荐返回明确状态，不无限等待。
- [x] 运行 `khttp_tests.exe`。

## Chunk 2: WebSocket Protocol Edges

### Task 6: 修复 WebSocket frame 长度溢出

**Files:**
- Modify: `src/KernelHttpLib/websocket/WebSocketFrame.cpp`
- Test: `tests/websocket_frame_tests.cpp`

- [x] 添加 125、126、65535、65536、`0x7fffffffffffffff`、`0x8000000000000000`、`SIZE_MAX` 边界 tests。
- [x] 在 `EncodeClientFrame` 入口拒绝 payload length > `0x7fffffffffffffff`。
- [x] 使用溢出安全加法计算 required size。
- [x] 若 required 超出 `SIZE_T`，返回 `STATUS_BUFFER_TOO_SMALL` 或 `STATUS_INVALID_PARAMETER`，并确保 `bytesWritten` 不溢出。
- [x] 运行 `websocket_frame_tests.exe`。

### Task 7: header 级协议错误发送 1002 close

**Files:**
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Test: `tests/websocket_client_tests.cpp`

- [x] 添加 tests：masked server frame、RSV、unknown opcode、fragmented ping、oversized ping、非最短 length。
- [x] 调整 `ReceiveMessage`：`DecodeFrameHeader` 返回协议错误时发送 close code 1002。
- [x] 标记连接不可继续，后续 receive/send 返回 disconnected。
- [x] 对输出容量不足的大帧发送 1009，报告 required length，不破坏状态。
- [x] 运行 `websocket_client_tests.exe` 和 `websocket_frame_tests.exe`。

### Task 8: 收紧 WebSocket 握手与高层语义

**Files:**
- Modify: `src/KernelHttpLib/websocket/WebSocketFrame.cpp`
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Modify: `src/KernelHttpLib/engine/WsEngine.cpp`
- Modify if enum changes: `include/KernelHttp/engine/Engine.h`
- Test: `tests/websocket_client_tests.cpp`
- Test: `tests/websocket_frame_tests.cpp`

- [x] 拒绝重复 `Sec-WebSocket-Accept`。
- [x] 明确 HTTP/1.0 101 策略：拒绝或文档化兼容；推荐拒绝。
- [x] 请求 subprotocol 按 token-list 校验，拒绝空 token、非法分隔、重复异常值。
- [x] 支持 0 长度 text/binary/continuation，或文档明确不支持并返回固定错误；推荐支持。
- [x] 决定出站 Text UTF-8 策略；推荐发送前校验，失败不发帧。
- [x] 增加 Pong 可观测能力，至少在 receive options 中允许返回 Pong。
- [x] 运行 WebSocket 两个测试二进制。

## Chunk 3: WSK Ownership And Cancellation

### Task 9: 修复 WSK 超时/取消 socket 所有权

**Files:**
- Modify: `src/KernelHttpLib/net/WskSync.h`
- Modify: `src/KernelHttpLib/net/WskSocket.cpp`
- Test: add focused fake WSK tests if harness exists, otherwise extend `tests/khttp_tests.cpp`

- [x] 添加 fake WSK resource counter：connect/send/receive timeout、caller cancel、late completion、connection pool release/close。
- [x] 超时或取消后不得仅清空 `socket_`/`dispatch_` 而失去 close 路径。
- [x] 设计明确状态：active socket、cancel pending、close pending、completion-owned cleanup、closed。
- [x] 如果 cancel 后 IRP 已完成但 socket 仍存在，必须调用 `WskCloseSocket` 或转移给 completion cleanup。
- [x] 保证 close exactly once，用户完成 callback exactly once。
- [x] 运行新增 focused tests 和 `khttp_tests.exe`。

### Task 10: 低层入口 IRQL 策略

**Files:**
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `src/KernelHttpLib/http2/Http2Connection.cpp`
- Test: nearest available user-mode tests with test IRQL hook, likely `tests/khttp_tests.cpp` plus focused unit hooks

- [x] 决定低层 client 类是 public-supported 还是 internal-only。
- [x] 若 public-supported，在 `Connect`/`Send`/`Receive`/`Initialize` 等入口显式检查 `PASSIVE_LEVEL`。
- [x] 若 internal-only，文档明确只能经 engine/khttp 入口调用。
- [x] 添加 raised IRQL tests，避免依赖 WSK/CNG 深层失败。
- [x] 运行相关测试。

## Chunk 4: TLS 1.3 PSK, HRR, And 0-RTT

### Task 11: 校验 PSK identity 与 ticket 绑定

**Files:**
- Modify: `include/KernelHttp/tls/TlsContext.h`
- Modify: `include/KernelHttp/tls/TlsConnection.h`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Test: `tests/tls_record_tests.cpp`

- [x] 添加 tests：server 选择 PSK 但 client 未提供、索引越界、ticket cipher mismatch、SNI/ALPN mismatch、过期 ticket。
- [x] 在 ticket 中记录 issue time、lifetime、SNI、ALPN、cipher suite、version。
- [x] 计算并校验 `obfuscated_ticket_age = age_ms + age_add`。
- [x] server selected identity 必须小于 offered identity count。
- [x] 不满足绑定条件时走 full handshake 或返回明确失败，不使用错误 resumption secret。
- [x] 运行 `tls_record_tests.exe`。

### Task 12: 修复 HRR 后 PSK binder

**Files:**
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify if helper needed: `src/KernelHttpLib/tls/TlsHandshake13.cpp`
- Test: `tests/tls_record_tests.cpp`

- [x] 添加 HRR + PSK ClientHello 测试，校验 second ClientHello binder 重新计算。
- [x] 在 HRR 生成第二个 ClientHello 前按 RFC 8446 synthetic message_hash 重建 transcript。
- [x] 对 second ClientHello 重新计算 binder，而不是复用第一次 binder。
- [x] 覆盖 HRR 后 selected identity 与 binder mismatch 负向测试。
- [x] 运行 `tls_record_tests.exe`。

### Task 13: 明确 0-RTT 策略

**Files:**
- Modify: `include/KernelHttp/tls/TlsConnection.h`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify if HTTP options are wired: `include/KernelHttp/engine/Engine.h`
- Test: `tests/tls_record_tests.cpp`
- Test if HTTP option changes: `tests/khttp_tests.cpp`

- [x] 保持默认禁用 0-RTT。
- [x] 若允许启用，必须要求调用方显式声明请求 replay-safe。
- [x] 禁止非幂等方法默认走 0-RTT。
- [x] 若 server 不接受 early data，不能把已发送 early data 的请求静默当作正常请求成功。
- [x] 运行 TLS 与 HTTP tests。

## Chunk 5: HTTP/2 And HPACK Strictness

### Task 14: HTTP/2 connection/frame 负向语义

**Files:**
- Modify: `src/KernelHttpLib/http2/Http2Connection.cpp`
- Modify: `src/KernelHttpLib/http2/Http2Frame.cpp`
- Test: `tests/http2_client_tests.cpp`
- Test: `tests/http2_frame_tests.cpp`

- [x] 添加 SETTINGS ACK payload 非 0 测试，期望 connection error。
- [x] 添加 PING/PING ACK payload 长度非 8 测试，期望 connection error。
- [x] 添加 stream 上 `PUSH_PROMISE` 测试，因 `ENABLE_PUSH=0` 发送 GOAWAY/PROTOCOL_ERROR。
- [x] 动态 SETTINGS `INITIAL_WINDOW_SIZE` 更新时调整现有 stream window。
- [x] 动态 SETTINGS `HEADER_TABLE_SIZE` 更新时同步 HPACK encoder/decoder 限制。
- [x] 运行 `http2_frame_tests.exe` 和 `http2_client_tests.exe`。

### Task 15: HTTP/2 header block 校验

**Files:**
- Modify: `src/KernelHttpLib/http2/Http2Connection.cpp`
- Modify if helper is split: `include/KernelHttp/http2/Http2Connection.h`
- Test: `tests/http2_client_tests.cpp`

- [x] 添加重复 `:status`、缺失 `:status`、伪头在普通头之后、大写字段名、`connection`/`upgrade` 等禁止字段测试。
- [x] 添加 `TE` 非 `trailers` 测试。
- [x] 添加 response trailers 测试：HEADERS after DATA 且 END_STREAM。
- [x] 解码后先校验 header block 语义，再暴露给 HTTP response。
- [x] 运行 `http2_client_tests.exe`。

### Task 16: HPACK table size 和内存策略

**Files:**
- Modify: `src/KernelHttpLib/http2/Hpack.cpp`
- Modify: `include/KernelHttp/http2/Hpack.h`
- Test: `tests/hpack_tests.cpp`

- [x] 添加 dynamic table size update 出现在非开头位置的负向测试。
- [x] 添加 header list size 超限测试。
- [x] 修改 decoder：table size update 只能在 header block 起始连续出现。
- [x] 实现 header list size 统计，受 SETTINGS_MAX_HEADER_LIST_SIZE 限制。
- [x] 修复 dynamic table eviction 后 data buffer 复用：压缩、环形或重建，避免 long-lived nonpaged 增长。
- [x] 对敏感请求头采用 never-indexed 编码，至少覆盖 `authorization`、`cookie`、`proxy-authorization`。
- [x] 运行 `hpack_tests.exe`、`http2_client_tests.exe`。

## Chunk 6: Certificate Validation Boundaries

### Task 17: 补 RFC 5280 负向策略

**Files:**
- Modify: `src/KernelHttpLib/tls/CertificateValidator.cpp`
- Modify: `include/KernelHttp/tls/CertificateValidator.h`
- Test: `tests/tls_record_tests.cpp`

- [x] 添加 Name Constraints DNS/IP permitted/excluded 测试。
- [x] 添加 pathLen + self-issued 中间证书测试。
- [x] 添加外部 trust anchor pathLen/basicConstraints 约束测试。
- [x] 添加 IDNA host 测试：明确拒绝非 ASCII，或实现 IDNA 规范化后匹配。
- [x] 添加 revocation-required 测试：未实现 OCSP/CRL 时返回 `STATUS_NOT_SUPPORTED`。
- [x] 实现或明确拒绝上述策略，不能静默放行。
- [x] 运行 `tls_record_tests.exe`。

## Chunk 7: HTTP Trailer And Streaming Boundaries

### Task 18: trailer 校验与 API 策略

**Files:**
- Modify: `src/KernelHttpLib/http/HttpParser.cpp`
- Modify: `src/KernelHttpLib/http/HttpTransferCoding.cpp`
- Modify if exposing: `include/KernelHttp/http/HttpResponse.h`
- Test: `tests/http_parser_tests.cpp`

- [x] 添加 malformed trailer field-name 测试。
- [x] 添加禁止 trailer 字段测试，例如 framing/routing/auth 相关字段。
- [x] 至少在 parser 内校验 trailer 语法并拒绝禁止字段。
- [x] 若暴露 trailer，设计固定容量结构，避免未界定的堆增长。
- [x] 运行 `http_parser_tests.exe`。

### Task 19: 大响应与 callback 语义文档/改造

**Files:**
- Modify if behavior changes: `src/KernelHttpLib/engine/HttpEngine.cpp`
- Modify docs: `docs/api-overview.md`
- Modify docs: `docs/high-level-api.md`
- Test if behavior changes: `tests/khttp_tests.cpp`

- [x] 决定当前 body callback 是否继续保持“聚合后回调”。
- [x] 若保持，文档明确它不是边收边流式，并说明 `MaxResponseBytes` 与 nonpaged pool 影响。
- [x] 若改造成 streaming，先写 failing tests：分块回调顺序、解压后分块、错误中止、连接复用。
- [x] 不把部分 streaming 作为兜底路径引入。

## Chunk 8: Documentation And Verification

### Task 20: 更新能力边界文档

**Files:**
- Modify: `README.md`
- Modify: `README_en.md`
- Modify: `docs/api-overview.md`
- Modify: `docs/high-level-api.md`
- Reference: `docs/plans/2026-06-09-http-websocket-protocol-audit-notes.md`

- [x] 明确“支持现代内核客户端协议子集”，不是完整 RFC optional 全量。
- [x] 记录 unsupported/limited：chunked upload、trailer exposure、proxy/CONNECT、WebSocket extensions/partial receive、TLS client cert/OCSP/CRL/IDNA、HTTP/2 push/priority/full multiplexing。
- [x] 记录 redirect 安全策略、retry 策略、0-RTT 策略。
- [x] 记录同步 API 与低层 API 的 IRQL 要求。

### Task 21: 最终测试与构建

**Files:**
- No source edits unless failures require fixes.

- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_frame_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_frame_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\hpack_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`
- [x] Run Debug x64 build without artificial timeout: `pwsh -NoLogo -NoProfile -Command '& msbuild.exe .\KernelHttp.sln /p:Configuration=Debug /p:Platform=x64 /m'`
- [x] Confirm highest warning level and warnings-as-errors remain enabled.
- [x] Do not commit unless the user explicitly asks.

## 完成标准

- redirect 不泄露跨源敏感头，不错误改写非 POST 方法，支持 RFC 3986 相对 Location。
- stale/reused connection retry 不会重放非幂等请求。
- WebSocket 对长度边界安全，对协议错误发送正确 close，并保留连接状态一致性。
- WSK timeout/cancel 后 native socket 所有权明确，不泄漏，不重复 close。
- TLS 1.3 PSK/HRR/0-RTT 不违反 binder、identity、age、replay 策略。
- HTTP/2/HPACK 负向语义更接近 RFC 9113/RFC 7541，尤其 header block、PUSH_PROMISE、ACK length、dynamic table。
- 证书校验对 unsupported RFC 5280 能力明确失败或文档化，不静默放行。
- 所有相关用户态测试和 Debug x64 构建通过。
