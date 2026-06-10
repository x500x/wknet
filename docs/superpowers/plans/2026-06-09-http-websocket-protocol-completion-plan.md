# HTTP WebSocket TLS HTTP2 Full Stack Completion Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将当前 Windows kernel driver 客户端协议子集补到“已声明能力严格、可测试、无静默放行”，并把仍缺失的 HTTP/WebSocket/TLS/HTTP2/WSK 宽度按模块分批补齐或显式列为非目标。

**Architecture:** 先修已支持子集内的协议正确性、安全和内核所有权问题，再扩展可控协议宽度。每批按模块收敛在约 3k 行变更内：先补正/负向测试，再补实现和文档，最后运行对应测试与 Debug x64 构建；不使用 WinHTTP、WinINet、SChannel 作为内核主路径，不把重试或降级当作正式架构手段。

**Tech Stack:** Windows kernel C++ under `/kernel`, WSK, kernel CNG/BCrypt, custom HTTP/1.x parser, custom WebSocket client, custom TLS 1.2/1.3, custom HTTP/2 + HPACK, MSBuild/user-mode protocol tests through `pwsh`. 不运行被禁止的 `pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild`。

---

## 执行规则

- 使用 `pwsh`，不要使用 `powershell`。
- 本计划文档不提交；只有用户明确要求提交时才 git commit。
- 每个实现任务先写测试或补测试，再实现。
- 代码变更后必须运行相关用户态测试；完成一个实现批次后运行 Debug x64 构建且 warning-as-error 保持 0 warning。
- Debug/Release 构建不要设置人为超时等待。
- 每个实现批次运行测试前先构建对应用户态测试二进制，避免运行旧 exe。
- 直接 `new/delete/new[]/delete[]` 视为待整改约束风险；新增代码不得引入新的直接 `new/delete`。
- lib 中避免栈上大对象；高频堆分配优先改为 workspace/pool 常驻或显式 bounded allocator。
- 所有同步网络/TLS/证书/crypto 路径继续要求 `PASSIVE_LEVEL`。
- 当前 CNG provider 不使用 `BCRYPT_PROV_DISPATCH`；TLS/证书/crypto 不得从 `DISPATCH_LEVEL` 调用。若未来支持 `DISPATCH_LEVEL`，必须单独设计 dispatch provider、nonpaged object buffer 和覆盖测试。
- 未实现能力必须返回固定错误、拒绝协商或文档列为非目标，不能静默成功。

## 第一轮子代理审计输入

- Boyle：HTTP/1.1、HTTP 语义、transfer/content coding。
- Dewey：WebSocket RFC 6455。
- Avicenna：TLS/证书/内核 CNG。
- Gauss：HTTP/2 与 HPACK。
- Kierkegaard：WSK、异步、DNS、连接池、跨层集成。

## 文件地图

- 说明文档：`docs/plans/2026-06-09-http-websocket-protocol-recheck-notes.md`
- 决策表：`docs/plans/2026-06-09-http-websocket-protocol-scope-decisions.md`
- HTTP/1.1：`include/KernelHttp/http/*`, `src/KernelHttpLib/http/*`, `src/KernelHttpLib/engine/HttpEngine.cpp`, `src/KernelHttpLib/client/HttpClient.cpp`, `tests/http_parser_tests.cpp`, `tests/khttp_tests.cpp`
- WebSocket：`include/KernelHttp/websocket/WebSocketFrame.h`, `include/KernelHttp/client/WebSocketClient.h`, `include/KernelHttp/khttp/WebSocket.h`, `src/KernelHttpLib/websocket/WebSocketFrame.cpp`, `src/KernelHttpLib/client/WebSocketClient.cpp`, `src/KernelHttpLib/engine/WsEngine.cpp`, `tests/websocket_frame_tests.cpp`, `tests/websocket_client_tests.cpp`
- TLS/证书：`include/KernelHttp/tls/*`, `src/KernelHttpLib/tls/*`, `src/KernelHttpLib/crypto/*`, `src/KernelHttpLib/client/HttpsClient.cpp`, `tests/tls_record_tests.cpp`
- HTTP/2/HPACK：`include/KernelHttp/http2/*`, `src/KernelHttpLib/http2/*`, `src/KernelHttpLib/client/Http2Client.cpp`, `tests/http2_frame_tests.cpp`, `tests/http2_client_tests.cpp`, `tests/hpack_tests.cpp`
- WSK/异步/连接池：`include/KernelHttp/net/*`, `include/KernelHttp/core/*`, `include/KernelHttp/engine/*`, `src/KernelHttpLib/net/*`, `src/KernelHttpLib/engine/Async.cpp`, `src/KernelHttpLib/engine/ConnectionPool.cpp`
- 文档：`README.md`, `README_en.md`, `docs/api-overview.md`, `docs/high-level-api.md`, `docs/low-level-api.md`

---

## Chunk 0: 文档复核循环

### Task 0.1: 第二轮遗漏审计

**Files:**
- Modify: `docs/superpowers/plans/2026-06-09-http-websocket-protocol-completion-plan.md`
- Modify: `docs/plans/2026-06-09-http-websocket-protocol-recheck-notes.md`
- Modify: `docs/plans/2026-06-09-http-websocket-protocol-scope-decisions.md`

- [x] 启动第二轮 gpt-5.5 xhigh 子代理，分别复核 HTTP/1.1、WebSocket、TLS/证书、HTTP/2/HPACK、WSK/跨层。
- [x] 子代理只读复核，不修改文件，不运行禁止 smoke 脚本。
- [x] 要求子代理输出“遗漏/误判/优先级调整/测试缺口/是否可进入实现”。
- [x] 若发现遗漏，更新三份文档并再次启动复核。
- [x] 直到第二轮或后续轮次返回“未发现新增遗漏/仅有已记录事项”为止。

---

## Chunk 0A: Kernel Lifetime And Allocator Baseline

### Task 0A.1: Async 生命周期前置修复

**Files:**
- Modify: `src/KernelHttpLib/engine/Async.cpp`
- Modify: `include/KernelHttp/engine/Async.h`
- Test: `tests/khttp_tests.cpp`
- Test if added: `tests/async_tests.cpp`

- [x] 写测试：cancel 后立即 release，worker 仍能观察到 cancel。
- [x] 写测试：wait 后 release、session close 等待 in-flight、websocket close 等待 receive/send。
- [x] 拆分“用户句柄关闭”和“内部 operation 有效性/引用计数”。
- [x] 保证 callback exactly once、operation free exactly once。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`

### Task 0A.2: 显式 allocator/pool wrapper 前置设计

**Files:**
- Modify: `include/KernelHttp/KernelHttpConfig.h`
- Modify: `include/KernelHttp/core/WorkspaceScratchAllocator.h`
- Modify if needed: `include/KernelHttp/http/HttpTypes.h`
- Modify if needed: `include/KernelHttp/engine/HandleAlloc.h`
- Test: all touched protocol tests

- [x] 建立显式 NonPaged allocator/pool wrapper，后续任务不得继续扩散直接 `new/delete`。
- [x] 列出现有 `HeapArray`/`HeapObject`/全局 `operator new/delete` 调用边界。
- [x] 明确 `Paged` public enum 与当前 NonPaged-only 实现的契约：删除、改名，或固定 `STATUS_INVALID_PARAMETER` 并文档化。
- [x] Run adjacent tests for each converted module.

Status 2026-06-09:
- Baseline complete: `AllocateNonPagedPoolBytes`/`FreeNonPagedPoolBytes` now own byte allocation; `AllocateNonPagedObject`/`FreeNonPagedObject` and array helpers are the only approved object/array construction wrappers for new work.
- Boundary recorded: `HeapArray`/`HeapObject` and global `operator new/delete` now route through the allocator helpers. Existing direct `new/delete/new[]/delete[]` outside these wrappers remains deferred to Chunk 6.1-6.4 and must not grow.
- `Paged` remains a reserved public ABI value; engine and khttp session/workspace creation reject it with `STATUS_INVALID_PARAMETER`.
- Rebuilt and ran all user-mode protocol tests, then ran `Debug|x64` build with 0 warning and 0 error.

---

## Chunk 1: HTTP/2 And HPACK Strictness

### Task 1.1: 连接级协议错误分类与 frame 入口校验

**Files:**
- Modify: `src/KernelHttpLib/http2/Http2Connection.cpp`
- Modify: `src/KernelHttpLib/http2/Http2Frame.cpp`
- Modify: `include/KernelHttp/http2/Http2Connection.h`
- Test: `tests/http2_client_tests.cpp`
- Test: `tests/http2_frame_tests.cpp`
- Test: `tests/hpack_tests.cpp`

- [x] 写测试：HPACK 解码非法索引、非法 Huffman、EOS、整数溢出时发送 GOAWAY `COMPRESSION_ERROR`，而不是仅 RST_STREAM。
- [x] 写测试：DATA/HEADERS/RST_STREAM/CONTINUATION 在 stream 0、PRIORITY 在 stream 0、WINDOW_UPDATE stream 0/非 0 规则。
- [x] 写测试：合法/非法 frame size 与本端 advertised `SETTINGS_MAX_FRAME_SIZE` 一致。
- [x] 写测试：服务端 `SETTINGS_ENABLE_PUSH=1` 返回连接级 `PROTOCOL_ERROR`。
- [x] 写测试：`SETTINGS_INITIAL_WINDOW_SIZE > 2^31-1` 返回 `FLOW_CONTROL_ERROR`；`SETTINGS_MAX_FRAME_SIZE` 越界返回 `PROTOCOL_ERROR`。
- [x] 写测试：本端 SETTINGS 未 ACK 的超时/同步策略符合决策，必要时发送 `SETTINGS_TIMEOUT`。
- [x] 写测试：GOAWAY `last_stream_id` 语义固定，graceful GOAWAY 是否允许完成当前 stream 不得含糊。
- [x] 将 HPACK 压缩上下文错误映射为连接级错误。
- [x] 记录并修复 HPACK Huffman decode CPU 放大风险：改为 decode table 或加入有界预算和负向测试。
- [x] 集中校验 frame type 与 stream id 合法性，错误码按 RFC 9113 分类。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_frame_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\hpack_tests.exe'`

### Task 1.2: 接收侧 flow control 修正

**Files:**
- Modify: `src/KernelHttpLib/http2/Http2Connection.cpp`
- Modify: `src/KernelHttpLib/http2/Http2Stream.cpp`
- Modify: `include/KernelHttp/http2/Http2Stream.h`
- Test: `tests/http2_client_tests.cpp`

- [x] 写测试：响应 DATA 总量超过 65,535 字节，发送 stream WINDOW_UPDATE 后继续接收成功。
- [x] 写测试：非活动 stream 的 WINDOW_UPDATE 不得增加 connection send window。
- [x] 写测试：`SETTINGS_INITIAL_WINDOW_SIZE` 动态减少/增加时 active stream window 正确调整。
- [x] 修复接收 DATA 后 stream local window 回补状态。
- [x] 区分 connection window 与 stream window，避免非目标 stream 帧影响主 stream 发送窗口。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'`

### Task 1.3: HTTP/2 请求/响应 header 语义补强

**Files:**
- Modify: `src/KernelHttpLib/client/Http2Client.cpp`
- Modify: `src/KernelHttpLib/http2/Http2Connection.cpp`
- Test: `tests/http2_client_tests.cpp`

- [x] 写测试：ExtraHeaders 注入 `:path`、`:authority`、重复伪头、空字段名、CR/LF、大写字段名均被拒绝。
- [x] 写测试：HEAD/204/304 响应带 DATA 的处理符合 HTTP 语义。
- [x] 写测试：interim 1xx、101、1xx END_STREAM、最终响应后非法 HEADERS/DATA、trailer 带伪头、trailer 在 DATA 前。
- [x] 请求和响应均校验 RFC 9113 field validity：字段名禁止 `0x00-0x20`、大写、`0x7f-0xff`、非法冒号；字段值禁止 NUL/CR/LF、首尾 SP/HTAB。
- [x] 补 Host 与 `:authority` 策略：拒绝 Host，或仅允许与 `:authority` 规范化后完全一致。
- [x] 请求构造阶段拒绝伪头和 connection-specific header 注入；保留 `TE: trailers` 唯一例外。
- [x] 响应阶段将 HTTP 语义的无 body 规则应用到 HTTP/2 DATA。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'`

### Task 1.4: 动态 frame payload 与 h2c 策略

**Files:**
- Modify: `src/KernelHttpLib/http2/Http2Connection.cpp`
- Modify: `include/KernelHttp/http2/Http2Connection.h`
- Modify: `include/KernelHttp/client/Http2Client.h`
- Modify: `docs/high-level-api.md`
- Test: `tests/http2_client_tests.cpp`

- [x] 写测试：peer 合法提高 `SETTINGS_MAX_FRAME_SIZE` 后接收 32KB frame。
- [x] 将固定 16KB `framePayload_` 改为 bounded 动态/常驻 buffer，上限不超过协议和本端配置。
- [x] 明确 `h2c` 是 legacy/test path 还是继续公开能力；文档不得把 h2c 当 RFC 9113 主路径。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'`

Status 2026-06-09:
- Chunk 1 complete: HTTP/2/HPACK strictness, flow control, request/response header validation, trailer ordering, no-body DATA rejection, SETTINGS timeout/error mapping, 32KB inbound frame payload, and h2c documentation policy are implemented and covered.
- `Http2Connection` internal long-lived buffers now use explicit NonPaged allocator helpers instead of added direct `new/delete`.
- Rebuilt and ran the full user-mode protocol test set; ran Debug x64 solution build with 0 warning and 0 error.

---

## Chunk 2: WebSocket Close, Control Frames, And Memory

### Task 2.1: 协议错误后的 transport 终止语义

**Files:**
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Modify: `src/KernelHttpLib/engine/WsEngine.cpp`
- Modify: `include/KernelHttp/client/WebSocketClient.h`
- Test: `tests/websocket_client_tests.cpp`
- Test: `tests/high_level_api_tests.cpp`

- [x] 写测试：masked server frame、RSV、reserved opcode、非法 close payload 后发送 close 且底层 transport 关闭。
- [x] 写测试：协议错误后 `WsSend`/`WsReceive` 返回 disconnected，engine handle `Connected=false`。
- [x] 写测试：非协议错误的终端 transport status，包括 send/receive timeout、cancel、disconnect、TLS/WSK terminal status，也同步关闭并置 disconnected。
- [x] `FailConnectionWithClose` 发送 close 后关闭 TCP/TLS transport，保持 close exactly once。
- [x] engine 同步连接状态，避免调用方忘记 `WsClose` 时资源悬挂。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_frame_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`

### Task 2.2: 控制帧独立缓冲与 AutoReplyPing

**Files:**
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Modify: `src/KernelHttpLib/engine/WsEngine.cpp`
- Test: `tests/websocket_client_tests.cpp`

- [x] 写测试：`AutoReplyPing=true`、应用 output buffer 很小、服务端发送 125 字节 Ping，仍能自动 Pong。
- [x] 写测试：`AutoReplyPing=false` 时调用方可看到 Ping 并显式 `WsSendPong`。
- [x] Ping/Pong/Close 使用独立 bounded 控制帧缓冲，不受消息输出容量限制。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`

### Task 2.3: 发送大小契约与分片策略

**Files:**
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Modify: `src/KernelHttpLib/engine/WsEngine.cpp`
- Modify: `docs/high-level-api.md`
- Test: `tests/websocket_client_tests.cpp`
- Test: `tests/high_level_api_tests.cpp`

- [x] 决定大消息发送策略：自动分片，或公开单帧发送上限。
- [x] 写测试：大于 16KB 且小于 `MaxMessageBytes` 的消息发送行为符合决策。
- [x] 写测试：fragmented send 累计总长度不能超过 `MaxMessageBytes`。
- [x] 若实现自动分片，保持 UTF-8 跨帧校验和 control frame 互不干扰；每个 fragment 重新生成 masking key，首帧 Text/Binary，后续 Continuation，仅末帧 FIN=1，控制帧不得自动分片。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`

### Task 2.4: public API 校验一致性

**Files:**
- Modify: `src/KernelHttpLib/engine/WsEngine.cpp`
- Modify: `src/KernelHttpLib/khttp/WebSocket.cpp`
- Test: `tests/websocket_client_tests.cpp`
- Test: `tests/high_level_api_tests.cpp`

- [x] 将 subprotocol token、close code、close reason UTF-8、reason 长度校验上移到 engine/khttp。
- [x] 将 `WsSendText`/`KhWebSocketSendTextSync` 的 UTF-8 校验上移到 engine/khttp，使 test transport 与真实 `WebSocketClient` 路径一致；无效 UTF-8 返回 `STATUS_INVALID_PARAMETER` 且不发送。
- [x] 让真实 transport 路径和 test transport 路径的校验一致。
- [x] 补握手负例：未请求 subprotocol 却返回、重复 accept、响应扩展、HTTP/1.0 101。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`

Status 2026-06-09:
- Chunk 2 complete: WebSocket protocol-error paths now send close, close the underlying TCP/TLS transport exactly once, and synchronize engine handle state to disconnected on protocol errors and terminal transport statuses.
- Large WebSocket messages use automatic fragmentation instead of exposing a 16KB single-frame limit; each fragment is masked independently, uses Text/Binary then Continuation opcodes, and only the last fragment sets FIN.
- Ping/Pong/Close control frames use bounded control-frame buffers independent of application output buffer capacity, including 125-byte auto Pong when `AutoReplyPing=true`.
- Public validation is consistent across real and test transports for subprotocols, text UTF-8, close code/reason UTF-8 and reason length; handshake negatives for duplicate accept, unexpected subprotocol/extensions, and HTTP/1.0 101 are covered.
- Rebuilt and ran `websocket_client_tests.exe`, `websocket_frame_tests.exe`, `high_level_api_tests.exe`, and `khttp_tests.exe`; ran Debug x64 solution build with 0 warning and 0 error.

---

## Chunk 3: TLS And Certificate Strictness

### Task 3.1: TLS 1.3 ServerHello 与 post-handshake 严格性

**Files:**
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake13.cpp`
- Modify: `include/KernelHttp/tls/TlsHandshake13.h`
- Test: `tests/tls_record_tests.cpp`

- [x] 写测试：ServerHello `legacy_version != 0x0303` 被拒绝。
- [x] 写测试：`legacy_session_id_echo` 与 ClientHello 不一致被拒绝；当前空 session id 时非空 echo 被拒绝。
- [x] 写测试：重复 extension、HRR 重复、KeyShare 非 offered group 被拒绝。
- [x] 写测试：KeyUpdate 当前若不支持，必须发送/返回明确错误而不静默继续。
- [x] 补 alert/close_notify 策略，至少关闭时发送 close_notify 或文档明确当前行为。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`

### Task 3.2: TLS 1.2 RFC 9325 加固

**Files:**
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake12.cpp`
- Modify: `src/KernelHttpLib/tls/TlsContext.cpp`
- Modify: `include/KernelHttp/tls/TlsContext.h`
- Test: `tests/tls_record_tests.cpp`

- [x] 写测试：ClientHello 带 `extended_master_secret` 与 `renegotiation_info`。
- [x] 写测试：ServerHello 缺 EMS 时按策略拒绝或降到明确 unsupported，不继续普通 master secret。
- [x] 实现 EMS session hash 派生 master secret。
- [x] 禁止 renegotiation 或仅接受安全 renegotiation indication，不实现不安全重协商。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`

### Task 3.3: TLS ALPN、SNI 与 0-RTT/resumption 细化

**Files:**
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake12.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake13.cpp`
- Modify: `src/KernelHttpLib/client/HttpsClient.cpp`
- Test: `tests/tls_record_tests.cpp`
- Test: `tests/khttp_tests.cpp`

- [x] 写测试：TLS 1.2 ALPN list length、尾部垃圾、多个协议、未 offer 协议。
- [x] 写测试：SNI 非 ASCII、IP literal、空标签、过长 label 的策略。
- [x] 写测试：TLS 1.3 early data 被服务端拒绝后，HTTP 层不能静默把已发请求当成功；需要失败或明确重发策略。
- [x] 补 `HttpsClient` API/传参：显式 `EarlyDataReplaySafe`，回传 `EarlyDataAccepted`/`EarlyDataBytesSent`；服务器拒绝 early data 时必须失败或按 replay-safe 策略重发。
- [x] 如果支持 TLS 1.2 resumption，先设计 ticket/session id 绑定 SNI/ALPN/cipher/version。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`

### Task 3.4: PKI 完整性边界

**Files:**
- Modify: `src/KernelHttpLib/tls/CertificateValidator.cpp`
- Modify: `include/KernelHttp/tls/CertificateValidator.h`
- Test: `tests/tls_record_tests.cpp`

- [x] 写测试：TBSCertificate 内层 `signatureAlgorithm` 与外层 `signatureAlgorithm` 不一致被拒绝。
- [x] 写测试：重复 SAN、BasicConstraints、KeyUsage、EKU、NameConstraints 等扩展被拒绝或按 RFC 5280 明确处理。
- [x] 写测试：未知 critical extension、AKI/SKI、certificate policies 的策略。
- [x] 写测试：重复任意 certificate extension OID 均被拒绝。
- [x] Name Constraints 若仍不实现，继续明确返回 `STATUS_NOT_SUPPORTED`，不得部分匹配后放行。
- [x] OCSP/CRL 仍非目标时，`RequireRevocationCheck` 继续返回 `STATUS_NOT_SUPPORTED`。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`

Status 2026-06-09:
- Chunk 3 complete: TLS 1.3 now rejects bad ServerHello `legacy_version`, non-empty legacy session id for the empty-session ClientHello policy, duplicate ServerHello/EncryptedExtensions/NewSessionTicket extensions, and unsupported post-handshake KeyUpdate with explicit `STATUS_NOT_SUPPORTED`.
- TLS 1.2 ClientHello advertises `extended_master_secret` and safe `renegotiation_info`; ServerHello must carry EMS and safe renegotiation indication, and the handshake derives the master secret through EMS session hash before key block setup. TLS 1.2 ALPN parsing now rejects list-length mismatches, trailing bytes, multiple selected protocols, and unoffered protocols.
- SNI is DNS-only for TLS 1.2/1.3 ClientHello encoding: non-ASCII names, IP literals, empty labels, IPv6 literals, and labels longer than 63 bytes are rejected. TLS 1.3 0-RTT remains replay-safe gated; `HttpsClient` now passes `EarlyDataReplaySafe`, `EarlyDataAccepted`, and `EarlyDataBytesSent` through to TLS.
- PKI parsing now enforces TBSCertificate/outer signature algorithm consistency, rejects duplicate certificate extension OIDs, rejects unknown critical extensions, records certificatePolicies and rejects them as unsupported during validation, and keeps Name Constraints and revocation as explicit `STATUS_NOT_SUPPORTED` policies.
- Close-notify policy remains explicit in current code: received `close_notify` is treated as clean disconnect, unsupported TLS 1.3 post-handshake messages fail explicitly, and no silent continuation is allowed. TLS 1.2 resumption was not enabled in this chunk, so no TLS 1.2 ticket/session binding design was introduced.
- Rebuilt and ran `tls_record_tests.exe` and `khttp_tests.exe`; ran Debug x64 solution build with 0 warning and 0 error.

---

## Chunk 4: HTTP/1.1 Framing And Semantics

### Task 4.1: transfer-coding 语法硬化

**Files:**
- Modify: `src/KernelHttpLib/http/HttpTransferCoding.cpp`
- Modify: `src/KernelHttpLib/http/HttpParser.cpp`
- Test: `tests/http_parser_tests.cpp`
- Test: `tests/khttp_tests.cpp`

- [x] 写测试：`Transfer-Encoding: chunked;foo=bar`、`gzip;foo=bar`、空成员、尾逗号的策略。
- [x] 对 chunked/compression transfer coding 参数采用收紧策略：按对端协议错误拒绝；不保留兼容接受分支。
- [x] 写测试：`Transfer-Encoding: gzip` close-delimited 响应必须等 EOF 才完成且连接不可复用。
- [x] 写测试：`Transfer-Encoding: chunked, gzip` close-delimited 场景按 EOF 定界处理，不误认为硬性非法。
- [x] 统一测试 transport 与真实 socket 的 close-delimited 完成语义，避免 `MessageCompleteOnConnectionClose=true` 掩盖半截响应。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`

### Task 4.2: 请求语义与方法/API 边界

**Files:**
- Modify: `include/KernelHttp/engine/Engine.h`
- Modify: `include/KernelHttp/khttp/Types.h`
- Modify: `src/KernelHttpLib/http/HttpRequest.cpp`
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`
- Test: `tests/http_parser_tests.cpp`
- Test: `tests/khttp_tests.cpp`

- [x] 决定 `Expect: 100-continue` 是否进入支持范围；若支持，实现“先发头、等 100、再发 body”的有界状态机。
- [x] 本批不实现 `Expect` 状态机时，带 body 的 `Expect: 100-continue` 请求必须在发送前返回 `STATUS_NOT_SUPPORTED`，不得作为普通 header 发送并立即发送 body。
- [x] 决定请求 `TE`、`Trailer`、request trailers；若不支持，固定 `STATUS_NOT_SUPPORTED`。
- [x] 决定 CONNECT/TRACE/custom method 高层 API 边界；当前 proxy/CONNECT 非目标时保持拒绝。
- [x] 补用户手写 `Transfer-Encoding`、`Host`、`Content-Length`、`Connection` 的拒绝测试。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`

### Task 4.3: content coding 与 header 字段 API 语义

**Files:**
- Modify: `src/KernelHttpLib/http/HttpContentEncoding.cpp`
- Modify: `src/KernelHttpLib/http/HttpCoding.cpp`
- Modify: `src/KernelHttpLib/engine/Engine.cpp`
- Modify: `include/KernelHttp/engine/Engine.h`
- Test: `tests/http_parser_tests.cpp`
- Test: `tests/khttp_tests.cpp`

- [x] 决定 `Content-Encoding: compress/x-compress`：支持或明确 `STATUS_NOT_SUPPORTED`，与已有 `HttpCoding` 能力保持一致。
- [x] 文档化 `Accept-Encoding` qvalue/content negotiation 边界：当前不宣传完整协商语义，只发送默认 header 并按 decoder 子集处理响应。
- [x] 写测试：重复字段按名返回首个、按 index 枚举完整、`Set-Cookie` 不合并。
- [x] 设计字段特定合并 API 或文档说明当前 API 不做字段语义合并。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`

### Task 4.4: URL/request-target 与 HTTP 语义宽度

**Files:**
- Modify: `src/KernelHttpLib/engine/UrlParser.cpp`
- Modify: `include/KernelHttp/engine/HandleTypes.h`
- Modify: `docs/high-level-api.md`
- Test: `tests/khttp_tests.cpp`

- [x] 写测试：path 接近 8000 octets、query-only、IPv6 Host header、fragment stripping、userinfo reject。
- [x] 写测试/文档：percent-encoded path/query 不做解码或归一化，按字节透传；非法 percent triplet 策略固定。
- [x] 写测试：非 ASCII host/IDNA 非目标，URL parser 或 connect 前拒绝；IPv6 zone id 拒绝或明确支持。
- [x] 明确 origin-form、absolute-form、authority-form、asterisk-form 的客户端支持边界。
- [x] 条件请求、Range、缓存语义先作为普通 header pass-through 还是内核 cache API，写入决策表。
- [x] 若实现 RFC 9111 cache，单独设计 bounded cache policy/storage，不在本批混入。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`

Status: Completed on 2026-06-10.

- Transfer-coding parsing now rejects empty list members, trailing commas, and parameters on `chunked/gzip/deflate/compress`; close-delimited non-final `chunked` transfer-coding paths now require EOF and do not enter the pool.
- Request semantics now reject caller-controlled `Host`/`Content-Length`/`Connection`, unsupported `Transfer-Encoding`/`TE`/`Trailer`, body + `Expect: 100-continue`, and invalid public method enum values before transport.
- Response decoding supports `Content-Encoding: compress` / `x-compress`; response header APIs are documented and tested as first-by-name plus full index enumeration without `Set-Cookie` merging.
- URL handling now preserves valid percent-encoded path/query bytes, rejects invalid percent triplets, rejects non-ASCII host and IPv6 zone id, strips fragments, emits origin-form, and allows request-target up to 8000 octets.
- Rebuilt and ran `http_parser_tests.exe` and `khttp_tests.exe`; ran Debug x64 solution build with 0 warning and 0 error.

---

## Chunk 5: WSK, Async, DNS, And Connection Pool

### Task 5.1: Async cancel/release 生命周期

**Files:**
- Modify: `src/KernelHttpLib/engine/Async.cpp`
- Modify: `include/KernelHttp/engine/Async.h`
- Test: `tests/khttp_tests.cpp`
- Test if added: `tests/async_tests.cpp`

- [x] 写测试：cancel 后立即 release，worker 仍能观察到 cancel。
- [x] 写测试：wait 后 release、session close 等待 in-flight、websocket close 等待 receive/send。
- [x] 拆分“用户句柄关闭”和“内部 operation 有效性/引用计数”。
- [x] 保证 callback exactly once、operation free exactly once。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`

### Task 5.2: DNS/ResolveAll 边界

**Files:**
- Modify: `src/KernelHttpLib/net/WskClient.cpp`
- Modify: `include/KernelHttp/net/WskClient.h`
- Modify: `docs/high-level-api.md`
- Test: `tests/khttp_tests.cpp`

- [x] 决定可取消 DNS resolve 是否实现；若仍不可取消，文档和 API 明确 resolve 开始后不承诺取消。
- [x] 写测试：固定 TTL 过期、family 隔离、缓存容量替换、顺序地址失败后下一个地址成功。
- [x] 明确 DNS cache 的全局作用域、任一 `WskClient::Shutdown()` 是否清空全局缓存；若语义不合适，改为 per-client/per-provider cache。
- [x] 决定真实 DNS TTL/negative cache/flush API 是否进入范围。
- [x] 不实现 Happy Eyeballs 时，文档说明 IPv4/IPv6 顺序连接策略。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`

### Task 5.3: 连接池契约

**Files:**
- Modify: `src/KernelHttpLib/engine/ConnectionPool.cpp`
- Modify: `include/KernelHttp/engine/ConnectionPool.h`
- Modify: `docs/high-level-api.md`
- Test: `tests/khttp_tests.cpp`

- [x] 明确 `MaxConnectionsPerHost` 是 per-host 还是 per-full-pool-key；当前完整 key 可能突破用户直觉。
- [x] 写测试：host 相同但 SNI/ALPN/cert policy/store 不同，不跨身份复用。
- [x] 写测试：HTTP/1.0 keep-alive、101 upgrade、close-delimited response 不回池。
- [x] 若实现 pure host quota，要在不破坏 TLS 身份隔离的前提下统计 active + idle。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`

### Task 5.4: WSK fake 和真实内核验证

**Files:**
- Create if needed: `tests/wsk_socket_tests.cpp`
- Modify if needed: `src/KernelHttpLib/net/WskSocket.cpp`
- Modify if needed: `src/KernelHttpLib/net/WskSync.h`
- Modify: `docs/plans/2026-06-09-http-websocket-protocol-recheck-notes.md`

- [x] 建 fake WSK provider，覆盖 connect/send/receive timeout、caller cancel、late completion、close exactly once。
- [x] 写测试：取消后 socket 不回池，late completion cleanup 不泄漏 native socket/IRP/buffer。
- [x] 记录 Driver Verifier + PoolMon + kernel debugger 验证步骤。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`

Status 2026-06-10:
- Async cancel/release now keeps live-operation cancellation observable after user-handle release, with callback/free exactly-once coverage in `khttp_tests.cpp`.
- `WskClient::ResolveAll` has a test resolver hook and shared positive cache coverage for fixed TTL expiry, address-family key isolation, capacity replacement, global clear semantics, and sequential address fallback. DNS cancellation remains a documented synchronous WSK boundary: once provider resolve starts, cancellation is not promised.
- DNS cache semantics are fixed and documented as global 16-slot positive cache, fixed 5-minute TTL, no DNS-record TTL, no negative cache, no public flush API, and cleared by any `WskClient::Shutdown()`.
- Connection pool host quota now counts active + idle by scheme/host/port/address-family while reuse still requires the full TLS identity key. Idle old-identity connections may be detached to satisfy a new TLS identity under the same host quota; active quota exhaustion returns `STATUS_INSUFFICIENT_RESOURCES`.
- User-mode WSK fake provider covers connect timeout with late socket cleanup, send caller cancel, receive timeout, idempotent close, and heap-backed `WskBuffer` send/receive paths under `KERNEL_HTTP_USER_MODE_TEST`.
- `tests/integration/https_smoke.ps1` khttp source list now includes `src\KernelHttpLib\net\WskClient.cpp` and `src\KernelHttpLib\net\WskSocket.cpp` so host regression builds link the new WSK test hooks.
- Rebuilt `tests\out\bin\khttp_tests.exe` manually with the same `/W4 /WX` user-mode test flags and the updated source list; ran `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`: passed.
- Ran Debug x64 kernel library Rebuild with `/Wall /WX`: `msbuild .\KernelHttp.sln /m /nr:false /t:KernelHttpLib:Rebuild /p:Configuration=Debug /p:Platform=x64`; result 0 warnings, 0 errors.

---

## Chunk 6: Kernel Memory And Allocator Cleanup

### Task 6.1: 移除 HTTP/2/HPACK 热路径直接 new/delete

**Files:**
- Modify: `src/KernelHttpLib/http2/Http2Connection.cpp`
- Modify: `src/KernelHttpLib/http2/Hpack.cpp`
- Modify: `include/KernelHttp/core/WorkspaceScratchAllocator.h`
- Test: `tests/http2_client_tests.cpp`
- Test: `tests/hpack_tests.cpp`

- [x] 枚举 HTTP/2/HPACK 直接 `new/delete/new[]/delete[]` 调用点。
- [x] 设计显式 NonPaged pool wrapper 或 workspace 常驻 buffer。
- [x] 替换动态表、frame payload、header decode 临时缓冲。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\hpack_tests.exe'`

### Task 6.2: 移除 TLS/证书/客户端路径直接 new/delete

**Files:**
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `src/KernelHttpLib/tls/CertificateValidator.cpp`
- Modify: `src/KernelHttpLib/client/HttpsClient.cpp`
- Modify: `src/KernelHttpLib/client/Http2Client.cpp`
- Test: `tests/tls_record_tests.cpp`
- Test: `tests/khttp_tests.cpp`

- [x] 枚举 TLS/HttpsClient/CertificateValidator/Http2Client 中直接 `new/delete`。
- [x] 将 transport、certificate chain、handshake scratch 改成显式 allocator 管理。
- [x] 复核固定容量：handshake 8192、HRR 512、证书链 8、authority DER 8192；保持 bounded 但给出错误码和文档。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`

### Task 6.3: WebSocket 热路径缓冲复用

**Files:**
- Modify: `src/KernelHttpLib/engine/WsEngine.cpp`
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Modify: `include/KernelHttp/engine/HandleTypes.h`
- Test: `tests/websocket_client_tests.cpp`
- Test: `tests/high_level_api_tests.cpp`

- [x] 将每次 receive 分配 `frameBuffer` 和 `payloadBuffer(maxMessageBytes)` 改为 workspace 常驻或分级复用。
- [x] 保持 per-session/per-websocket 上限，避免 ping/fragment flood 放大 nonpaged pool。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`

### Task 6.4: Core/net/engine/http allocator cleanup

**Files:**
- Modify: `include/KernelHttp/http/HttpTypes.h`
- Modify: `include/KernelHttp/KernelHttpConfig.h`
- Modify: `include/KernelHttp/engine/HandleAlloc.h`
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`
- Modify: `src/KernelHttpLib/engine/Engine.cpp`
- Modify: `src/KernelHttpLib/engine/Async.cpp`
- Modify: `src/KernelHttpLib/net/WskClient.cpp`
- Modify: `src/KernelHttpLib/net/WskSocket.cpp`
- Modify: `src/KernelHttpLib/net/WskSync.h`
- Modify: `src/KernelHttpLib/client/HttpClient.cpp`
- Modify if touched: `src/KernelHttpLib/khttp/Request.cpp`
- Modify if touched: `src/KernelHttpLib/khttp/Response.cpp`
- Modify if touched: `src/KernelHttpLib/khttp/Session.cpp`
- Modify if touched: `src/KernelHttpLib/khttp/WebSocket.cpp`
- Test: `tests/khttp_tests.cpp`
- Test: adjacent protocol tests touched by conversions

- [x] 枚举 core/net/engine/http/khttp 路径直接或间接 `new/delete`、`HeapArray`、`HeapObject` 调用点。
- [x] 用显式 allocator/pool wrapper 替代通用 heap helper，保留 bounded ownership 和 close exactly once。
- [x] 复核 WSK/Async/HandleAlloc 生命周期，不把 allocator 改造变成隐式兜底重试。
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`

Status 2026-06-10:
- Chunk 6 complete: direct business `new/delete/new[]/delete[]` use in `src/KernelHttpLib` and `include/KernelHttp` is now contained behind explicit NonPaged helpers or global allocator wrappers; remaining search hits are allocator internals, enum names, comments, or test text.
- `AllocateNonPagedObject<T>` now supports constructor arguments, and object/array ownership conversions in HTTP/2/HPACK, TLS/certificate validation, client, engine, async, pool, and WSK paths use explicit NonPaged allocation helpers.
- WebSocket receive now reuses per-websocket workspace scratch for frame and payload buffers. The connect-time `MaxMessageBytes` capacity bounds payload scratch, and per-call receive limits can reduce but not raise that connection limit.
- Added `TestWebSocketReceiveCannotRaiseConnectionLimit` coverage in `tests/khttp_tests.cpp`.
- Rebuilt and ran user-mode tests with `/W4 /WX`: `hpack_tests.exe`, `http2_client_tests.exe`, `tls_record_tests.exe`, `websocket_client_tests.exe`, `high_level_api_tests.exe`, and `khttp_tests.exe`; all passed.
- Ran Debug x64 kernel library Rebuild with `/Wall /WX`: `msbuild .\KernelHttp.sln /m /nr:false /t:KernelHttpLib:Rebuild /p:Configuration=Debug /p:Platform=x64`; result 0 warnings, 0 errors.
- Did not run the prohibited integration smoke command `pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild`.

---

## Chunk 7: Optional Width Decisions

### Task 7.1: 明确延期或非目标能力

**Files:**
- Modify: `docs/plans/2026-06-09-http-websocket-protocol-scope-decisions.md`
- Modify: `README.md`
- Modify: `README_en.md`
- Modify: `docs/api-overview.md`
- Modify: `docs/high-level-api.md`
- Modify: `docs/low-level-api.md`

- [x] HTTP proxy/CONNECT：当前非目标，保持 `STATUS_NOT_SUPPORTED` 或配置拒绝。
- [x] 入站 HTTP request parser/server role：非目标；当前是客户端协议栈。
- [x] WebSocket over HTTP/2 RFC 8441 extended CONNECT：非目标或延期；当前 WebSocket 主路径是 HTTP/1.1 Upgrade。
- [x] WebSocket 自定义 opening handshake headers（Origin/Authorization/Cookie 等）：延期；若要支持，需要单独 header validation、敏感头策略和测试。
- [x] 主动 close handshake：实现发送 close 后有界等待 peer close，或文档化为发送 close 后关闭 transport 的客户端简化语义。
- [x] WebSocket permessage-deflate/extensions：当前非目标，拒绝未请求或任何返回扩展。
- [x] WebSocket frame metadata/partial receive：延期，需单独 ABI 和 bounded buffering。
- [x] TLS client certificate：延期，需 kernel private key handle 与 CertificateVerify 设计。
- [x] OCSP/CRL：非目标，`RequireRevocationCheck` 返回 `STATUS_NOT_SUPPORTED`。
- [x] IDNA：非目标，拒绝非 ASCII host。
- [x] Name Constraints：当前不完整，触发返回 `STATUS_NOT_SUPPORTED`，不得静默放行。
- [x] ChaCha20-Poly1305/X25519/EdDSA：延期，按内核 CNG 可用性和测试向量另行决策；CBC/RSA key exchange：非目标，不协商。
- [x] HTTP/2 full multiplexing/server push/priority：full multiplexing 延期，server push/priority 非目标或受限处理。
- [x] SETTINGS ACK timeout、GOAWAY `last_stream_id`、PUSH_PROMISE ACK 前后边界：先实现决策，不宣传完整多流语义。
- [x] RFC 9111 cache、Range、conditional request：当前为普通 header pass-through 或延期，不能宣传为完整语义实现。
- [x] Accept-Encoding qvalue/content negotiation：当前仅作为默认请求头和响应 decoder 子集，不宣传完整协商语义。

Status 2026-06-10:
- Chunk 7 complete: README, English README, API overview, high-level API, low-level API, and the scope decision table now share the same optional-width boundary language.
- WebSocket over HTTP/2 RFC 8441, custom opening headers, permessage-deflate/extensions, frame metadata/partial receive, HTTP proxy/CONNECT, inbound server role, TLS client certificates, OCSP/CRL, IDNA, Name Constraints, ChaCha20/X25519/EdDSA, CBC/RSA key exchange, HTTP/2 full multiplexing/server push/priority, RFC 9111 cache, Range/conditional semantics, and full `Accept-Encoding` negotiation are documented as deferred, non-target, or pass-through only.
- WebSocket active close is documented as the implemented client-simplified behavior: send close when possible and close the transport; received peer close is echoed before close.

---

## Chunk 8: Verification

### Task 8.1: 全量用户态协议测试

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
- [x] Do not run the forbidden integration smoke command.

### Task 8.2: Debug x64 构建

**Files:**
- No source edits unless failures require fixes.

- [x] Run without artificial timeout: `pwsh -NoLogo -NoProfile -Command '$ErrorActionPreference = "Stop"; $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"; $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath; if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsPath)) { throw "Visual Studio with VC tools was not found." }; $devShell = Join-Path $vsPath.Trim() "Common7\Tools\Launch-VsDevShell.ps1"; & $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; & msbuild.exe .\KernelHttp.sln /p:Configuration=Debug /p:Platform=x64 /m; exit $LASTEXITCODE'`
- [x] Confirm warning-as-error remains enabled.
- [x] Confirm no new direct `new/delete` was introduced.
- [x] Do not commit unless explicitly requested.

Status 2026-06-10:
- Chunk 8 complete: all nine user-mode protocol tests passed: `http_parser_tests.exe`, `websocket_frame_tests.exe`, `websocket_client_tests.exe`, `http2_frame_tests.exe`, `hpack_tests.exe`, `http2_client_tests.exe`, `tls_record_tests.exe`, `high_level_api_tests.exe`, and `khttp_tests.exe`.
- Did not run the forbidden integration smoke command.
- Debug x64 solution build completed successfully with `msbuild.exe .\KernelHttp.sln /p:Configuration=Debug /p:Platform=x64 /m`: 0 warnings, 0 errors.
- Confirmed warning-as-error remains enabled: `WarningLevel=EnableAllWarnings` and `TreatWarningAsError=true` are present for both `KernelHttpLib` and `KernelHttpTest`; the Debug compile command used `/Wall /WX`.
- Confirmed no new direct business `new/delete` use: filtered search across `include/KernelHttp` and `src/KernelHttpLib` found no hits outside allocator wrappers and deleted special-member declarations.
- No commit was made.

## 完成标准

- 第二轮及后续复核未发现新增遗漏。
- 已声明支持子集内的协议错误都有明确 close/RST/GOAWAY/alert/NTSTATUS 语义。
- HTTP/1.1、WebSocket、TLS、证书、HTTP/2、HPACK、WSK/Async/Pool 的高风险缺口均有测试覆盖。
- 未实现能力保持显式拒绝或文档非目标，不静默成功。
- 全量用户态测试和 Debug x64 构建通过，0 warning、0 error。
