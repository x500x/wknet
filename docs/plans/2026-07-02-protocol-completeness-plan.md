# 协议完整性补全 Implementation Plan

> **For agentic workers:** REQUIRED: 按任务复选框逐项执行；实现阶段优先使用 subagent-driven-development（若可用）或 executing-plans；每个任务完成后运行对应测试。计划文档本身不要提交，除非用户明确要求。

**Goal:** 把 KernelHttp 的协议完整性从“能力很多但边界分散”提升为“客户端主路径能力完整、缺口可审计、非目标清晰显示、测试可证明”的状态。

**Architecture:** 以“协议能力账本”为源头，把 RFC/公开行为拆成已实现、待补全、安全拒绝、明确非目标四类；实现上优先补 HTTP/1.1、HTTP/2、TLS/证书、WebSocket 的客户端主路径缺口。所有新增路径复用现有 WSK/CNG/内核自实现路线，使用 `KhWorkspace`、lookaside、`HeapArray`/`HeapObject` 等堆内存模型，不引入 WinHTTP/WinINet/SChannel 主路径。

**Tech Stack:** Windows kernel C++17（`/kernel`、无异常、无 RTTI）、WSK transport、内核态 CNG/BCrypt、现有用户态协议测试、`pwsh`、MSBuild/WDK。

---

## 推荐路线与取舍

推荐方案：先做“账本驱动的客户端主路径完整性”，再按账本补代码与文档。这样能避免把所有 RFC 特性无差别塞进内核库，也不会把“不做”伪装成“以后兜底”。协议完整性在本项目里应定义为：客户端 HTTP/HTTPS/WebSocket/TLS 主路径能力可用，安全边界明确，非目标清晰，所有公开说法都有测试或审计依据。

替代方案一：只改 docsite/能力矩阵，让页面看起来完整。成本低，但代码缺口仍在，后续会继续出现“显示完整但行为不完整”的问题，不推荐。

替代方案二：追求全 RFC 覆盖，包括服务端、HTTP/3/QUIC、在线 OCSP/CRL、WebSocket 扩展等。范围过大且偏离内核客户端定位，不推荐作为当前计划。

## 完整性定义

- 核心补全：HTTP/1.1 `Expect: 100-continue`、流式请求体、明文 HTTP over proxy、HTTP/2 高层语义一致性、HTTP/2 请求 trailers/流式 DATA、WebSocket wire fragment 回调、TLS/证书路径构建审计。
- 安全拒绝：HTTP obs-fold、HTTP/2 server push、非法 CONTINUATION/PING/WINDOW_UPDATE、WebSocket 扩展默认拒绝、TLS 降级哨兵、未知 critical 证书扩展。
- 明确非目标：HTTP/3/QUIC、服务端/入站 request parser、在线 OCSP/CRL 网络抓取、WebSocket permessage-deflate 自动协商、把 WinHTTP/WinINet/SChannel 作为内核主路径；HTTP/1.1 pipeline、TRACE、Expect 与流式上传已后续迁移为显式 opt-in 或已验证能力。
- 显示要求：`docsite/capability-matrix*.md` 不应只写“未支持”；必须写“为何不做、是否安全拒绝、是否可选开启、未来是否计划”。

## 文件结构地图

- 修改：`include/wknet/Wknet.h`、`include/wknet/http/Types.h`
  - 承载新增公开选项、flags、回调签名和兼容默认值。
- 修改：`src/wknetlib/engine/Engine.cpp`、`src/wknetlib/engine/HttpEngine.cpp`
  - 承载高层请求构建、连接池、代理、HTTP/1.1/HTTP/2 分发、回调与重试。
- 修改：`src/wknetlib/http/HttpRequest.cpp`、`include/wknet/http1/HttpRequest.h`
  - 拆出“仅头部构建”和“body 分段写入”能力，服务 `Expect: 100-continue` 与流式上传。
- 修改：`src/wknetlib/http/HttpParser.cpp`、`src/wknetlib/http/HttpTransferCoding.cpp`、`src/wknetlib/http/HttpContentEncoding.cpp`
  - 补强 interim/final response、trailer、增量 body/解码边界测试。
- 修改：`src/wknetlib/http2/Http2Connection.cpp`、`include/wknet/http2/Http2Connection.h`
  - 补 HTTP/2 流式 DATA、请求 trailers、高层复用下的 GOAWAY/RST 重试语义。
- 修改：`src/wknetlib/client/Http2Client.cpp`、`include/wknet/client/Http2Client.h`
  - 保持低层 h2/h2c 行为，同时向高层提供明确可控的 h2c/upgrade 入口。
- 修改：`src/wknetlib/client/WebSocketClient.cpp`、`include/wknet/client/WebSocketClient.h`
  - 让 `OnMessage` 可选择按 wire fragment 交付，并保留默认聚合行为。
- 修改：`src/wknetlib/tls/CertificateValidator.cpp`、`include/wknet/tls/CertificateValidator.h`
  - 补证书路径候选选择、AKI/SKI、交叉签名、name constraints/policy 的账本测试。
- 修改：`tests/http_parser_tests.cpp`、`tests/http2_client_tests.cpp`、`tests/websocket_client_tests.cpp`、`tests/tls_handshake_tests.cpp`、`tests/tls_record_tests.cpp`、`tests/khttp_tests.cpp`、`tests/high_level_api_tests.cpp`
  - 所有协议缺口先写失败测试，再实现。
- 修改：`docsite/capability-matrix.md`、`docsite/capability-matrix.en.md`、`docsite/roadmap.md`、`docsite/roadmap.en.md`、各协议页与 README
  - 文档显示作为单独 docsite 提交处理。

---

## Chunk 1: 能力账本与验收基线

### Task 1: 建立协议能力账本

**Files:**
- Create: `docs/protocol-completeness-ledger.md`
- Modify: `docs/memory/protocol-completeness.md`

- [x] **Step 1: 按协议列出 RFC 条目**

  覆盖 HTTP/1.1、HTTP/2、HPACK、TLS 1.2、TLS 1.3、X.509、WebSocket、代理。每项写清 `MUST/SHOULD/MAY`、当前文件入口、测试入口、状态分类。

- [x] **Step 2: 标记主路径与非目标**

  主路径只包括客户端 HTTP/HTTPS/WebSocket/TLS。服务端、HTTP/3、在线撤销抓取等写入“明确非目标”，并说明理由。

- [x] **Step 3: 运行文档自查**

  Run: `pwsh -NoLogo -NoProfile -Command 'rg -n "未完成|不完整|TODO|planned|incomplete" .\docs .\docsite .\README.md .\README_en.md'`

  Expected: 所有命中都有账本条目或被改成明确边界描述。

### Task 2: 冻结验证命令

**Files:**
- Modify: `docs/protocol-completeness-ledger.md`
- Modify: `docsite/build-and-test.md`

- [x] **Step 1: 写入用户态测试全集**

  至少包括：

  ```powershell
  pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test http_parser_tests -Run
  pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test http2_frame_tests -Run
  pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test http2_client_tests -Run
  pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test websocket_frame_tests -Run
  pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test websocket_client_tests -Run
  pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_crypto_tests -Run
  pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_handshake_tests -Run
  pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_record_tests -Run
  pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_interop_matrix_tests -Run
  pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test khttp_tests -Run
  pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test high_level_api_tests -Run
  ```

- [x] **Step 2: 写入构建验证**

  ```powershell
  pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
  pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64
  ```

  如果本机装有 ARM64 WDK 工具链，再运行 ARM64 Debug/Release。不要运行被禁止的 `tests\integration\https_smoke.ps1` 命令。

---

## Chunk 2: HTTP/1.1 主路径补全

### Task 3: 拆分 HTTP/1.1 header/body 发送模型

**Files:**
- Modify: `include/wknet/http1/HttpRequest.h`
- Modify: `src/wknetlib/http/HttpRequest.cpp`
- Modify: `src/wknetlib/engine/HttpEngine.cpp`
- Test: `tests/http_parser_tests.cpp`
- Test: `tests/khttp_tests.cpp`

- [x] **Step 1: 写失败测试**

  覆盖“只构建 header block”“Content-Length body 后续分段发送”“chunked body 分段发送并在末尾发送 trailer”。

- [x] **Step 2: 新增 header-only 构建入口**

  在 `HttpRequestBuilder` 中增加内部接口，用于生成 request line + headers + 空行，不附加 body。保持现有 `Build` 行为不变。

- [x] **Step 3: 引擎层使用 body producer**

  在 `HttpEngine.cpp` 中把“发送整个 workspace request buffer”改为“发送 header buffer，再按 body source 发送 body”。已有小 body 仍可一次性发送，但接口按分段语义组织。

- [x] **Step 4: 运行测试**

  Run: `pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test http_parser_tests -Run`

  Expected: 新增 header-only/request-body 测试通过，旧 request builder 字节级测试不变。

### Task 4: 实现 `Expect: 100-continue`

**Files:**
- Modify: `include/wknet/Wknet.h`
- Modify: `include/wknet/http/Types.h`
- Modify: `src/wknetlib/engine/Engine.cpp`
- Modify: `src/wknetlib/engine/HttpEngine.cpp`
- Modify: `src/wknetlib/http/HttpParser.cpp`
- Test: `tests/http_parser_tests.cpp`
- Test: `tests/khttp_tests.cpp`

- [x] **Step 1: 增加显式选项**

  增加 opt-in flag，例如 `ExpectContinue` 与 `ExpectContinueTimeoutMs`。默认不改变现有行为；只有调用方显式开启且请求有 body 时才发送 `Expect: 100-continue`。

- [x] **Step 2: 写状态机测试**

  覆盖服务端返回 `100` 后发送 body、直接返回 final response 时不发送 body、`417` 返回给调用方、等待超时后发送 body、取消/断连返回明确错误。

- [x] **Step 3: 实现 header-first 发送**

  发送 header 后读取 interim/final response。读到 `100` 才发送 body；读到 final response 则结束；超时发送 body属于 RFC 时序，不作为“临时兜底”处理。

- [x] **Step 4: 验证**

  Run: `pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test khttp_tests -Run`

  Expected: `Expect: 100-continue` 的每个分支都有断言。

### Task 5: 支持明文 HTTP over proxy

**Files:**
- Modify: `src/wknetlib/engine/HttpEngine.cpp`
- Modify: `src/wknetlib/client/ProxyTunnel.cpp`
- Modify: `include/wknet/engine/ConnectionPool.h`
- Test: `tests/khttp_tests.cpp`
- Test: `tests/high_level_api_tests.cpp`

- [x] **Step 1: 写失败测试**

  覆盖 `http://` + proxy 时发送 absolute-form request target，携带 `Proxy-Authorization`，不建立 CONNECT 隧道。

- [x] **Step 2: 调整 pool key**

  连接池 key 同时包含 proxy endpoint、origin scheme/host/port、ALPN；避免把不同 origin 的明文代理连接错误复用。

- [x] **Step 3: 实现 absolute-form 请求**

  对明文代理请求构建 `GET http://host[:port]/path?query HTTP/1.1`，Host 仍为 origin host。HTTPS 继续走 CONNECT，不改变现有路径。

- [x] **Step 4: 验证**

  Run: `pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test khttp_tests -Run`

  Expected: 代理明文请求通过；HTTPS CONNECT 既有测试不回归。

### Task 6: 真流式请求体与响应回调边界

**Files:**
- Modify: `include/wknet/Wknet.h`
- Modify: `include/wknet/http/Types.h`
- Modify: `src/wknetlib/khttp/Body.cpp`
- Modify: `src/wknetlib/khttp/Http.cpp`
- Modify: `src/wknetlib/engine/HttpEngine.cpp`
- Test: `tests/khttp_tests.cpp`
- Test: `tests/high_level_api_tests.cpp`

- [x] **Step 1: 设计 body source ABI**

  新增读取回调或复用文件 body，使请求体按块读取。所有状态对象放堆或 workspace，不在 lib 热路径放大栈对象。

- [x] **Step 2: 实现 Content-Length 与 chunked 两种流式上传**

  已知长度走 `Content-Length`；未知长度走 chunked。禁止调用方手写 `Transfer-Encoding` 的安全边界保持不变。

- [x] **Step 3: 复核响应回调模式**

  `OnBody` 且未设置 `AggregateWithCallbacks` 时，不应因普通大响应触发低位聚合硬上限；只保留 header section、单帧、解压膨胀比等协议安全上限。

- [x] **Step 4: 验证**

  Run: `pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test high_level_api_tests -Run`

  Expected: 大请求体、大响应回调、chunked trailer 均通过。

---

## Chunk 3: HTTP/2 高层完整性

### Task 7: HTTP/2 请求 body source 与 trailers

**Files:**
- Modify: `include/wknet/http2/Http2Connection.h`
- Modify: `src/wknetlib/http2/Http2Connection.cpp`
- Modify: `src/wknetlib/client/Http2Client.cpp`
- Modify: `src/wknetlib/engine/HttpEngine.cpp`
- Test: `tests/http2_client_tests.cpp`
- Test: `tests/khttp_tests.cpp`

- [x] **Step 1: 写失败测试**

  覆盖流控窗口耗尽、连接级/stream 级 WINDOW_UPDATE 任意顺序、请求 trailers 以 final HEADERS 发送、trailer 伪头被拒。

- [x] **Step 2: 将 DATA 发送改为 body source 驱动**

  `Http2Connection` 按 `min(connectionSendWindow, stream.RemoteWindow, peer.MaxFrameSize)` 切块发送，不一次性要求完整 body 在内存中。

- [x] **Step 3: 实现请求 trailers**

  HTTP/2 不使用 chunked；当 request trailer 存在时，body 结束后发送 trailing HEADERS + END_STREAM。禁止字段规则沿用 HTTP/1.1 trailer 安全边界。

- [x] **Step 4: 验证**

  Run: `pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test http2_client_tests -Run`

  Expected: HTTP/2 大 body、trailers、流控测试全部通过。

### Task 8: 高层 h2c 显式入口

**Files:**
- Modify: `include/wknet/Wknet.h`
- Modify: `include/wknet/http/Types.h`
- Modify: `src/wknetlib/engine/HttpEngine.cpp`
- Modify: `src/wknetlib/client/Http2Client.cpp`
- Test: `tests/http2_client_tests.cpp`
- Test: `tests/khttp_tests.cpp`

- [x] **Step 1: 增加显式配置**

  增加类似 `AllowHttp2Cleartext` / `Http2CleartextMode` 的配置，默认关闭。支持 prior knowledge 与 Upgrade，且 `ws://` 不因该选项隐式走 RFC 8441。

- [x] **Step 2: 写失败测试**

  覆盖默认 http:// 不走 h2c、显式 prior knowledge、显式 Upgrade 禁请求体、101 后残留字节重放。

- [x] **Step 3: 接入连接池**

  pool key 区分 HTTP/1.1、h2c prior knowledge、h2c Upgrade，避免协议层复用混淆。

- [x] **Step 4: 验证**

  Run: `pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test http2_client_tests -Run`

  Expected: 低层 h2c 行为与高层显式入口一致。

### Task 9: GOAWAY/RST_STREAM 重试语义

**Files:**
- Modify: `src/wknetlib/http2/Http2Connection.cpp`
- Modify: `src/wknetlib/engine/HttpEngine.cpp`
- Modify: `src/wknetlib/engine/ConnectionPool.cpp`
- Test: `tests/http2_client_tests.cpp`
- Test: `tests/khttp_tests.cpp`

- [x] **Step 1: 写失败测试**

  覆盖 GOAWAY `NO_ERROR` 且 stream id 大于 `lastStreamId` 时，安全方法可新连接重试一次；非幂等方法不自动重试。

- [x] **Step 2: 区分可重试与连接失败**

  保留当前 `STATUS_RETRY`，但让高层知道是“stream 未处理”而不是普通断连。

- [x] **Step 3: 释放 stream lease**

  任何失败路径都必须释放 H2 stream lease，避免连接池并发槽泄漏。

- [x] **Step 4: 验证**

  Run: `pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test khttp_tests -Run`

  Expected: H2 retry 行为与 HTTP/1.1 stale retry 规则一致但不误重试非安全方法。

---

## Chunk 4: WebSocket 完整性

### Task 10: wire fragment 回调与文档口径一致

**Files:**
- Modify: `include/wknet/Wknet.h`
- Modify: `include/wknet/http/Types.h`
- Modify: `src/wknetlib/client/WebSocketClient.cpp`
- Modify: `src/wknetlib/khttp/WebSocket.cpp`
- Test: `tests/websocket_frame_tests.cpp`
- Test: `tests/websocket_client_tests.cpp`

- [x] **Step 1: 写失败测试**

  覆盖文本消息分为多个 wire fragment 时，开启 fragment 回调能收到首帧、续帧、final 标志；默认行为仍返回聚合消息。

- [x] **Step 2: 增加显式选项**

  在 `ReceiveOptions` 中增加类似 `DeliverFragments` 的布尔项，默认 `false`。已有 `finalFragment` 回调参数开始承载真实 wire fragment 语义。

- [x] **Step 3: 保持 UTF-8 增量校验**

  文本 fragment 跨片状态仍使用现有增量 UTF-8 校验；最终片不完整码点返回 1007/协议错误。

- [x] **Step 4: 验证**

  Run: `pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test websocket_client_tests -Run`

  Expected: 默认聚合与 fragment 回调两套行为都稳定。

### Task 11: WebSocket opening-handshake 完整性审计

**Files:**
- Modify: `src/wknetlib/client/WebSocketClient.cpp`
- Modify: `tests/websocket_client_tests.cpp`
- Modify: `docsite/websocket.md`
- Modify: `docsite/websocket.en.md`

- [x] **Step 1: 审计 101/401/3xx 行为**

  默认仍不跟随 redirect/401；若决定补，必须新增显式 opt-in，并沿用 HTTP redirect 安全规则：跨源清理敏感头，拒绝 HTTPS 降级。

- [x] **Step 2: 强化失败可见性**

  失败时区分 `STATUS_NOT_SUPPORTED`、`STATUS_INVALID_NETWORK_RESPONSE`、握手状态码不接受等场景，让调用方能判断是协议错误还是策略拒绝。

- [x] **Step 3: 验证**

  Run: `pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test websocket_client_tests -Run`

  Expected: opening-handshake 的所有边界都有明确断言。

---

## Chunk 5: TLS 与证书完整性

### Task 12: 证书路径构建补全

**Files:**
- Modify: `include/wknet/tls/CertificateValidator.h`
- Modify: `src/wknetlib/tls/CertificateValidator.cpp`
- Modify: `src/wknetlib/tls/CertificateStore.cpp`
- Test: `tests/tls_handshake_tests.cpp`
- Test: `tests/tls_record_tests.cpp`
- Add test data under: `tests/testdata/pki/`

- [ ] **Step 1: 写失败测试**

  覆盖多中间证书、交叉签名、AKI/SKI 匹配、pathLen、Name Constraints、certificatePolicies、缺信任锚失败、未知 critical 扩展失败。

- [ ] **Step 2: 实现有界候选路径搜索**

  链深仍 ≤8，CA 包仍有上限；候选对象使用堆内存或 certificate scratch，不使用大栈数组。按 AKI/SKI、issuer/subject、签名可验证性选择路径。

- [ ] **Step 3: 保持离线撤销模型**

  不在线抓 OCSP/CRL。`OnlineRequired` 继续 fail-closed；OCSP stapling/CRL 只走调用方提供的表驱动输入。

- [ ] **Step 4: 验证**

  Run: `pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_handshake_tests -Run`

  Expected: 新 PKI 场景全部有确定结果。

### Task 13: TLS post-handshake 与 KeyUpdate 审计

**Files:**
- Modify: `include/wknet/tls/TlsConnection.h`
- Modify: `src/wknetlib/tls/TlsConnection.cpp`
- Modify: `src/wknetlib/tls/TlsRecord.cpp`
- Test: `tests/tls_record_tests.cpp`
- Test: `tests/tls_interop_matrix_tests.cpp`

- [ ] **Step 1: 写失败测试**

  覆盖 TLS 1.3 KeyUpdate、post-handshake CertificateRequest 策略关闭时拒绝、策略开启时按 mTLS 回调签名、post-handshake 消息洪泛上限。

- [ ] **Step 2: 补齐状态机**

  保留“默认不主动 rekey”的公开行为；若实现主动 KeyUpdate，必须是明确 API 或序列号安全边界触发，不作为临时兜底。

- [ ] **Step 3: 验证**

  Run: `pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_record_tests -Run`

  Expected: post-handshake 消息处理、拒绝和上限都可重复验证。

### Task 14: TLS 互通矩阵扩展

**Files:**
- Modify: `tests/tls_interop_matrix_tests.cpp`
- Modify: `tests/integration/tls_matrix.ps1`
- Modify: `docsite/tls-and-certificates.md`
- Modify: `docsite/tls-and-certificates.en.md`

- [ ] **Step 1: 扩展矩阵声明**

  覆盖 TLS1.2/1.3、ALPN h2/http1、RSA-PSS/ECDSA/Ed25519/Ed448、X25519/P-256/P-384、可选 FFDHE、legacy policy。

- [ ] **Step 2: 运行本地 TLS 矩阵**

  Run: `pwsh -NoLogo -NoProfile -File .\tests\integration\tls_matrix.ps1 -Configuration Debug -Platform x64`

  Expected: OpenSSL/BoringSSL 缺失时明确 SKIP；存在时核心矩阵通过。

---

## Chunk 6: 文档显示与发布边界

### Task 15: 更新能力矩阵

**Files:**
- Modify: `docsite/capability-matrix.md`
- Modify: `docsite/capability-matrix.en.md`
- Modify: `docsite/roadmap.md`
- Modify: `docsite/roadmap.en.md`

- [x] **Step 1: 按账本重写“当前边界”**

  每项能力只允许四类表述：已实现/已验证、默认关闭需开启、安全拒绝、明确非目标。

- [x] **Step 2: 删除模糊未完成表述**

  不写“后续补”“暂时不支持”这种不带原因的描述。确实延期的能力要写触发条件、风险和是否计划。

- [x] **Step 3: 中英文同步**

  中英文页面的能力分类、默认行为和非目标必须一致。

### Task 16: 更新协议页与 README

**Files:**
- Modify: `docsite/http1.md`
- Modify: `docsite/http1.en.md`
- Modify: `docsite/http2.md`
- Modify: `docsite/http2.en.md`
- Modify: `docsite/websocket.md`
- Modify: `docsite/websocket.en.md`
- Modify: `docsite/tls-and-certificates.md`
- Modify: `docsite/tls-and-certificates.en.md`
- Modify: `README.md`
- Modify: `README_en.md`

- [x] **Step 1: 同步新增能力**

  写清 `Expect: 100-continue`、流式上传、HTTP proxy、h2c、H2 trailers、WebSocket fragment callback、证书路径构建。

- [x] **Step 2: 写清仍不做的能力**

  HTTP/3、服务端、在线撤销等保持非目标，不和“未完成”混写；WebSocket permessage-deflate 已后续迁移为显式 opt-in 能力。

- [x] **Step 3: docsite 提交边界**

  实现提交和 docsite 提交必须分开；docsite 提交信息必须以 `docsite:` 开头。计划文档本身不自动提交。

---

## Chunk 7: 总体验证

### Task 17: 用户态协议测试全集

**Files:**
- Test-only

- [x] **Step 1: 构建并运行协议测试**

  Run the commands listed in Task 2. Expected: 全部 PASS；任何 SKIP 必须有明确环境原因。

- [x] **Step 2: 复查禁止项**

  Run: `pwsh -NoLogo -NoProfile -Command 'rg -n "new |delete |WinHTTP|WinINet|SChannel|兜底|临时|先这样" .\include .\src .\tests .\docsite .\docs'`

  Expected: 不出现新增违规用法；若命中历史文档，必须确认不是新增架构手段。

### Task 18: Debug/Release 构建

**Files:**
- Build-only

- [x] **Step 1: Debug x64**

  Run: `pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64`

  Expected: `/WX` 下 0 warning。

- [x] **Step 2: Release x64**

  Run: `pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64`

  Expected: `/WX` 下 0 warning。

- [x] **Step 3: ARM64（环境具备时）**

  Run Debug/Release ARM64。若缺 WDK ARM64 工具链，记录为环境限制，不改代码降级。

  Result: 本机 MSVC 14.44.35207 未检测到 HostX64\arm64\cl.exe 或 HostX86\arm64\cl.exe，ARM64 构建记录为环境限制。

### Task 19: 最终审计

**Files:**
- Modify as needed only if audit finds mismatch.

- [x] **Step 1: 对照账本逐项勾选**

  每个“待补全”必须变成“已实现/已验证”“安全拒绝”或“明确非目标”之一。

- [x] **Step 2: 对照 docsite 逐项检查**

  页面显示不能再让协议能力呈现为不完整的模糊状态。

- [x] **Step 3: 准备提交说明**

  如果用户要求提交，按 Conventional Commits。实现提交示例：

  ```text
  feat: 补全客户端协议主路径完整性
  - 支持 HTTP/1.1 expect-continue、流式上传与明文代理
  - 补齐 HTTP/2 高层 body/trailer/h2c 与重试语义
  - 完善 WebSocket 分片回调和 TLS/证书路径校验
  ```

  docsite 提交单独示例：

  ```text
  docsite: 更新协议完整性能力矩阵
  - 按账本同步中英文协议能力与非目标
  - 明确安全拒绝和默认关闭能力
  ```

## 风险控制

- 不引入“临时兜底”：超时、容量、重试都必须来自协议语义或安全边界。
- 不扩大普通 buffered response 的默认总量硬上限；大响应应走回调/流式路径。
- 不实现 JSON 解析/构造。
- 不用 `new/delete`；新增对象走现有分配器、lookaside、workspace 或 `HeapObject`/`HeapArray`。
- 新 API 默认保持兼容；改变默认行为前必须有用户明确确认。
- 所有协议行为必须在用户态测试中可重放，不能只靠人工连一次服务端。


