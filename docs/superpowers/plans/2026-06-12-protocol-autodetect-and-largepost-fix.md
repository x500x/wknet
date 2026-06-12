# 协议自动识别、LargePost 修复与 TLS 版本策略 实施计划

> **For agentic workers:** 用 superpowers:executing-plans 执行本计划。步骤用 `- [ ]` 跟踪。

**Goal:** 修复用户提出的三点诉求：
1. 修复 `HTTP LargePost` 返回 `STATUS_BUFFER_TOO_SMALL (0xC0000023)` 的真实根因。
2. 高层 khttp API 自动识别并使用协议（HTTPS 下 h2/http1.1 按 ALPN 协商自动落地），调用方无需手动指定 ALPN。
3. TLS 版本默认优先 1.3，支持按 min/max 设置降级：min=max=1.3 只用 1.3；min=1.2/max=1.3 在对端不支持 1.3 时降级到 1.2。

**关键现状结论（已通过代码核实，非推测）:**

- **需求1 根因**：`khttp::Post` 全链路从不设置 `request.Tls.Alpn`，所以 `HttpEngine.cpp:1887` 的 h2 分支不进，LargePost 实际走 **HTTP/1.1**（这解释了日志中没有任何 `Http2Connection ... flow-control failed` 诊断行）。HTTP/1.1 响应解码路径 `ReadHttpResponseFromSocket → HttpParser::ParseResponse → ApplyContentEncoding` 使用固定 16 KiB 的 `workspace.DecodedBody`（`KhWorkspaceDecodedBodyBytes = 16*1024`），且**没有按需扩容重试**。httpbin 把 64 KiB body 以 base64 回显并压缩（gzip/deflate/br），解压后约 90 KiB > 16 KiB，`HttpContentEncoding::Decode` 返回 `STATUS_BUFFER_TOO_SMALL`，`ReadHttpResponseFromSocket` 第 1237-1238 行原样上抛。
  - 对照：HTTP/2 路径 `SendHttp2ViaTransport` 用 `DecodeContentWithWorkspace`（`HttpEngine.cpp:910-955`）带 `GrowDecodedBodyAfterBufferTooSmall` 扩容循环（可长到 `MaxResponseBytes`），所以 h2 不会出这个问题。
  - **前一版计划把 `MaxResponseBytes` 从 128KiB 提到 256KiB 改错了地方**：`MaxResponseBytes` 限制的是 raw 响应缓冲与解码上限，不是 `DecodedBody` 的初始/扩容容量。提高它不会让 16KiB 的 `DecodedBody` 自动变大。

- **需求2 现状**：高层 khttp 引擎要走 h2 必须调用方手动设 `request.Tls.Alpn = "h2"`（`HttpEngine.cpp:1590-1594` 仅在 Alpn 非空时 offer；`:1887` 仅当 Alpn 字面量为 "h2" 才走 h2 分支）。默认 `TlsConfig.Alpn=nullptr`，等于纯 HTTP/1.1。对照低层 `HttpsClient` 默认 offer `{h2, http/1.1}` 且按协商结果分发（半自动）。

- **需求3 现状**：已基本实现。默认 Min=1.2/Max=1.3；TLS1.3 ClientHello 的 supported_versions 只写 0x0304；对端回 1.2 形态时记为 `VersionNegotiation` 失败，`IsHttpTls12ConfirmationCandidate`（`HttpEngine.cpp:295-301`）判定后在 `EnsureTlsConnected`（`:1664`）重连降级到 1.2。min=max=1.3 时该判定不成立、不降级且只发 1.3。**用户已确认保持默认 Min=1.2/Max=1.3。** 此需求主要补测试与文档，代码改动很小。

**Tech Stack:** Windows kernel C++ under `/kernel`, WSK, kernel CNG/BCrypt, 自实现 TLS 1.2/1.3、HTTP/2/HPACK、WebSocket，khttp engine，user-mode protocol tests，KernelHttpTest 驱动，MSBuild via `pwsh`。

---

## Ground Rules

- 回复、计划维护、最终记录用简体中文。
- 只生成和执行计划，不自动 git commit；仅用户明确要求才提交。
- 禁止把“兜底设计”当正式架构；禁止“临时兜底后面再删”“先跑起来”作为引入回退方案的理由。
- 不通过跳过公网样例、吞 `STATUS_NOT_SUPPORTED`、禁用证书校验、强切端点、禁用 HTTP/2、默认降级 TLS 策略来掩盖问题。
- `lib` 禁止新增大栈对象；新增缓冲必须 nonpaged heap / workspace / 连接常驻成员 / 既有 `HeapArray`/`HeapObject`。
- `lib` 禁止直接 `new/delete`；沿用 `AllocateNonPagedObject`/`AllocateNonPagedArray`/`FreeNonPaged*`/`HeapArray`/`HeapObject`/workspace helper。
- 高频堆缓冲优先常驻（`KhWorkspace`、`Http2Connection`、连接对象成员）。
- Debug/Release 必须最高警告等级且视警告为错误；新增代码清零所有 warning。
- 写完代码必须进入 user-mode protocol tests 和 Debug 构建验证；禁止 test 烟测，尤其禁止运行：
  `pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild`
- 使用 `pwsh`，不用 `powershell`。

---

## Chunk 1: 修复 HTTP/1.1 响应解码缺少扩容重试（需求1 真实根因）

**核心思路**：让 HTTP/1.1 解码路径与 HTTP/2 路径用同一套“`STATUS_BUFFER_TOO_SMALL` → 扩容 `DecodedBody` → 重解析”循环。`ParseResponse` 每次都从原始字节全量重解析（无指针别名问题），扩容后重试安全。

### Task 1: 写失败测试：HTTP/1.1 压缩大响应解码成功

**Files:**
- Modify: `tests/high_level_api_tests.cpp`（或 `tests/khttp_tests.cpp` 中已有的 content-encoding 路径测试）

- [ ] **Step 1: 构造 fake transport 响应**：返回 `Content-Encoding: gzip`（或 deflate）、解压后 ≈ 90 KiB 的 HTTP/1.1 响应（content-length 为压缩体长度）。原始压缩体远小于 `MaxResponseBytes`，但解压后远超 16 KiB 初始 `DecodedBody`。
  - fixture 用文件级 `static const` 常量或测试数据文件，不在 lib 新增栈缓冲。
  - 若现有测试基建难以构造真实压缩流，使用 `identity` + 单响应体 ≈ 90 KiB 也能复现（因为 `ApplyContentEncoding` 对 identity 也走 `Decode` 拷贝到 `DecodedBody`）。优先用 identity 90 KiB 以避免引入压缩 fixture。
- [ ] **Step 2: 断言**：`Expect(NT_SUCCESS(status), ...)` 且 `response.BodyLength ≈ 90 KiB`。
- [ ] **Step 3: 运行失败测试**
  `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe; exit $LASTEXITCODE'`
  Expected: FAIL，返回 `0xC0000023`。

### Task 2: 在 ReadHttpResponseFromSocket 增加扩容重试

**Files:**
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`

- [ ] **Step 1**：把 `GrowDecodedBodyAfterBufferTooSmall`（当前在 h2 区域匿名命名空间，`HttpEngine.cpp:882-908`）确保对 `ReadHttpResponseFromSocket`（`:1178`）可见（同一匿名命名空间内即可，必要时上移定义位置）。
- [ ] **Step 2**：在 `ReadHttpResponseFromSocket` 解析循环里，`ParseResponse` 返回 `STATUS_BUFFER_TOO_SMALL` 时（区别于 `STATUS_MORE_PROCESSING_REQUIRED`），调用 `GrowDecodedBodyAfterBufferTooSmall(workspace)`：
  - 成功扩容则 `continue` 重新用更大的 `DecodedBody` 解析当前已收字节（不再 `ReceiveWithTimeout`）。
  - `GrowDecodedBodyAfterBufferTooSmall` 返回 `STATUS_BUFFER_TOO_SMALL`（已达 `MaxResponseBytes`）则原样返回，保持“响应确实超限时仍报 `0xC0000023`”的语义。
  - 注意：扩容仅针对 DecodedBody，不动 `workspace.Response`（raw 接收缓冲）的现有扩容逻辑。
- [ ] **Step 3: 运行测试确认通过**
  Expected: PASS。

### Task 3: 复核连接关闭分支（CloseDelimited）也有扩容重试

**Files:**
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`

- [ ] **Step 1**：`ReadHttpResponseFromSocket` 在连接 orderly close 后的内层 `for(;;)` 重解析循环（`:1271` 起，`MessageCompleteOnConnectionClose=true`）同样可能因 `DecodedBody` 太小返回 `STATUS_BUFFER_TOO_SMALL`。为该分支补同样的扩容重试（命中 `0xC0000023` 时 grow 后 retry，达 `MaxResponseBytes` 才真失败）。
- [ ] **Step 2**：补一个 close-delimited（无 content-length、connection: close）大响应测试，断言成功。
- [ ] **Step 3: 运行测试确认通过**

---

## Chunk 2: HTTPS 协议自动识别（需求2）

**核心思路**：高层引擎在 HTTPS 且调用方未显式指定 ALPN 时，默认 offer `{h2, http/1.1}`，并按 TLS 实际协商结果 `NegotiatedAlpn()` 分发到 h2 或 HTTP/1.1。调用方仍可手动指定 ALPN 覆盖（例如强制 http/1.1 或非法 ALPN 测失败）。明文 HTTP 不自动 h2c（用户已确认）。

### Task 4: 在 TlsConfig 增加协议偏好开关

**Files:**
- Modify: `include/KernelHttp/khttp/Types.h`
- Modify: `include/KernelHttp/khttp/Detail.h`
- Modify: `include/KernelHttp/engine/Engine.h`（`KhTlsOptions` / 请求侧）

- [ ] **Step 1**：在 `khttp::TlsConfig` 增加 `bool PreferHttp2 = true;`（语义：HTTPS 下未显式指定 ALPN 时是否自动 offer h2）。
- [ ] **Step 2**：在 `engine::KhTlsOptions` 增加对应字段，并在 `Detail.h` 的 `FillApiTlsOptions` 透传。
- [ ] **Step 3**：保证 ABI/默认值：未设置时默认 `true`，与低层 `HttpsClient` 行为一致。

### Task 5: 引擎默认 offer ALPN 并按协商结果分发

**Files:**
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`
- Test: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: 写失败测试**：HTTPS 请求，调用方不设 ALPN，fake TLS 协商出 `h2` → 断言走 h2 路径（响应 `MajorVersion==2`）；协商出 `http/1.1` → 走 HTTP/1.1 路径。再补“调用方显式设 `http/1.1`”仍走 HTTP/1.1 的测试。
- [ ] **Step 2: 运行失败测试** Expected: FAIL（当前不设 ALPN 不 offer，永远 HTTP/1.1）。
- [ ] **Step 3: 改 `ConnectTlsOnExistingSocket`（`HttpEngine.cpp:1590`）**：HTTPS 且 `request.Tls.Alpn` 为空且 `PreferHttp2` 为真时，offer 常驻的 `{h2, http/1.1}` 列表（参考 `HttpsClient.cpp:284`）；调用方显式给了 ALPN 则只 offer 调用方那一个（保持现有覆盖能力）。
  - offer 列表用文件级 `static const` 或常驻结构，不新增栈大数组。
- [ ] **Step 4: 改分发判据（`HttpEngine.cpp:1886-1899`）**：把“`request.Tls.Alpn == "h2"` 才走 h2”改为“`tlsConnection->NegotiatedAlpn()` 实际为 `h2` 才走 h2，否则 HTTP/1.1”。
  - 调用方显式指定 `h2` 但协商失败时：保持现有 `STATUS_NOT_SUPPORTED` 语义（显式要求 h2 却拿不到属于错误）。
  - 自动模式（未显式指定）协商出非 h2：正常走 HTTP/1.1，不报错。
- [ ] **Step 5: 连接池键**：确认 `ConnectionKey`（含 ALPN，`HttpEngine.cpp:467`）在自动协商下按实际协议正确区分，避免 h2 与 http/1.1 连接混用复用。必要时补测试。
- [ ] **Step 6: 运行测试确认通过**

### Task 6: 样例改为依赖自动识别

**Files:**
- Modify: `src/KernelHttpTest/samples/HighLevelApiSamples.cpp`
- Modify: `src/KernelHttpTest/samples/HttpVerbSamples.cpp`

- [ ] **Step 1**：保留少量显式 ALPN 样例（http/1.1、非法 ALPN 失败、h2 强制）作为回归覆盖；新增/调整若干样例**不设 ALPN** 走自动协商，日志注明协商出的协议。
- [ ] **Step 2**：不要把所有样例无差别改成自动；保留显式路径以覆盖手动指定能力。

---

## Chunk 3: TLS 版本默认与降级 测试 + 文档（需求3）

**核心思路**：行为已满足，重点是补测试锁定语义、补注释/文档说明默认 Min=1.2/Max=1.3 与降级规则。保持现有默认值。

### Task 7: 补 TLS 版本协商/降级回归测试

**Files:**
- Modify: `tests/tls_handshake_tests.cpp` 或 `tests/high_level_api_tests.cpp`

- [ ] **Step 1**：测试 min=max=Tls13 时不触发降级（`IsHttpTls12ConfirmationCandidate` 返回 false），且 ClientHello supported_versions 只含 0x0304。
- [ ] **Step 2**：测试 min=Tls12/max=Tls13 且对端模拟 `VersionNegotiation` 失败时，触发一次重连并以 1.2 成功（fake transport 模拟）。
- [ ] **Step 3: 运行测试确认通过**

### Task 8: 文档/注释澄清

**Files:**
- Modify: 相关 header 注释（`include/KernelHttp/khttp/Types.h` 的 `TlsConfig.MinVersion/MaxVersion` 附近）

- [ ] **Step 1**：用注释说明默认 Min=1.2/Max=1.3，含义为“优先 1.3，对端不支持时降级 1.2”；min=max=1.3 表示仅 1.3。不改默认值。

---

## Chunk 4: End-To-End 验证

### Task 9: 运行相关 user-mode tests

- [ ] `high_level_api_tests.exe`、`http2_client_tests.exe`、`khttp_tests.exe`、`tls_handshake_tests.exe`、`tls_record_tests.exe`、`websocket_client_tests.exe` 全部 PASS。

### Task 10: Debug/Release 构建

- [ ] `pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64` → 0 warning 0 error。
- [ ] `pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64` → 0 warning 0 error。
- [ ] Debug driver solution build（VsDevShell + msbuild `KernelHttp.sln`）→ 0 warning 0 error。

### Task 11: Live KernelHttpTest 验收

- [ ] 运行现有驱动加载流程的 KernelHttpTest 全量场景（不跑被禁的 smoke 脚本）。
- [ ] 验收：
  - `HTTP LargePost` 不再返回 `0xC0000023`（除非响应真实超过 `MaxResponseBytes`）。
  - HTTPS 请求未显式设 ALPN 时能自动用 h2 或 http/1.1，日志显示协商结果。
  - TLS 版本默认 1.3 优先、可降级语义不回归。
  - 既有负面样本（TrustFailure、ALPN mismatch）、IPv6 环境失败诊断保持原行为。

---

## Acceptance Criteria

- `HTTP LargePost` 在 HTTP/1.1 压缩/大响应下成功；响应真实超过 `MaxResponseBytes` 时仍明确返回 `STATUS_BUFFER_TOO_SMALL`。
- HTTP/1.1 与 HTTP/2 解码路径都有 `STATUS_BUFFER_TOO_SMALL → 扩容 → 重解析` 循环，语义一致。
- HTTPS 下未显式指定 ALPN 时自动协商 h2/http1.1 并按实际结果落地；调用方显式指定 ALPN 仍可覆盖。
- 明文 HTTP 保持仅 HTTP/1.1（不自动 h2c）。
- TLS 默认 Min=1.2/Max=1.3：优先 1.3，对端不支持时降级 1.2；min=max=1.3 仅 1.3。语义有测试锁定。
- 不新增 lib 栈大对象、不直接 `new/delete`、高频缓冲常驻或复用 workspace。
- 相关 user-mode tests、Debug/Release x64 lib build、Debug x64 solution build 通过且 0 warning。
