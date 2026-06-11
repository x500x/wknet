# HTTP/2 TLS WebSocket Failure Fixes Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复 2026-06-11 公网全量示例中暴露的 HTTP/2 响应头兼容性、HTTP/2 高层大响应聚合、TLS 1.2 WebSocket 握手解析失败问题，让失败项回到真实协议错误才失败。

**Architecture:** 以协议正确性为主线修复，不通过跳过公网样例、禁用 HTTP/2、强制 HTTP/1.1、重试降级或“临时兜底”隐藏问题。HTTP/2 响应头校验按 RFC 9113/9110 允许字段值 OWS，HTTP/2 高层响应接收改为显式 bounded heap/workspace 增长，TLS 1.2 ServerKeyExchange 增加字段级诊断并修复实际解析偏差。所有 lib 侧新增缓冲必须使用堆内存；频繁使用的堆缓冲优先放入 workspace 或连接常驻对象，禁止新增大栈对象。

**Tech Stack:** Windows kernel C++ under `/kernel`, WSK, kernel CNG/BCrypt, custom TLS 1.2/1.3, custom HTTP/2/HPACK, high-level khttp engine, user-mode protocol tests, KernelHttpTest driver, MSBuild via `pwsh`.

---

## Ground Rules

- 回复、注释和计划维护使用简体中文。
- 不把“兜底设计”当作正式架构手段；禁止用“临时兜底后面再删”“先这样跑起来”作为理由。
- 不通过禁用 HTTP/2、切换公网端点、跳过样例、吞掉错误、自动降级 TLS/ALPN 来掩盖本计划中的协议缺陷。
- lib 禁止新增大栈对象；协议缓冲、响应聚合缓冲、诊断捕获缓冲都必须走 nonpaged heap/workspace/常驻连接成员。
- lib 禁止直接 `new/delete`；沿用 `AllocateNonPagedObject`、`AllocateNonPagedArray`、`HeapObject`、`HeapArray` 或 workspace helper。
- 频繁使用的堆缓冲必须考虑常驻：优先复用 `KhWorkspace`、`Http2Connection` 成员缓冲或 session/request workspace，不在热路径反复分配释放。
- Debug/Release 构建必须保持最高警告等级并视警告为错误；新增代码清零所有 warning。
- 计划文档写入后不执行 git commit；只有用户明确要求提交时才提交。
- 禁止运行会卡住的命令：

```powershell
pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild
```

## Failure Evidence

2026-06-11 live kernel log 中的关键失败：

- `HTTPS GET HTTP/2 ALPN`、`HTTPS REMOTE IPv4`、HTTPS encoding matrix 等对 `httpbin.dev` 的 HTTP/2 路径返回 `STATUS_INVALID_NETWORK_RESPONSE (0xC00000C3)`。
- `HTTP LargePost` 返回 `STATUS_BUFFER_TOO_SMALL (0xC0000023)`。
- `ws.postman-echo.com` WebSocket TLS 1.2 路径在 `TlsConnection parse ServerKeyExchange failed: 0xC00000BB type=12 body=329` 处失败。
- IPv6 `STATUS_NO_MATCH (0xC0000272)`、TrustFailure、ALPN mismatch 已由样例标注为环境或预期负样本，不属于本计划修复目标。

已确认的外部抓取证据：

- `httpbin.dev` HTTP/2 响应 HEADERS 可以成功 HPACK 解码；`content-security-policy` 字段值以 SP 开头，例如 `b" frame-ancestors 'self' ..."`。
- 当前 `Http2Connection::IsValidHttp2FieldValue` 拒绝首尾 SP/HTAB，导致 `ValidateResponseHeaderBlock` 返回 `STATUS_INVALID_NETWORK_RESPONSE`。
- `httpbin.dev/post` 对 64 KiB body 的 HTTP/2 响应 DATA 约 88 KiB；当前高层 H2 路径把响应写入固定初始 `workspace.Response.Data`，在容量不足时直接返回 `STATUS_BUFFER_TOO_SMALL`。
- OpenSSL 抓到 `ws.postman-echo.com` TLS 1.2 `ServerKeyExchange` 为标准 ECDHE_RSA/P-256/rsa_pkcs1_sha256/256-byte signature，总长度 329，静态看应被当前解析器支持，需字段级断点或日志确认运行时偏差。

## File Structure

### Modify

- `src/KernelHttpLib/http2/Http2Connection.cpp`
  - 调整 HTTP/2 响应字段值校验，允许字段值首尾 SP/HTAB，但继续拒绝 NUL/CR/LF。
  - 将 HTTP/2 响应 DATA 聚合改为可按 `MaxResponseBytes` 有界增长，避免固定 4 KiB 初始响应 buffer。
  - 若需要新增回调/接口，保持内部边界清晰，不让 `Http2Connection` 直接理解 `KhWorkspace`。
- `include/KernelHttp/http2/Http2Connection.h`
  - 如采用接收 sink/callback，需要新增小型内部接口或参数结构。
  - 新增成员缓冲时必须为堆/常驻成员，不放大栈。
- `src/KernelHttpLib/engine/HttpEngine.cpp`
  - 高层 H2 调用侧接入可增长 workspace 响应聚合。
  - 内容解码前确保 `DecodedBody` 对需要解码的 body 有足够容量；identity 响应不应无谓复制到固定 16 KiB decoded buffer。
- `include/KernelHttp/engine/Workspace.h`
  - 如需新增 workspace helper 声明，放在这里。
- `src/KernelHttpLib/engine/Workspace.cpp`
  - 如需新增 `EnsureDecodedBodyCapacity` 或 H2 response append helper，使用现有 `GrowBuffer` 模式。
- `src/KernelHttpLib/tls/TlsHandshake12.cpp`
  - 为 `ParseServerKeyExchange` 增加测试驱动修复点；必要时将读取失败映射到更精确错误并增加字段级校验。
- `src/KernelHttpLib/tls/TlsConnection.cpp`
  - 在 TLS 1.2 ServerKeyExchange 失败日志中打印 cipher suite、key exchange kind、curve type、named group、point length、signature scheme、signature length、offset/body length。
  - 调试日志不得泄露完整密钥材料或签名内容。
- `tests/http2_client_tests.cpp`
  - 新增 HTTP/2 字段值 OWS 兼容测试。
  - 新增高层/底层大响应 DATA 聚合容量测试。
- `tests/high_level_api_tests.cpp`
  - 覆盖 `khttp::Post` / 高层 HTTPS H2 大响应在 `MaxResponseBytes` 内成功、超过上限返回 `STATUS_BUFFER_TOO_SMALL`。
- `tests/tls_record_tests.cpp` 或 `tests/tls_handshake_tests.cpp`
  - 新增 `ws.postman-echo.com` 抓到的 ServerKeyExchange fixture 解析测试。
- `src/KernelHttpTest/samples/AdvancedScenarioSamples.cpp`
  - 修复完成后只调整期望/日志，不把协议错误降级为公网诊断通过。

### Create If Needed

- `tests/testdata/tls/ws-postman-echo-server-key-exchange.bin`
  - 保存去掉 TLS handshake 4 字节头后的 ServerKeyExchange body fixture。
  - 不保存私钥、会话密钥或证书私有材料。

---

## Chunk 1: HTTP/2 响应头字段值 OWS 兼容

### Task 1: 为 HTTP/2 响应头首尾 OWS 写失败测试

**Files:**
- Modify: `tests/http2_client_tests.cpp`
- Modify: `src/KernelHttpLib/http2/Http2Connection.cpp`

- [ ] **Step 1: 添加响应头值首空格测试**

在 `tests/http2_client_tests.cpp` 新增一个 fixture：服务端返回 HTTP/2 HEADERS，字段包含：

```text
:status: 200
content-security-policy:  frame-ancestors 'self'
content-length: 0
```

注意字段值前有一个 SP。

- [ ] **Step 2: 运行 HTTP/2 测试确认失败**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe; exit $LASTEXITCODE'
```

Expected: 新测试失败，当前返回 `STATUS_INVALID_NETWORK_RESPONSE`。

- [ ] **Step 3: 修改字段值校验**

在 `src/KernelHttpLib/http2/Http2Connection.cpp` 中调整 `IsValidHttp2FieldValue`：

- 允许首尾 SP/HTAB。
- 继续拒绝 `NUL`、`\r`、`\n`。
- 不放宽字段名校验，大写字段名、非法冒号、connection-specific header 仍拒绝。

实现方向：

```cpp
bool IsValidHttp2FieldValue(const char* data, SIZE_T len) noexcept
{
    if (data == nullptr && len != 0) {
        return false;
    }
    for (SIZE_T i = 0; i < len; ++i) {
        if (data[i] == '\0' || data[i] == '\r' || data[i] == '\n') {
            return false;
        }
    }
    return true;
}
```

- [ ] **Step 4: 增加非法 CR/LF/NUL 回归测试**

确保新增测试覆盖：

- 字段值包含 `\r` 返回 `STATUS_INVALID_NETWORK_RESPONSE`。
- 字段值包含 `\n` 返回 `STATUS_INVALID_NETWORK_RESPONSE`。
- 字段值包含 `\0` 返回 `STATUS_INVALID_NETWORK_RESPONSE`。

- [ ] **Step 5: 运行 HTTP/2/HPACK 测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\hpack_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\http2_client_tests.exe; exit $LASTEXITCODE'
```

Expected: PASS。

---

## Chunk 2: HTTP/2 高层响应聚合按 MaxResponseBytes 有界增长

### Task 2: 为 H2 大响应聚合写失败测试

**Files:**
- Modify: `tests/http2_client_tests.cpp`
- Modify: `tests/high_level_api_tests.cpp`
- Modify: `include/KernelHttp/engine/Workspace.h`
- Modify: `src/KernelHttpLib/engine/Workspace.cpp`
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`
- Modify: `include/KernelHttp/http2/Http2Connection.h`
- Modify: `src/KernelHttpLib/http2/Http2Connection.cpp`

- [ ] **Step 1: 添加底层 H2 大响应测试**

在 `tests/http2_client_tests.cpp` 增加响应 DATA 总长度超过 `KhWorkspaceResponseInitialBytes` 的 fixture，例如 88 KiB，服务端分多个 DATA frame 返回。

Expected behavior:

- 当提供的 response sink/缓冲上限足够时，返回 `STATUS_SUCCESS`。
- body 长度等于 fixture 总长度。
- DATA frame 流控仍发送 WINDOW_UPDATE。

- [ ] **Step 2: 添加高层 khttp 大响应测试**

在 `tests/high_level_api_tests.cpp` 覆盖：

- session `MaxResponseBytes = 128 * 1024`，H2 POST 返回约 88 KiB body，期望成功。
- session 或 send options `MaxResponseBytes = 64 * 1024`，同一响应期望 `STATUS_BUFFER_TOO_SMALL`。

- [ ] **Step 3: 运行测试确认失败**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\high_level_api_tests.exe; exit $LASTEXITCODE'
```

Expected: 新增大响应测试失败，暴露固定 H2 response buffer。

- [ ] **Step 4: 设计 H2 响应接收 sink**

首选方案：给 `Http2Connection::SendRequest` 增加内部响应写入 sink 参数，由 `HttpEngine` 提供 workspace-backed append。

要求：

- sink 在追加前调用 `KhWorkspaceEnsureResponseCapacity`。
- 总容量不得超过 `MaxResponseBytes`。
- 不在 `Http2Connection` 内创建大栈临时数组。
- 不在每个 DATA frame 上重复分配小堆对象；使用 workspace 常驻 `Response` buffer。

如果不新增接口，也可在进入 H2 请求前按 `MaxResponseBytes` 一次性确保 `workspace.Response` 容量，但必须评估 nonpaged pool 占用；优先使用按需增长。

- [ ] **Step 5: 实现 workspace decoded buffer 增长**

如果响应存在 `Content-Encoding` 且需要解码：

- 解码目标容量应按 `MaxResponseBytes` 有界增长。
- identity 或无 `Content-Encoding` 响应应直接引用原 body，不能因为固定 16 KiB `DecodedBody` 失败。
- 新增 helper 时放入 `Workspace.cpp`，复用 `GrowBuffer`。

- [ ] **Step 6: 实现 H2 DATA append**

在 `Http2Connection.cpp` 的 DATA 处理路径替换固定判断：

```cpp
if (bodyLen + contentLen > responseBodyCapacity) {
    return STATUS_BUFFER_TOO_SMALL;
}
MemCopy(responseBody + bodyLen, content, contentLen);
```

改为通过 sink/workspace append：

- 先检查加法溢出。
- 再确保容量或返回 `STATUS_BUFFER_TOO_SMALL`。
- 再复制到 heap/workspace buffer。

- [ ] **Step 7: 运行 H2/高层测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\high_level_api_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\khttp_tests.exe; exit $LASTEXITCODE'
```

Expected: PASS。

---

## Chunk 3: TLS 1.2 ServerKeyExchange 字段级定位与修复

### Task 3: 固化公网 ServerKeyExchange fixture

**Files:**
- Create if needed: `tests/testdata/tls/ws-postman-echo-server-key-exchange.bin`
- Modify: `tests/tls_record_tests.cpp` or `tests/tls_handshake_tests.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake12.cpp`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`

- [ ] **Step 1: 保存最小 ServerKeyExchange body fixture**

从 OpenSSL 抓到的 TLS 1.2 `ServerKeyExchange` 去掉 handshake header `0c 00 01 49` 后保存 body：

```text
03 00 17 41 04 ... 04 01 01 00 ...
```

fixture 只包含公开服务端发送的临时公钥参数和签名，不包含私钥或会话密钥。

- [ ] **Step 2: 添加解析单测**

测试内容：

- context cipher suite 设为 `TlsEcdheRsaWithAes128GcmSha256 (0xC02F)`。
- message type 为 `ServerKeyExchange`。
- body 长度为 329。
- 期望 `ParseServerKeyExchange` 成功。
- 期望 `NamedGroup == Secp256r1`。
- 期望 `EcPointLength == 65`。
- 期望 `SignatureScheme == RsaPkcs1Sha256`。
- 期望 `SignatureLength == 256`。

- [ ] **Step 3: 运行 TLS 测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\tls_handshake_tests.exe; exit $LASTEXITCODE'
```

Expected: 如果静态解析已支持，则测试 PASS；如果失败，修复 parser。

- [ ] **Step 4: 增加字段级失败日志**

在 `TlsConnection.cpp` 现有日志基础上增加非敏感字段：

- selected cipher suite。
- key exchange kind。
- ServerKeyExchange body length。
- curve type。
- named group。
- point length。
- signature scheme。
- signature length。
- parser offset。

禁止打印完整 ECDHE point、签名字节、premaster secret、traffic secret。

- [ ] **Step 5: 如果 fixture PASS，则用 live kernel 断点验证运行偏差**

使用 WinDbg 在以下点打断点：

- `KernelHttpTest!KernelHttp::tls::TlsHandshake12::ParseServerKeyExchange`
- `KernelHttpTest!KernelHttp::tls::TlsConnection::ConnectTls12` 中调用 parse 后的位置

捕获：

- `context_.CipherSuite()`。
- `handshake.Type`。
- `handshake.BodyLength`。
- `handshake.Body[0..8]`。
- parse 返回状态。

不要在高频路径设置无条件长期断点；只针对 WebSocket 复现路径短时断住。

- [ ] **Step 6: 修复实际偏差**

按 live 结果选择最小修复：

- 如果 body 偏移错误，修复 handshake message 读取/聚合逻辑。
- 如果 cipher suite 状态不一致，修复 `TlsContext` 更新或 ServerHello 解析后的上下文设置。
- 如果 signature scheme offer/policy 判断错误，修复 `ValidateServerKeyExchangeOffer`。
- 如果是分片读取问题，补充跨 record handshake 聚合测试。

不得通过忽略 parse 错误、跳过签名验证、切换 WebSocket host 或自动 TLS 降级解决。

- [ ] **Step 7: 运行 TLS/WebSocket 用户态测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\tls_handshake_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\websocket_client_tests.exe; exit $LASTEXITCODE'
```

Expected: PASS。

---

## Chunk 4: KernelHttpTest 样例回归与结果边界

### Task 4: 修复后保持样例失败边界清晰

**Files:**
- Modify: `src/KernelHttpTest/samples/AdvancedScenarioSamples.cpp`
- Modify: `src/KernelHttpTest/samples/HighLevelApiSamples.cpp`
- Modify: `src/KernelHttpTest/samples/HttpVerbSamples.cpp`
- Modify: `src/KernelHttpTest/samples/Http2VerbSamples.cpp`

- [ ] **Step 1: 复核公网失败分类**

确认以下状态仍可作为公网环境诊断：

- `STATUS_NO_MATCH`
- `STATUS_IO_TIMEOUT`
- `STATUS_NETWORK_UNREACHABLE`
- `STATUS_HOST_UNREACHABLE`
- `STATUS_CONNECTION_REFUSED`
- `STATUS_CONNECTION_RESET`
- `STATUS_CONNECTION_ABORTED`

确认以下状态不得被当成公网环境通过：

- `STATUS_INVALID_NETWORK_RESPONSE`
- `STATUS_NOT_SUPPORTED`
- `STATUS_BUFFER_TOO_SMALL`
- `STATUS_TRUST_FAILURE`，除非负面样本明确预期。

- [ ] **Step 2: LargePost 不降级**

修复完成后 `HTTP LargePost` 应成功。不要把 `STATUS_BUFFER_TOO_SMALL` 加入 `IsPublicEndpointDiagnosticStatus`。

- [ ] **Step 3: HTTPS HTTP/2 不降级**

修复完成后 `httpbin.dev` HTTP/2 GET/POST/encoding matrix 应成功。不要强制改成 HTTP/1.1 ALPN。

- [ ] **Step 4: WebSocket 不降级**

修复完成后 `ws.postman-echo.com` 若公网可达应能通过 TLS1.2/HTTP1.1 Upgrade。只有真实网络不可达/超时才按公网诊断处理。

---

## Chunk 5: 构建、测试与驱动验证

### Task 5: 用户态协议测试全量回归

**Files:**
- No source change expected.

- [ ] **Step 1: 运行核心用户态测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\websocket_frame_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\websocket_client_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\http2_frame_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\hpack_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\http2_client_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\tls_record_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\tls_crypto_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\tls_handshake_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\high_level_api_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\khttp_tests.exe; exit $LASTEXITCODE'
```

Expected: PASS。

### Task 6: Debug/Release 构建

**Files:**
- No source change expected.

- [ ] **Step 1: Debug x64 构建**

Run:

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
```

Expected: 0 warnings, 0 errors。

- [ ] **Step 2: Release x64 构建**

Run:

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64
```

Expected: 0 warnings, 0 errors。

### Task 7: 驱动加载全量示例验证

**Files:**
- No source change expected.

- [ ] **Step 1: 使用项目允许的驱动构建/加载路径**

按当前项目已有驱动部署方式构建并加载 Debug 包。不要运行禁止的 `https_smoke.ps1 -SkipDriverBuild`。

- [ ] **Step 2: 观察 WinDbg 输出**

Expected:

- `HTTPS GET HTTP/2 ALPN` 成功。
- HTTPS encoding matrix 不再因 `0xC00000C3` 失败。
- `HTTP LargePost` 不再返回 `0xC0000023`。
- `ws.postman-echo.com` WebSocket 样例不再卡在 `parse ServerKeyExchange failed`；若公网不可达，只记录网络诊断状态。
- `KernelHttpTest 全量示例完成` 不再因上述三类问题聚合失败。

---

## Completion Criteria

- HTTP/2 response header value OWS 行为符合 RFC 边界：允许首尾 SP/HTAB，拒绝 NUL/CR/LF。
- 高层 HTTP/2 响应聚合按 `MaxResponseBytes` 有界增长；大响应在上限内成功，超过上限返回 `STATUS_BUFFER_TOO_SMALL`。
- H2 identity 响应不因为固定 16 KiB decoded buffer 失败。
- TLS 1.2 `ServerKeyExchange` 对 ECDHE_RSA/P-256/rsa_pkcs1_sha256/2048-bit signature 成功解析并验证。
- `ws.postman-echo.com` 失败点若仍存在，必须有字段级日志证明真实原因，不能保留模糊 `STATUS_NOT_SUPPORTED`。
- lib 新增缓冲全部在 heap/workspace/常驻成员上；没有新增大栈数组，没有直接 `new/delete`。
- 用户态测试、Debug 构建、Release 构建均通过，0 warnings / 0 errors。
- 未运行禁止烟测命令，未执行 git commit。
