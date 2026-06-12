# TLS Signature And Public Sample Fixes Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 补齐 TLS 签名方案能力矩阵，并修复 2026-06-12 全量公网示例中暴露的 WebSocket TLS1.2 握手失败、HTTPS HTTP/2 header 缓冲复用、LargePost 容量边界问题。

**Architecture:** TLS 签名方案按能力表、策略、ClientHello offer、ServerKeyExchange 解析、验签映射一条链闭环补齐；SHA1 只作为 TLS1.2 legacy 兼容能力显式启用，不进入 ModernDefault 主路径。HTTP/2 header name/value 与响应 body 解码使用互不覆盖的堆缓冲；LargePost 使用有界 `MaxResponseBytes` 和 HTTP/2 flow-control 诊断修正，不跳过公网样例、不改端点逃避问题。

**Tech Stack:** Windows kernel C++ under `/kernel`, WSK, kernel CNG/BCrypt, custom TLS 1.2/1.3, custom HTTP/2/HPACK, WebSocket HTTP/1.1 Upgrade, khttp engine, user-mode protocol tests, KernelHttpTest driver, MSBuild via `pwsh`.

---

## Ground Rules

- 回复、计划维护和最终记录使用简体中文。
- 只生成和执行计划，不自动 git commit；只有用户明确要求提交时才提交。
- 禁止把“兜底设计”当作正式架构手段；禁止用“临时兜底后面再删”“先这样跑起来”作为理由。
- 不通过跳过公网样例、吞掉 `STATUS_NOT_SUPPORTED`、禁用证书校验、强制切换端点、禁用 HTTP/2、默认降级 TLS 策略来掩盖问题。
- `lib` 禁止新增大栈对象；新增缓冲必须使用 nonpaged heap、workspace、连接常驻成员或既有 `HeapArray` / `HeapObject`。
- `lib` 禁止直接 `new/delete`；沿用项目 allocator：`AllocateNonPagedObject`、`AllocateNonPagedArray`、`FreeNonPagedObject`、`FreeNonPagedArray`、`HeapArray`、`HeapObject`、workspace helper。
- 高频堆缓冲必须考虑常驻：优先放入 `KhWorkspace`、`Http2Connection`、sample IO buffer 结构或连接对象成员，避免热路径反复分配释放。
- Debug/Release 构建必须保持最高警告等级并视警告为错误；新增代码清零所有 warning。
- 写完代码后必须进入 user-mode protocol tests 和 Debug 构建验证；禁止 test 烟测，尤其禁止运行：

```powershell
pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild
```

## Failure Evidence

2026-06-12 live kernel log 的关键证据：

- `ws.postman-echo.com` WebSocket TLS1.2 握手失败：

```text
TlsConnection parse ServerKeyExchange failed: 0xC00000BB cipher=0xC02F kx=3 type=12 body=329 curve=3 group=23 point=65 sig=0x0201 sigLen=256 offset=329
```

- `sig=0x0201` 是 TLS1.2 legacy `rsa_pkcs1_sha1`。当前 `TlsSignatureScheme`、`TlsSignatureSchemeCapabilities`、`ToSignatureAlgorithm`、`HashForSignature`、`SignatureSchemeMatchesPublicKey` 都没有 SHA1 signature scheme 闭环，所以解析阶段返回 `STATUS_NOT_SUPPORTED`。
- `tests/testdata/tls/ws-postman-echo-server-key-exchange.bin` 现有 fixture 是 `0x0401` (`rsa_pkcs1_sha256`)，不能覆盖这次公网实际返回的 `0x0201`。
- HTTPS encoding matrix 里 `gzip/deflate/br` 请求成功，但 header 打印变成 JSON 碎片。原因是 `HttpsClient` HTTP/2 分支用 `DecodedBodyBuffer` 承载 HPACK 解出的 header name/value，随后又把同一块 buffer 用作 content decode 输出，导致 `response.Headers[*].Name/Value` 指针被 body 覆盖。
- `HTTP LargePost` 返回 `STATUS_BUFFER_TOO_SMALL (0xC0000023)`。当前高级场景 `LargeBodyBytes = 64 * 1024`，但 session `MaxResponseBytes = 128 * 1024`；公网 echo JSON 可能超过该上限。同时需要补充 HTTP/2 大 POST flow-control 边界测试，确认不是 65535 初始窗口后的发送/接收状态问题。

## File Structure

### Modify

- `include/KernelHttp/tls/TlsHandshake12.h`
  - 增加 TLS1.2 legacy 签名方案枚举：`RsaPkcs1Sha1 = 0x0201`、`EcdsaSha1 = 0x0203`。
  - 不增加 DSA、MD5、SHA224 主路径支持；若需要识别，必须另开计划补齐证书公钥、hash、provider 和策略矩阵。
- `include/KernelHttp/crypto/CngProvider.h`
  - 增加 `SignatureAlgorithm::RsaPkcs1Sha1` 和 `SignatureAlgorithm::EcdsaSha1`。
- `src/KernelHttpLib/crypto/CngProvider.cpp`
  - 映射 RSA/ECDSA SHA1 验签到 `HashAlgorithm::Sha1` 和对应 CNG padding / ECDSA verify。
  - 复用已有 SHA1 hash provider / user-mode SHA1 fallback，不新增栈大缓冲。
- `src/KernelHttpLib/tls/TlsCapabilities.cpp`
  - 将 `RsaPkcs1Sha1`、`EcdsaSha1` 登记为 `Legacy`。
- `include/KernelHttp/tls/TlsPolicy.h`
  - 增加显式兼容开关，例如 `EnableTls12Sha1Signatures`，默认 `false`。
- `src/KernelHttpLib/tls/TlsPolicy.cpp`
  - ModernDefault 拒绝 `EnableTls12Sha1Signatures = true`。
  - CompatibilityExplicit 仅在 `EnableTls12Sha1Signatures = true` 时允许 SHA1 signature scheme。
- `src/KernelHttpLib/tls/TlsConnection.cpp`
  - `TlsDefaultOfferSignatureSchemes` 在容量上包含 SHA1 legacy 项，但只由 policy 过滤进实际 ClientHello。
  - `ToSignatureAlgorithm`、`HashForSignature`、`SignatureSchemeMatchesPublicKey`、客户端证书签名选择逻辑补齐 SHA1 分支。
  - ServerKeyExchange 失败日志保留字段级输出，不打印签名内容或密钥材料。
- `src/KernelHttpLib/tls/TlsHandshake12.cpp`
  - `DefaultSignatureSchemes` 与 policy offer 行为对齐；解析只确认 known scheme，策略由 offer validation 决定。
- `src/KernelHttpLib/client/HttpsClient.cpp`
  - HTTP/2 分支使用独立 HPACK name/value 缓冲，不能复用 content decode 输出缓冲。
- `include/KernelHttp/client/HttpsClient.h`
  - 在 `HttpsResponseBuffers` 增加 `HeaderNameValueBuffer` / `HeaderNameValueBufferLength`，或改为优先使用 `options.Workspace->Http2HeaderScratch`。
  - 若选择新增字段，所有 H2 调用方必须显式提供；不能 silent fallback 到 `DecodedBodyBuffer`。
- `src/KernelHttpTest/samples/HttpVerbSamples.cpp`
  - 更新 HTTPS sample IO buffer，为 HTTP/2 header name/value 提供独立常驻堆/结构成员缓冲。
- `src/KernelHttpTest/samples/AdvancedScenarioSamples.cpp`
  - WebSocket `ws.postman-echo.com` 样例显式启用 TLS1.2 SHA1 signature compatibility policy，并在日志中说明这是 endpoint 兼容策略。
  - LargePost 使用有界但足够的 `MaxResponseBytes`，例如 256 KiB 或按 `LargeBodyBytes` 计算出的上界；不得把 `STATUS_BUFFER_TOO_SMALL` 加入公网诊断通过集合。
- `src/KernelHttpLib/http2/Http2Connection.cpp`
  - 补充大 POST flow-control 诊断日志，必要时修复 connection-level / stream-level `WINDOW_UPDATE` 处理顺序问题。
- `tests/tls_record_tests.cpp`
  - 补 TLS signature scheme policy、ServerKeyExchange parse/offer/verify 相关测试。
- `tests/tls_crypto_tests.cpp`
  - 补 CNG RSA/ECDSA SHA1 验签映射测试，或在已有签名测试文件中补覆盖。
- `tests/tls_handshake_tests.cpp`
  - 补 ClientHello signature_algorithms offer 矩阵：ModernDefault 不 offer SHA1，CompatibilityExplicit + `EnableTls12Sha1Signatures` 才 offer。
- `tests/http2_client_tests.cpp`
  - 补 HTTPS/HTTP2 header buffer lifetime 或 H2 response frame 测试。
  - 补 POST body 长度 `Http2InitialWindowSize + 1` 的 flow-control 回归测试。
- `tests/high_level_api_tests.cpp`
  - 补 LargePost 在有界容量内成功、低容量明确 `STATUS_BUFFER_TOO_SMALL` 的测试。
- `tests/websocket_client_tests.cpp`
  - 补 WebSocket TLS policy 透传测试，确认连接选项能把 SHA1 compatibility policy 传到 TLS 连接。

### Create If Needed

- `tests/testdata/tls/ws-postman-echo-server-key-exchange-sha1.bin`
  - 仅保存去掉 TLS handshake 4 字节头后的 ServerKeyExchange body。
  - 不保存私钥、session secret、key log 或证书私有材料。
  - 如果没有完整公网抓包，用测试构造器生成最小 ECDHE_RSA/P-256/`0x0201` body 覆盖 parse/offer；真实验签另用本地公钥测试向量。

---

## Chunk 1: TLS 签名方案能力矩阵

### Task 1: 补齐 signature scheme 枚举和能力表测试

**Files:**
- Modify: `include/KernelHttp/tls/TlsHandshake12.h`
- Modify: `src/KernelHttpLib/tls/TlsCapabilities.cpp`
- Modify: `tests/tls_record_tests.cpp`

- [ ] **Step 1: 写失败测试：SHA1 schemes 是 known 但 legacy**

在 `tests/tls_record_tests.cpp::TestTlsCapabilityTables` 或相邻 policy 测试中新增断言：

```cpp
Expect(KernelHttp::tls::TlsIsKnownSignatureScheme(TlsSignatureScheme::RsaPkcs1Sha1),
    "TLS 1.2 rsa_pkcs1_sha1 is known");
Expect(KernelHttp::tls::TlsIsKnownSignatureScheme(TlsSignatureScheme::EcdsaSha1),
    "TLS 1.2 ecdsa_sha1 is known");
Expect(!KernelHttp::tls::TlsIsDefaultEnabledSignatureScheme(TlsSignatureScheme::RsaPkcs1Sha1),
    "rsa_pkcs1_sha1 is not modern-default");
Expect(!KernelHttp::tls::TlsIsDefaultEnabledSignatureScheme(TlsSignatureScheme::EcdsaSha1),
    "ecdsa_sha1 is not modern-default");
```

- [ ] **Step 2: 运行失败测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe; exit $LASTEXITCODE'
```

Expected: FAIL，编译或测试提示 enum/capability 不存在。

- [ ] **Step 3: 添加 enum 和 capability**

在 `TlsSignatureScheme` 中添加：

```cpp
RsaPkcs1Sha1 = 0x0201,
EcdsaSha1 = 0x0203,
```

在 `SignatureSchemeCapabilities` 中添加：

```cpp
{ TlsSignatureScheme::RsaPkcs1Sha1, TlsCapabilityDisposition::Legacy, TlsCapabilityDisposition::Legacy },
{ TlsSignatureScheme::EcdsaSha1, TlsCapabilityDisposition::Legacy, TlsCapabilityDisposition::Legacy },
```

- [ ] **Step 4: 运行测试确认通过**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe; exit $LASTEXITCODE'
```

Expected: PASS。

### Task 2: 增加 SHA1 签名策略开关

**Files:**
- Modify: `include/KernelHttp/tls/TlsPolicy.h`
- Modify: `src/KernelHttpLib/tls/TlsPolicy.cpp`
- Modify: `tests/tls_record_tests.cpp`

- [ ] **Step 1: 写失败测试：ModernDefault 永远不允许 SHA1**

新增断言：

```cpp
TlsPolicy policy = {};
Expect(!KernelHttp::tls::TlsPolicyAllowsSignatureScheme(policy, TlsSignatureScheme::RsaPkcs1Sha1),
    "modern policy rejects rsa_pkcs1_sha1");
Expect(!KernelHttp::tls::TlsPolicyAllowsSignatureScheme(policy, TlsSignatureScheme::EcdsaSha1),
    "modern policy rejects ecdsa_sha1");
policy.EnableTls12Sha1Signatures = true;
Expect(KernelHttp::tls::TlsValidatePolicy(policy) == STATUS_INVALID_PARAMETER,
    "modern policy rejects SHA1 compatibility switch");
```

- [ ] **Step 2: 写失败测试：CompatibilityExplicit 必须显式打开 SHA1**

```cpp
policy = {};
policy.Profile = TlsSecurityProfile::CompatibilityExplicit;
Expect(!KernelHttp::tls::TlsPolicyAllowsSignatureScheme(policy, TlsSignatureScheme::RsaPkcs1Sha1),
    "compatibility policy keeps SHA1 off by default");
policy.EnableTls12Sha1Signatures = true;
Expect(KernelHttp::tls::TlsPolicyAllowsSignatureScheme(policy, TlsSignatureScheme::RsaPkcs1Sha1),
    "compatibility policy allows rsa_pkcs1_sha1 when explicitly enabled");
```

- [ ] **Step 3: 运行失败测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe; exit $LASTEXITCODE'
```

Expected: FAIL，因为 `EnableTls12Sha1Signatures` 不存在。

- [ ] **Step 4: 实现 policy 字段和校验**

在 `TlsPolicy` 增加：

```cpp
bool EnableTls12Sha1Signatures = false;
```

在 `TlsValidatePolicy` 的 `ModernDefault` 分支拒绝该字段；在 `TlsPolicyAllowsSignatureScheme` 对 `RsaPkcs1Sha1` / `EcdsaSha1` 增加显式开关判断。

- [ ] **Step 5: 运行测试确认通过**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe; exit $LASTEXITCODE'
```

Expected: PASS。

## Chunk 2: TLS1.2 SHA1 验签闭环

### Task 3: 补 CNG 签名算法映射

**Files:**
- Modify: `include/KernelHttp/crypto/CngProvider.h`
- Modify: `src/KernelHttpLib/crypto/CngProvider.cpp`
- Test: `tests/tls_crypto_tests.cpp`

- [ ] **Step 1: 写失败测试：RSA/ECDSA SHA1 验签可调用**

优先复用现有签名验签测试 helper。如果没有现成 helper，新增最小 fixture：

- RSA public key + SHA1 digest + PKCS#1 v1.5 SHA1 signature。
- ECDSA P-256 public key + SHA1 digest + DER/raw signature，按当前 ECDSA verify 输入格式构造。

测试目标：

```cpp
ExpectStatus(status, STATUS_SUCCESS, "RSA PKCS1 SHA1 signature verifies");
ExpectStatus(status, STATUS_SUCCESS, "ECDSA SHA1 signature verifies");
```

所有 fixture 使用 `static const UCHAR[]` 文件级常量或测试数据文件；不要在 lib 中新增栈缓冲。

- [ ] **Step 2: 运行失败测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_crypto_tests.exe; exit $LASTEXITCODE'
```

Expected: FAIL，`SignatureAlgorithm` 缺少 SHA1 分支。

- [ ] **Step 3: 添加 `SignatureAlgorithm` 值**

在 `include/KernelHttp/crypto/CngProvider.h` 中添加：

```cpp
RsaPkcs1Sha1,
EcdsaSha1,
```

- [ ] **Step 4: 实现 CNG 映射**

在 `CngProvider::VerifySignature` 中：

- `RsaPkcs1Sha1` 使用 `BCRYPT_PKCS1_PADDING_INFO` + `BCRYPT_SHA1_ALGORITHM` / `HashAlgorithm::Sha1`。
- `EcdsaSha1` 使用 ECDSA provider 与 SHA1 digest。
- user-mode fallback 使用已有 `Sha1Hash` / verify helper，不新增栈大对象。

- [ ] **Step 5: 运行测试确认通过**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_crypto_tests.exe; exit $LASTEXITCODE'
```

Expected: PASS。

### Task 4: 补 TLSConnection 签名方案映射

**Files:**
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `tests/tls_record_tests.cpp`

- [ ] **Step 1: 写失败测试：ServerKeyExchange SHA1 parse 成功但现代 offer 拒绝**

构造 ECDHE_RSA/P-256 ServerKeyExchange body：

- curve type `3`
- named group `23`
- point length `65`
- signature scheme `0x0201`
- signature length 非零

断言：

```cpp
Expect(status == STATUS_SUCCESS, "rsa_pkcs1_sha1 ServerKeyExchange parses structurally");
Expect(keyExchange.SignatureScheme == TlsSignatureScheme::RsaPkcs1Sha1,
    "rsa_pkcs1_sha1 signature scheme parses");

TlsClientHelloOptions modernOptions = {};
status = TlsHandshake12::ValidateServerKeyExchangeOffer(keyExchange, modernOptions);
Expect(status == STATUS_INVALID_NETWORK_RESPONSE,
    "modern ClientHello offer rejects unoffered rsa_pkcs1_sha1");
```

- [ ] **Step 2: 写失败测试：兼容策略 offer 后接受 SHA1**

如果 `ValidateServerKeyExchangeOffer` 只能接收 `TlsClientHelloOptions`，构造 `SignatureSchemes = { RsaPkcs1Sha1 }`：

```cpp
const TlsSignatureScheme sha1Only[] = { TlsSignatureScheme::RsaPkcs1Sha1 };
TlsClientHelloOptions options = {};
options.SignatureSchemes = sha1Only;
options.SignatureSchemeCount = sizeof(sha1Only) / sizeof(sha1Only[0]);
status = TlsHandshake12::ValidateServerKeyExchangeOffer(keyExchange, options);
Expect(status == STATUS_SUCCESS, "offered rsa_pkcs1_sha1 ServerKeyExchange is accepted");
```

- [ ] **Step 3: 运行失败测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe; exit $LASTEXITCODE'
```

Expected: FAIL，当前 parse 返回 `STATUS_NOT_SUPPORTED`。

- [ ] **Step 4: 补 `TlsConnection.cpp` 映射**

更新以下 helper：

- `ToSignatureAlgorithm(RsaPkcs1Sha1 -> crypto::SignatureAlgorithm::RsaPkcs1Sha1)`
- `ToSignatureAlgorithm(EcdsaSha1 -> crypto::SignatureAlgorithm::EcdsaSha1)`
- `HashForSignature(...Sha1 -> crypto::HashAlgorithm::Sha1)`
- `SignatureSchemeMatchesPublicKey(Rsa -> RsaPkcs1Sha1)`
- `SignatureSchemeMatchesPublicKey(ECDSA P-256/P-384/P-521 -> EcdsaSha1)`；若只允许 ECDSA SHA1 与任意 ECDSA key，需要测试覆盖并说明原因。

- [ ] **Step 5: 运行测试确认通过**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe; exit $LASTEXITCODE'
```

Expected: PASS。

### Task 5: 补 ClientHello offer 策略矩阵

**Files:**
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake12.cpp`
- Test: `tests/tls_handshake_tests.cpp`

- [ ] **Step 1: 写失败测试：ModernDefault 不 offer SHA1**

在 `tests/tls_handshake_tests.cpp` 使用现有 `ClientHelloOffersSignatureScheme` helper：

```cpp
TlsPolicy modern = {};
// Encode TLS1.2 ClientHello with modern policy.
Expect(!ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::RsaPkcs1Sha1),
    "modern TLS 1.2 ClientHello does not offer rsa_pkcs1_sha1");
```

- [ ] **Step 2: 写失败测试：CompatibilityExplicit + SHA1 开关才 offer**

```cpp
TlsPolicy compatibility = {};
compatibility.Profile = TlsSecurityProfile::CompatibilityExplicit;
compatibility.EnableTls12Sha1Signatures = true;
// Encode TLS1.2 ClientHello with compatibility policy.
Expect(ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::RsaPkcs1Sha1),
    "compatibility TLS 1.2 ClientHello offers rsa_pkcs1_sha1 when enabled");
```

- [ ] **Step 3: 运行失败测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe; exit $LASTEXITCODE'
```

Expected: FAIL。

- [ ] **Step 4: 扩展 offer 数组但由 policy 过滤**

在 `TlsDefaultOfferSignatureSchemes` 和 TLS1.2 default signature list 中加入 SHA1 legacy 项，但实际写入 ClientHello 前必须经过 `TlsPolicyAllowsSignatureScheme`。

- [ ] **Step 5: 运行测试确认通过**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe; exit $LASTEXITCODE'
```

Expected: PASS。

## Chunk 3: WebSocket 公网样例使用显式兼容策略

### Task 6: 让 ws.postman-echo.com 样例显式启用 TLS1.2 SHA1 signature compatibility

**Files:**
- Modify: `src/KernelHttpTest/samples/HttpVerbSamples.cpp`
- Modify: `src/KernelHttpTest/samples/HighLevelApiSamples.cpp` if it has a Postman WebSocket path
- Modify: `src/KernelHttpTest/samples/AdvancedScenarioSamples.cpp`
- Test: `tests/websocket_client_tests.cpp`

- [ ] **Step 1: 写 policy 透传测试**

在 `tests/websocket_client_tests.cpp` 的 fake TLS/WebSocket path 中记录 `WebSocketConnectOptions.Policy`，断言：

```cpp
Expect(observedPolicy.Profile == TlsSecurityProfile::CompatibilityExplicit,
    "WebSocket sample passes compatibility TLS policy");
Expect(observedPolicy.EnableTls12Sha1Signatures,
    "WebSocket sample explicitly enables TLS 1.2 SHA1 signatures");
```

- [ ] **Step 2: 运行失败测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe; exit $LASTEXITCODE'
```

Expected: FAIL，样例尚未设置 policy。

- [ ] **Step 3: 设置样例 policy**

对 `ws.postman-echo.com` 相关样例设置：

```cpp
options.Policy.Profile = tls::TlsSecurityProfile::CompatibilityExplicit;
options.Policy.EnableTls12Sha1Signatures = true;
```

并在样例日志中说明：

```text
TLS策略=CompatibilityExplicit SHA1签名=启用(endpoint兼容)
```

不要对所有 WebSocket 默认启用；`wss://websocket-echo.com` 已经能通过，不应被无差别改成 legacy 策略。

- [ ] **Step 4: 运行 WebSocket 测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe; exit $LASTEXITCODE'
```

Expected: PASS。

## Chunk 4: HTTPS HTTP/2 Header Buffer Lifetime

### Task 7: 拆分 HPACK name/value 缓冲和 decoded body 缓冲

**Files:**
- Modify: `include/KernelHttp/client/HttpsClient.h`
- Modify: `src/KernelHttpLib/client/HttpsClient.cpp`
- Modify: `src/KernelHttpTest/samples/HttpVerbSamples.cpp`
- Test: `tests/http2_client_tests.cpp` or `tests/high_level_api_tests.cpp`

- [ ] **Step 1: 写失败测试：H2 解码后 header 不被 body 覆盖**

构造一个 HTTP/2 响应：

- header: `content-type: application/json`
- body: JSON 文本，开头包含容易识别的 `{ "args": ... }`
- Content-Encoding 为 `gzip` 或 `identity` 均可，但必须触发 `HttpsClient` 的 H2 header decode 后再 content decode。

断言请求完成后：

```cpp
Expect(TextEquals(response.Headers[contentTypeIndex].Name, MakeText("content-type")),
    "HTTP/2 header name survives content decode");
Expect(TextEquals(response.Headers[contentTypeIndex].Value, MakeText("application/json")),
    "HTTP/2 header value survives content decode");
```

- [ ] **Step 2: 运行失败测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe; exit $LASTEXITCODE'
```

Expected: FAIL，当前 header 指针会指向 decoded body buffer。

- [ ] **Step 3: 扩展 `HttpsResponseBuffers`**

增加：

```cpp
char* HeaderNameValueBuffer = nullptr;
SIZE_T HeaderNameValueBufferLength = 0;
```

`HttpsClient` H2 path 调用 `Http2Connection::SendRequest` 时将 `HeaderNameValueBuffer` 作为 `nameValueBuffer`，content decode 继续使用 `DecodedBodyBuffer`。

- [ ] **Step 4: 更新 sample IO buffers**

在 `src/KernelHttpTest/samples/HttpVerbSamples.cpp` 的 HTTPS IO buffer 结构中新增 header name/value 常驻成员，例如：

```cpp
char HeaderNameValue[Http2HeaderScratchBytes];
```

不要在请求函数栈上放大数组。

- [ ] **Step 5: 防止空缓冲静默复用**

H2 path 中如果 `HeaderNameValueBuffer == nullptr || HeaderNameValueBufferLength == 0`，返回 `STATUS_INVALID_PARAMETER` 并打印诊断；不要 fallback 到 `DecodedBodyBuffer`。

- [ ] **Step 6: 运行测试确认通过**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe; exit $LASTEXITCODE'
```

Expected: PASS。

## Chunk 5: LargePost 有界容量和 HTTP/2 Flow-Control

### Task 8: 修正 LargePost 样例容量边界

**Files:**
- Modify: `src/KernelHttpTest/samples/AdvancedScenarioSamples.cpp`
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: 写失败测试：LargePost 在足够 MaxResponseBytes 下成功**

在 `tests/high_level_api_tests.cpp` 增加公网等价 fake transport 响应，响应体大小覆盖 `LargeBodyBytes` 包装后的真实上界，例如 180 KiB。

```cpp
config.MaxResponseBytes = 256 * 1024;
Expect(NT_SUCCESS(status), "Advanced LargePost succeeds within bounded MaxResponseBytes");
```

- [ ] **Step 2: 写失败测试：低上限仍返回 BUFFER_TOO_SMALL**

```cpp
config.MaxResponseBytes = 64 * 1024;
Expect(status == STATUS_BUFFER_TOO_SMALL, "Advanced LargePost still fails when response exceeds MaxResponseBytes");
```

- [ ] **Step 3: 运行失败测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe; exit $LASTEXITCODE'
```

Expected: FAIL，当前样例上限不足或测试缺失。

- [ ] **Step 4: 设置明确的 LargePost 上限常量**

在 `AdvancedScenarioSamples.cpp` 增加：

```cpp
constexpr SIZE_T LargePostMaxResponseBytes = 256 * 1024;
```

并将高级场景 session 的 `MaxResponseBytes` 改为该常量或按 `LargeBodyBytes` 计算出的安全上界。不要设为无限；不要把 `STATUS_BUFFER_TOO_SMALL` 当公网诊断通过。

- [ ] **Step 5: 运行测试确认通过**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe; exit $LASTEXITCODE'
```

Expected: PASS。

### Task 9: 覆盖 HTTP/2 POST body 超过初始窗口 1 字节

**Files:**
- Modify: `tests/http2_client_tests.cpp`
- Modify: `src/KernelHttpLib/http2/Http2Connection.cpp`

- [ ] **Step 1: 写失败测试：POST body = 65536 bytes**

在 HTTP/2 fake transport 中模拟：

- client 发送 HEADERS。
- client 发送 65535 bytes DATA 后窗口耗尽。
- server 发送 connection-level `WINDOW_UPDATE` 和 stream-level `WINDOW_UPDATE`，顺序分别覆盖两种排列。
- client 发送最后 1 byte DATA + END_STREAM。
- server 返回 200。

断言：

```cpp
Expect(NT_SUCCESS(status), "HTTP/2 POST handles body larger than initial flow-control window");
```

- [ ] **Step 2: 运行失败测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe; exit $LASTEXITCODE'
```

Expected: 如果当前实现有 flow-control bug，应 FAIL；如果 PASS，保留测试防回归。

- [ ] **Step 3: 必要时修复 flow-control**

如果失败，修复 `Http2Connection::SendRequest`：

- `available <= 0` 时循环读取 frame 后同时正确处理 stream 和 connection `WINDOW_UPDATE`。
- 收到响应 HEADERS/DATA 过早到达时，不把合法响应帧当连接协议错误；若请求 body 尚未完整发送且 peer 提前响应，需要按 HTTP/2 语义决定是继续 drain/stop sending，不能用兜底。
- 保持所有 frame payload 缓冲使用 `Http2Connection` 常驻成员 `framePayload_`，不新增栈大数组。

- [ ] **Step 4: 增加诊断日志**

仅在失败路径打印：

```text
Http2Connection request body flow-control failed: status=... bodyOffset=... bodyLength=... connWindow=... streamWindow=...
```

不要打印 body 内容。

- [ ] **Step 5: 运行测试确认通过**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe; exit $LASTEXITCODE'
```

Expected: PASS。

## Chunk 6: End-To-End Verification

### Task 10: 运行相关 user-mode tests

**Files:**
- Inspect: `tests/*.cpp`
- Inspect: `tests/out/bin/*.exe`

- [ ] **Step 1: 运行 TLS/crypto tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_crypto_tests.exe; exit $LASTEXITCODE'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe; exit $LASTEXITCODE'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe; exit $LASTEXITCODE'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_interop_matrix_tests.exe; exit $LASTEXITCODE'
```

Expected: 全部 PASS。

- [ ] **Step 2: 运行 HTTP/2 和高层 API tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe; exit $LASTEXITCODE'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe; exit $LASTEXITCODE'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe; exit $LASTEXITCODE'
```

Expected: 全部 PASS。

- [ ] **Step 3: 运行 WebSocket tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe; exit $LASTEXITCODE'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_frame_tests.exe; exit $LASTEXITCODE'
```

Expected: 全部 PASS。

### Task 11: Debug/Release 构建

**Files:**
- Inspect: `KernelHttp.sln`
- Inspect: `tools/build-lib.ps1`

- [ ] **Step 1: Debug x64 构建**

Run:

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
```

Expected: 成功，0 warning，0 error。

- [ ] **Step 2: Release x64 构建**

Run:

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64
```

Expected: 成功，0 warning，0 error。

- [ ] **Step 3: Debug driver solution build**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '$ErrorActionPreference = "Stop"; $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"; $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath; if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsPath)) { throw "Visual Studio with VC tools was not found." }; $devShell = Join-Path $vsPath.Trim() "Common7\Tools\Launch-VsDevShell.ps1"; & $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; & msbuild.exe .\KernelHttp.sln /p:Configuration=Debug /p:Platform=x64 /m /nr:false; exit $LASTEXITCODE'
```

Expected: 成功，0 warning，0 error。

### Task 12: Live KernelHttpTest 验收

**Files:**
- Inspect: `src/KernelHttpTest/samples/*.cpp`

- [ ] **Step 1: 运行全量示例**

使用现有驱动加载流程运行 KernelHttpTest 全量场景。不要运行被项目禁止的 smoke 脚本。

Expected:

- `ws.postman-echo.com` 样例不再卡在 `parse ServerKeyExchange failed: 0xC00000BB ... sig=0x0201`。
- 若 endpoint 仍返回 SHA1，日志应显示显式兼容 TLS 策略已启用。
- `WebSocket Echo` / `ConnectEx` / 异步配置连接等 Postman WebSocket 样例返回成功，或在真实网络故障时输出明确网络状态，而不是模糊 `STATUS_NOT_SUPPORTED`。
- `ENCODING gzip/deflate/br` header 日志不再出现 JSON body 碎片；header name/value 与 body 各自正确。
- `HTTP LargePost` 不再返回 `STATUS_BUFFER_TOO_SMALL`，除非响应真实超过新的有界 `LargePostMaxResponseBytes`。
- IPv6 `STATUS_NO_MATCH` 仍按环境诊断处理；TrustFailure、ALPN mismatch 仍按负面样本预期处理。

## Acceptance Criteria

- TLS signature scheme capability 表覆盖当前实现可验证的 RSA/ECDSA SHA1 和既有 SHA2/PSS/EdDSA 项。
- SHA1 signature schemes 不进入 ModernDefault，不被默认 ClientHello offer。
- CompatibilityExplicit 也必须设置 `EnableTls12Sha1Signatures = true` 才允许 SHA1。
- `ws.postman-echo.com` TLS1.2 `ServerKeyExchange sig=0x0201` 能 parse、offer validate、verify，并完成 WebSocket HTTP/1.1 Upgrade。
- HTTPS HTTP/2 response headers 的 name/value 生命周期独立于 decoded body，日志不再被 body 覆盖。
- LargePost 使用有界响应容量成功；低于响应大小的 `MaxResponseBytes` 仍返回 `STATUS_BUFFER_TOO_SMALL`。
- 不新增 lib 栈大对象，不直接使用 `new/delete`，高频缓冲常驻或复用 workspace。
- 相关 user-mode tests、Debug x64 lib build、Release x64 lib build、Debug x64 solution build 通过且 0 warning。
