# TLS 1.2/1.3 Full Support Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将当前 TLS 1.2/1.3 现代客户端子集扩展为完整、可审计、可测试的 TLS 客户端协议栈，优先补齐 X25519，并系统补齐 TLS 1.2/1.3 的 cipher suite、named group、签名、客户端证书、resumption、revocation 和互通测试矩阵。

**Architecture:** 先建立 TLS 能力矩阵和安全策略层，再扩展内核 crypto provider、record layer、TLS 1.2/TLS 1.3 handshake 编排和证书/PKI 验证。完整实现与默认安全策略分离：协议实现层覆盖完整矩阵，默认策略只启用现代安全能力，旧式或弱安全 TLS 1.2 能力必须显式兼容模式启用。

**Tech Stack:** Windows kernel C++17 under `/kernel`, WSK transport, kernel CNG/BCrypt first, deterministic in-tree crypto only for CNG kernel path缺失的标准算法, TLS RFC 5246/8446, IANA TLS Parameters, OpenSSL/BoringSSL interop fixtures, existing user-mode protocol tests, Debug/Release x64/ARM64 builds with warnings as errors.

---

## Ground Rules

- 不引入 WinHTTP、WinINet、SChannel 作为内核主路径。
- 不把失败后重试、自动降级或“先跑起来”当作架构手段；所有能力选择必须来自显式 policy/capability matrix。
- 不使用 `new/delete`；库代码继续使用项目既有 `HeapObject<T>` / `HeapArray<T>` / nonpaged pool helper。
- 同步 TLS、证书、WSK I/O 路径保持 `PASSIVE_LEVEL` 约束。
- 本计划文档不提交 git；后续实现中的提交也只在用户明确要求时执行，并遵守项目 Conventional Commits 格式。
- 禁止运行项目已标记会卡住的 `tests/integration/https_smoke.ps1 -SkipDriverBuild` 命令。

## Execution Status

### 2026-06-10

- Chunk 1 Task 1/2 已完成：新增 TLS capability matrix、默认启用查询 API、显式 `TlsPolicy`，并将 policy 贯穿到 khttp、engine、direct client、TLS connection options 和连接池 key。
- 已同步项目文件和用户态测试编译清单：`TlsCapabilities.cpp` / `TlsPolicy.cpp` 已进入 `KernelHttpLib.vcxproj`、`.filters` 和相关测试 source list。
- 当前仓库还没有计划中的 `tests/tls_handshake_tests.cpp` / `tls_handshake_tests.exe`，本次 Chunk 1 测试落在既有 `tests/tls_record_tests.cpp` / `tls_record_tests.exe` 中，后续 Chunk 建立 handshake 测试二进制时再迁移或扩展。
- 已通过本地测试：`http_parser_tests.exe`、`websocket_frame_tests.exe`、`websocket_client_tests.exe`、`http2_frame_tests.exe`、`hpack_tests.exe`、`http2_client_tests.exe`、`tls_record_tests.exe`、`high_level_api_tests.exe`、`khttp_tests.exe`。
- 已通过构建：`pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64` 和 `pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64`，均为 0 warnings / 0 errors。
- 未运行 `tests/integration/https_smoke.ps1`，未执行 git commit。
- 本次从 Chunk 3 前复核 Chunk 2：Chunk 2 不能标记完成。Task 3 X25519 已有 RFC 7748 向量、raw key_share 和默认 offer 覆盖；Task 5 AEAD 已覆盖 ChaCha20-Poly1305、AES-CCM、AES-CCM_8；但 Task 4 X448/FFDHE 仍明确返回 `STATUS_NOT_SUPPORTED`，Task 6 只补了 `signature_algorithms_cert` ClientHello 扩展，完整签名算法验证矩阵仍未完成。
- Chunk 3 已推进 Task 7/8/10 的可独立子项：默认 TLS 1.3 ClientHello 提供 5 个 TLS 1.3 cipher suite，补 `signature_algorithms_cert`，保持 ServerHello/HRR offer 严格校验；新增 TLS 1.3 KeyUpdate 解析、post-handshake KeyUpdate 消费、application traffic secret update、exporter helper、显式发送 padding option，并保持 NewSessionTicket 消费；PSK/resumption/HRR binder、ticket SNI/ALPN/cipher/version/age 绑定和 0-RTT replay-safe opt-in 已有测试覆盖。
- Chunk 3 尚未完成：Task 7 仍缺完整 group 组合和本地互通矩阵，且 FFDHE 受 Chunk 2 Task 4 阻塞；Task 9 客户端证书/后握手认证仍未实现，`CertificateRequest` 仍返回 `STATUS_NOT_SUPPORTED`；Task 10 仍缺完整 PSK/0-RTT accept/reject 互通矩阵。
- 本次已通过用户态回归：`http_parser_tests.exe`、`websocket_frame_tests.exe`、`websocket_client_tests.exe`、`http2_frame_tests.exe`、`hpack_tests.exe`、`http2_client_tests.exe`、`tls_record_tests.exe`、`tls_crypto_tests.exe`、`tls_handshake_tests.exe`、`high_level_api_tests.exe`、`khttp_tests.exe`。
- 本次已通过构建：`pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64` 和 `pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64`，均为 0 warnings / 0 errors。
- 本次未运行禁止的 `tests/integration/https_smoke.ps1 -SkipDriverBuild`，未执行 git commit。
- 补充完成 Chunk 3 Task 8 padding 子项：`TlsPlaintextRecord::Tls13PaddingLength` 和 `TlsClientConnectionOptions::Tls13RecordPaddingLength` 均为显式 opt-in，默认 0；发送端按 padding 长度限制 TLS 1.3 application_data 分片，record layer 会拒绝超过 TLSInnerPlaintext 边界的 padding。
- 已重新编译并运行 `tls_record_tests.exe`（`/W4 /WX`），新增显式 padding 剥离和超界 padding 拒绝测试通过。

### 2026-06-11

- 本次从 Chunk 4 前复核 Chunk 3：Chunk 3 仍不能标记完成。`tests/tls_crypto_tests.cpp` 仍明确期望 X448/FFDHE 返回未支持状态，TLS 1.3 `CertificateRequest` 在连接路径仍返回 `STATUS_NOT_SUPPORTED`，post-handshake auth 和完整互通矩阵仍未补齐。
- Chunk 4 Task 11 Step 1/2 已完成：新增 TLS 1.2 cipher suite metadata 和矩阵测试，覆盖 ECDHE_RSA、ECDHE_ECDSA、DHE_RSA、RSA key exchange、AES-GCM、AES-CBC、ChaCha20-Poly1305 在 ModernDefault 与 CompatibilityExplicit policy 下的允许/拒绝语义。
- `TlsCipherSuiteCapability` 已扩展认证方式、record MAC、PRF hash 和 required extensions 元数据；TLS 1.2 PRF hash 选择已改为读取该元数据，避免后续 RSA/DHE 套件继续维护分散映射。
- 本次只完成 Chunk 4 的基础矩阵层；Task 11 Step 3/4/5 仍未完成，RSA key exchange、DHE_RSA/FFDHE 握手路径、AES-CBC constant-time MAC/encrypt-then-MAC record path 仍待实现。
- 已重新编译并运行用户态测试：`tls_handshake_tests.exe`、`tls_record_tests.exe`，均使用 `/W4 /WX`，结果 PASS。
- 已通过构建：`pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64` 和 `pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64`，均为 0 warnings / 0 errors。
- 本次未运行禁止的 `tests/integration/https_smoke.ps1 -SkipDriverBuild`，未执行 git commit。
- 本次继续推进 Chunk 2/3/4 的阻塞项：X448 已按 RFC 7748 向量实现 raw key share；FFDHE2048/3072/4096/6144/8192 已实现 RFC 7919 参数、短指数生成、有限域公钥范围校验、共享密钥派生和参数识别；TLS 1.3 supported_groups/default HRR 路径已覆盖 X448/FFDHE，key_share 和 scratch 上限已扩到 FFDHE8192；0-RTT 未被接受时改为继续 1-RTT；TLS 1.3 握手期 CertificateRequest 已支持无客户端凭据时发送空 Certificate。
- Chunk 4 继续推进 DHE_RSA：TLS 1.2 ClientHello 默认补入 DHE_RSA AEAD 套件和 FFDHE groups；ServerKeyExchange 已能解析并校验 RFC 7919 DHE 参数，连接路径已能生成 FFDHE ClientKeyExchange 并派生 premaster secret。
- 本次新增/更新测试并通过：`tls_crypto_tests.exe`（X448 RFC 7748、FFDHE key agreement、FFDHE 参数识别）、`tls_handshake_tests.exe`（TLS 1.3 X448/FFDHE groups、HRR FFDHE、空客户端 Certificate）、`tls_record_tests.exe`。
- 本次已通过构建：`pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64` 和 `pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64`，均为 0 warnings / 0 errors。
- 本次未运行禁止的 `tests/integration/https_smoke.ps1 -SkipDriverBuild`，未执行 git commit。
- 本轮最终补齐 Chunk 2 Task 6：TLS signature scheme 映射覆盖 RSA-PKCS1 SHA256/384/512、RSA-PSS-RSAE/PSS SHA256/384/512、ECDSA P-256/P-384/P-521、Ed25519、Ed448；TLS 1.2/1.3 默认 ClientHello 均补 SHA512/EdDSA 覆盖，TLS 1.3 同步发送 `signature_algorithms_cert`，连接层在证书验证和客户端凭据选择前校验签名 scheme 与公钥/私钥算法兼容。
- 本轮最终补齐 Chunk 3 Task 7/8/9/10：ClientHello 由 policy/capability 构造 TLS 1.3 cipher/group/key_share/signature/cert-signature offers；KeyUpdate、exporter、record padding 保持测试覆盖；握手期和 post-handshake `CertificateRequest` 均能按显式 policy 与客户端凭据发送 Certificate/CertificateVerify，无匹配凭据时发送空 Certificate；TLS 1.3 ticket 存储绑定 issue time、age_add、cipher、SNI、ALPN、policy identity 和 early_data 大小，HRR 后重算 binder，0-RTT 仅在 replay-safe opt-in 且票据允许时发送，未接受时继续 1-RTT。
- 本轮最终补齐 Chunk 4 Task 11/12/13：TLS 1.2 RSA key exchange 使用 `{3,3}+46 random` premaster 并走 RSAES-PKCS1-v1_5 加密；CBC record path 使用 encrypt-then-MAC、严格 MAC/padding 校验且失败不推进序号；TLS 1.2 session ID/RFC 5077 ticket cache 绑定 SNI、ALPN、cipher、policy identity 和版本；secure renegotiation indication 严格校验，client-initiated renegotiation 默认不作为主路径；TLS 1.2 客户端证书复用客户端凭据模型并支持 CertificateVerify；`status_request` 默认发送并支持 CertificateStatus/OCSP staple 解析与握手消费，强撤销验证仍由后续 PKI/revocation chunk 承接，当前策略要求撤销检查时保持明确 `STATUS_NOT_SUPPORTED`。
- 本轮新增/更新测试并通过：`tls_handshake_tests.exe`（TLS 1.2/1.3 签名 scheme offer、TLS 1.3 Certificate/CertificateVerify/EndOfEarlyData、TLS 1.2 full matrix）、`tls_record_tests.exe`（AES-CBC EtM roundtrip/MAC/padding 篡改、TLS 1.2 session cache ClientHello、TLS 1.2 CertificateStatus parser、TLS 1.3 exporter/KeyUpdate/padding/PSK/HRR/early_data）、`tls_crypto_tests.exe`。
- 本轮已通过最终验证：`pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_crypto_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\tls_handshake_tests.exe; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & .\tests\out\bin\tls_record_tests.exe; exit $LASTEXITCODE'`；`pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64`，0 warnings / 0 errors。
- 本轮未运行禁止的 `tests/integration/https_smoke.ps1 -SkipDriverBuild`，未执行 git commit。
- 本轮从 Chunk 5 开始并补齐 Task 14/15：证书验证路径支持无序链重排、leaf-to-anchor path building、serial 解析、Name Constraints、certificatePolicies/anyPolicy/policyConstraints/inhibitAnyPolicy 基础处理、BasicConstraints/KeyUsage/EKU/SAN/CN 组合校验；证书存储支持外部传入的 OCSP/CRL 撤销缓存条目，验证策略覆盖 `Off`、`StapledOnly`、`OnlineRequired`，强撤销判定由调用侧传入的新鲜撤销条目驱动，TLS 1.2 `CertificateStatus` 保持可解析且不再硬失败；URL parser 与证书 dNSName 匹配支持 UTF-8 U-label 到 Punycode A-label 的 IDNA 规范化。
- 本轮新增测试证书 fixture：`tests/testdata/pki/root.cert.pem`、`intermediate.cert.pem`、`leaf.cert.pem`、`bad-leaf.cert.pem`、`idna-leaf.cert.pem`；未保留私钥、`.srl` 或 `.cnf` 临时文件。
- 外部 CA bundle 仍由调用侧以文件路径或已加载 PEM bundle 传入；库层没有硬编码 `E:\work\kernel_http\certs\cacert.pem`，测试仅覆盖从外部路径加载。
- 本轮新增/更新测试并通过：`tls_record_tests.exe`、`tls_handshake_tests.exe`、`khttp_tests.exe`、`high_level_api_tests.exe`。
- 本轮已通过构建：`pwsh -NoLogo -NoProfile -Command '& .\tools\build-lib.ps1 -Configuration Debug -Platform x64'` 和 `pwsh -NoLogo -NoProfile -Command '& .\tools\build-lib.ps1 -Configuration Release -Platform x64'`，均为 0 warnings / 0 errors。
- 本轮未运行禁止的 `tests/integration/https_smoke.ps1 -SkipDriverBuild`，未执行 git commit。
- 本轮完成 Chunk 6 Task 16/17：新增 `tests/tls_interop_matrix_tests.cpp` 和 `tests/integration/tls_matrix.ps1`，覆盖 TLS 1.3 cipher/group、TLS 1.2 key exchange/cipher、ALPN/SNI、客户端证书、resumption/0-RTT/KeyUpdate/renegotiation policy 的本地矩阵；同步登记到 `KernelHttpTest.vcxproj` / `.filters`，并把 `https_smoke.ps1` 的主机回归编译清单补入 interop matrix 测试。
- 本轮完成公开文档更新：`README.md`、`README_en.md`、`docs/api-overview.md`、`docs/high-level-api.md`、`docs/low-level-api.md`、`docs/ntstatus-codes.md` 已从“TLS 子集”表述更新为 TLS 1.2/1.3 能力矩阵、默认安全策略、兼容能力显式 opt-in、证书/撤销/IDNA 能力和 NTSTATUS 分类。
- 本轮 Chunk 6 验证已通过全部用户态协议测试：`http_parser_tests.exe`、`websocket_frame_tests.exe`、`websocket_client_tests.exe`、`http2_frame_tests.exe`、`hpack_tests.exe`、`http2_client_tests.exe`、`tls_record_tests.exe`、`tls_crypto_tests.exe`、`tls_handshake_tests.exe`、`tls_interop_matrix_tests.exe`、`high_level_api_tests.exe`、`khttp_tests.exe`。
- 本轮本地 TLS 矩阵已通过：`pwsh -NoLogo -NoProfile -File .\tests\integration\tls_matrix.ps1 -Configuration Debug -Platform x64`，结果 `pass=14 skip=4`；SKIP 项均为本地 OpenSSL CLI 能力或非交互 harness 限制，并由项目矩阵二进制覆盖对应策略语义。
- 本轮最终构建已通过：`pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64` 和 `pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64`，均为 0 warnings / 0 errors。
- 本轮未运行可选 ARM64 构建，未运行禁止的 `tests/integration/https_smoke.ps1 -SkipDriverBuild`，未执行 git commit。

## Definition of Complete Support

完整支持不等于默认启用所有历史弱算法。完整支持在本项目中定义为：

- TLS 1.3 覆盖 RFC 8446 客户端语义：全部 TLS 1.3 cipher suite、supported_versions、key_share、supported_groups、signature_algorithms、signature_algorithms_cert、PSK/resumption、0-RTT、HRR、KeyUpdate、post-handshake authentication、NewSessionTicket、exporter、record padding、alert/close_notify。
- TLS 1.2 覆盖 RFC 5246 及现代互通必需扩展：SNI、ALPN、secure renegotiation、extended master secret、encrypt-then-MAC、session ID、session ticket、ECDHE/DHE/RSA key exchange、AES-GCM、AES-CBC、ChaCha20-Poly1305、FFDHE、X25519/X448、客户端证书、OCSP stapling。
- PKI 覆盖证书链构建、Name Constraints、policy tree、EKU/KeyUsage/BasicConstraints、SAN/CN、IDNA、OCSP/CRL revocation、SPKI pin、外部 trust anchor。
- 默认策略遵循现代安全建议：TLS 1.3 + ECDHE/DHE PFS + AEAD 默认启用；TLS 1.2 RSA key exchange、CBC、renegotiation 等兼容能力默认关闭，只能由调用方显式启用。

## File Structure

### Create

- `include/KernelHttp/tls/TlsCapabilities.h`: TLS cipher/group/signature/extension 能力矩阵与查询 API。
- `src/KernelHttpLib/tls/TlsCapabilities.cpp`: 静态能力表、默认策略过滤、兼容策略过滤。
- `include/KernelHttp/tls/TlsPolicy.h`: 安全策略结构，区分默认安全 profile 与兼容 profile。
- `src/KernelHttpLib/tls/TlsPolicy.cpp`: policy validation、offer ordering、legacy opt-in 判断。
- `include/KernelHttp/crypto/KeyExchange.h`: X25519/X448/NIST P curve/FFDHE 统一 key exchange facade。
- `src/KernelHttpLib/crypto/KeyExchange.cpp`: CNG-backed key exchange，必要时承载经测试的内核可用标准算法实现。
- `include/KernelHttp/crypto/Aead.h`: AES-GCM/AES-CCM/ChaCha20-Poly1305 统一 AEAD facade。
- `src/KernelHttpLib/crypto/Aead.cpp`: AEAD provider selection 与常量时间 tag 校验。
- `tests/tls_crypto_tests.cpp`: X25519、X448、FFDHE、AEAD、signature algorithm 向量测试。
- `tests/tls_handshake_tests.cpp`: ClientHello/ServerHello/HRR/CertificateRequest/KeyUpdate/renegotiation 编码解析测试。
- `tests/tls_interop_matrix_tests.cpp`: 本地 OpenSSL/BoringSSL 矩阵互通测试入口。
- `tests/integration/tls_matrix.ps1`: 启动本地 TLS server 矩阵并执行确定性互通测试，不做公网烟测。

### Modify

- `include/KernelHttp/crypto/CngProvider.h`
- `src/KernelHttpLib/crypto/CngProvider.cpp`
- `include/KernelHttp/crypto/CngProviderCache.h`
- `src/KernelHttpLib/crypto/CngProviderCache.cpp`
- `include/KernelHttp/tls/TlsContext.h`
- `src/KernelHttpLib/tls/TlsContext.cpp`
- `include/KernelHttp/tls/TlsRecord.h`
- `src/KernelHttpLib/tls/TlsRecord.cpp`
- `include/KernelHttp/tls/TlsHandshake12.h`
- `src/KernelHttpLib/tls/TlsHandshake12.cpp`
- `include/KernelHttp/tls/TlsHandshake13.h`
- `src/KernelHttpLib/tls/TlsHandshake13.cpp`
- `include/KernelHttp/tls/TlsConnection.h`
- `src/KernelHttpLib/tls/TlsConnection.cpp`
- `include/KernelHttp/tls/CertificateValidator.h`
- `src/KernelHttpLib/tls/CertificateValidator.cpp`
- `include/KernelHttp/tls/CertificateStore.h`
- `src/KernelHttpLib/tls/CertificateStore.cpp`
- `include/KernelHttp/khttp/Types.h`
- `include/KernelHttp/engine/Engine.h`
- `src/KernelHttpLib/engine/HttpEngine.cpp`
- `src/KernelHttpLib/client/HttpsClient.cpp`
- `src/KernelHttpLib/client/Http2Client.cpp`
- `src/KernelHttpLib/client/WebSocketClient.cpp`
- `src/KernelHttpLib/KernelHttpLib.vcxproj`
- `src/KernelHttpLib/KernelHttpLib.vcxproj.filters`
- `src/KernelHttpTest/KernelHttpTest.vcxproj`
- `README.md`
- `README_en.md`
- `docs/api-overview.md`
- `docs/high-level-api.md`
- `docs/low-level-api.md`

## Chunk 1: Capability Matrix and TLS Policy

### Task 1: Add TLS capability matrix

**Files:**
- Create: `include/KernelHttp/tls/TlsCapabilities.h`
- Create: `src/KernelHttpLib/tls/TlsCapabilities.cpp`
- Modify: `include/KernelHttp/tls/TlsContext.h`
- Modify: `src/KernelHttpLib/KernelHttpLib.vcxproj`
- Test: `tests/tls_record_tests.cpp` for current Chunk 1 coverage; `tests/tls_handshake_tests.cpp` remains a later planned test binary.

- [x] **Step 1: Write failing matrix tests**

Add tests that assert the matrix contains at least:

```cpp
CHECK(TlsIsKnownNamedGroup(TlsNamedGroup::X25519));
CHECK(TlsIsKnownCipherSuite(TlsCipherSuite::TlsChaCha20Poly1305Sha256));
CHECK(TlsIsKnownSignatureScheme(TlsSignatureScheme::Ed25519));
CHECK(TlsIsDefaultEnabledNamedGroup(TlsNamedGroup::X25519));
CHECK(!TlsIsDefaultEnabledTls12KeyExchange(Tls12KeyExchangeKind::Rsa));
```

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: FAIL because the test binary or symbols do not exist yet.

- [x] **Step 2: Extend public TLS enums**

Add enum values without changing existing numeric values:

```cpp
enum class TlsNamedGroup : USHORT
{
    Secp256r1 = 23,
    Secp384r1 = 24,
    Secp521r1 = 25,
    X25519 = 29,
    X448 = 30,
    Ffdhe2048 = 256,
    Ffdhe3072 = 257,
    Ffdhe4096 = 258,
    Ffdhe6144 = 259,
    Ffdhe8192 = 260
};
```

Add TLS 1.3 cipher suites:

```cpp
TlsChaCha20Poly1305Sha256 = 0x1303,
TlsAes128CcmSha256 = 0x1304,
TlsAes128Ccm8Sha256 = 0x1305
```

Add missing signature schemes:

```cpp
RsaPssPssSha256 = 0x0809,
RsaPssPssSha384 = 0x080a,
RsaPssPssSha512 = 0x080b,
EcdsaSecp521r1Sha512 = 0x0603,
Ed25519 = 0x0807,
Ed448 = 0x0808
```

- [x] **Step 3: Implement matrix API**

Create constexpr/static tables for:

- TLS version support.
- Cipher suites by TLS version.
- Named groups by key exchange family.
- Signature schemes by certificate/key type.
- Extensions and whether they are default, optional, legacy, or unsupported.

- [x] **Step 4: Wire project files**

Add created files to `src/KernelHttpLib/KernelHttpLib.vcxproj` and `.filters`.

- [x] **Step 5: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: PASS for matrix tests after the test binary is built by the normal test build.

Actual 2026-06-10: `tls_handshake_tests.exe` has not been created yet, so Chunk 1 matrix coverage was added to and verified by `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`.

### Task 2: Add explicit TLS policy

**Files:**
- Create: `include/KernelHttp/tls/TlsPolicy.h`
- Create: `src/KernelHttpLib/tls/TlsPolicy.cpp`
- Modify: `include/KernelHttp/tls/TlsConnection.h`
- Modify: `include/KernelHttp/khttp/Types.h`
- Modify: `include/KernelHttp/engine/Engine.h`
- Test: `tests/tls_record_tests.cpp` for current Chunk 1 coverage; `tests/tls_handshake_tests.cpp` remains a later planned test binary.

- [x] **Step 1: Write failing policy tests**

Test that default policy offers X25519 and AEAD suites, but does not offer TLS 1.2 RSA key exchange, CBC, or renegotiation.

- [x] **Step 2: Define policy structures**

Add a small, explicit policy model:

```cpp
enum class TlsSecurityProfile : UCHAR
{
    ModernDefault,
    CompatibilityExplicit
};

struct TlsPolicy final
{
    TlsSecurityProfile Profile = TlsSecurityProfile::ModernDefault;
    bool EnableTls12RsaKeyExchange = false;
    bool EnableTls12Cbc = false;
    bool EnableTls12Renegotiation = false;
    bool EnablePostHandshakeClientAuth = false;
    bool RequireRevocationCheck = false;
};
```

- [x] **Step 3: Validate options**

Reject contradictory policy, such as `ModernDefault` with legacy flags enabled. Compatibility flags must be deliberate and visible in connection options.

- [x] **Step 4: Thread policy through API layers**

Propagate from khttp/engine options into `TlsClientConnectionOptions` without changing existing defaults.

- [x] **Step 5: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: PASS for policy filtering.

Actual 2026-06-10: `tls_handshake_tests.exe` has not been created yet, so Chunk 1 policy coverage was added to and verified by `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`.

## Chunk 2: Crypto Substrate

### Task 3: Implement X25519 first

**Files:**
- Create: `include/KernelHttp/crypto/KeyExchange.h`
- Create: `src/KernelHttpLib/crypto/KeyExchange.cpp`
- Modify: `include/KernelHttp/crypto/CngProvider.h`
- Modify: `src/KernelHttpLib/crypto/CngProvider.cpp`
- Modify: `include/KernelHttp/crypto/CngProviderCache.h`
- Modify: `src/KernelHttpLib/crypto/CngProviderCache.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake13.cpp`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Test: `tests/tls_crypto_tests.cpp`
- Test: `tests/tls_handshake_tests.cpp`

- [x] **Step 1: Write RFC 7748 vector tests**

Add X25519 public key and shared secret vectors. Expected: FAIL before implementation.

- [x] **Step 2: Add key exchange facade**

Model raw key-share groups separately from NIST EC point groups:

```cpp
enum class KeyExchangeGroup : USHORT
{
    Secp256r1 = 23,
    Secp384r1 = 24,
    Secp521r1 = 25,
    X25519 = 29,
    X448 = 30
};
```

- [x] **Step 3: Implement CNG-backed X25519 where available**

Use CNG named curve capability probing during provider initialization. Selection is deterministic by group and capability, not failure-driven retry.

- [x] **Step 4: Encode TLS key_share correctly**

For X25519, send raw 32-byte public keys. Do not wrap it as an uncompressed EC point.

- [x] **Step 5: Change TLS 1.3 default offer order**

Offer default groups:

```text
X25519, secp256r1, secp384r1, secp521r1
```

Keep HRR support for server-selected group regeneration.

- [x] **Step 6: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_crypto_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: PASS for X25519 vectors, ClientHello offer order, HRR retry group handling.

### Task 4: Add X448 and FFDHE

**Files:**
- Modify: `include/KernelHttp/crypto/KeyExchange.h`
- Modify: `src/KernelHttpLib/crypto/KeyExchange.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake12.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake13.cpp`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Test: `tests/tls_crypto_tests.cpp`
- Test: `tests/tls_handshake_tests.cpp`

- [x] **Step 1: Add failing X448 and FFDHE tests**

Cover X448 vector, FFDHE public key validation, and rejection of invalid finite-field public values.

- [x] **Step 2: Implement X448 raw key shares**

Use raw 56-byte key_share encoding.

- [x] **Step 3: Implement FFDHE groups**

Add ffdhe2048/3072/4096/6144/8192 with static group parameters in nonpaged constant data. Validate peer public key range before secret derivation.

- [x] **Step 4: Wire TLS 1.2 DHE and TLS 1.3 FFDHE paths**

TLS 1.2 uses ServerKeyExchange DHE params; TLS 1.3 uses key_share group.

- [x] **Step 5: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_crypto_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: PASS.

### Task 5: Add AEAD coverage

**Files:**
- Create: `include/KernelHttp/crypto/Aead.h`
- Create: `src/KernelHttpLib/crypto/Aead.cpp`
- Modify: `include/KernelHttp/tls/TlsRecord.h`
- Modify: `src/KernelHttpLib/tls/TlsRecord.cpp`
- Modify: `src/KernelHttpLib/tls/TlsContext.cpp`
- Test: `tests/tls_crypto_tests.cpp`
- Test: `tests/tls_record_tests.cpp`

- [x] **Step 1: Add failing AEAD vector tests**

Cover ChaCha20-Poly1305, AES-CCM, and AES-CCM_8 known-answer vectors.

- [x] **Step 2: Introduce AEAD abstraction**

Move TLS record protection from AES-GCM-only helpers to an algorithm-tagged AEAD path while preserving existing AES-GCM tests.

- [x] **Step 3: Implement ChaCha20-Poly1305**

Prefer kernel CNG if available; otherwise use a reviewed in-tree constant-time implementation with RFC test vectors. The provider is chosen by capability matrix at initialization, not as an error fallback.

- [x] **Step 4: Implement AES-CCM and AES-CCM_8**

Add tag length handling and TLS 1.3 nonce construction.

- [x] **Step 5: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_crypto_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'
```

Expected: PASS for all AEAD variants and existing AES-GCM regression tests.

### Task 6: Add signature algorithm coverage

**Files:**
- Modify: `include/KernelHttp/crypto/CngProvider.h`
- Modify: `src/KernelHttpLib/crypto/CngProvider.cpp`
- Modify: `include/KernelHttp/tls/TlsHandshake12.h`
- Modify: `include/KernelHttp/tls/TlsHandshake13.h`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `src/KernelHttpLib/tls/CertificateValidator.cpp`
- Test: `tests/tls_crypto_tests.cpp`
- Test: `tests/tls_handshake_tests.cpp`

- [x] **Step 1: Add failing tests**

Cover RSA-PSS-PSS, RSA-PSS-RSAE SHA512, ECDSA P-521 SHA512, Ed25519, and Ed448 certificate/key verification paths.

- [x] **Step 2: Extend signature enum mapping**

Map TLS signature schemes to CNG or in-tree verified algorithms.

- [x] **Step 3: Implement `signature_algorithms_cert`**

TLS 1.3 must distinguish handshake signature schemes from certificate signature schemes.

- [x] **Step 4: Verify certificate public key compatibility**

Reject mismatched signature scheme and key type before calling provider verification.

- [x] **Step 5: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_crypto_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: PASS.

## Chunk 3: TLS 1.3 Full Support

### Task 7: Complete TLS 1.3 cipher/group negotiation

**Files:**
- Modify: `src/KernelHttpLib/tls/TlsHandshake13.cpp`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `src/KernelHttpLib/tls/TlsContext.cpp`
- Test: `tests/tls_handshake_tests.cpp`
- Test: `tests/tls_interop_matrix_tests.cpp`

- [x] **Step 1: Add failing negotiation tests**

Cover all TLS 1.3 cipher suites and selected group combinations, including HRR from X25519 to P-256 and X25519 to FFDHE.

- [x] **Step 2: Extend ClientHello**

Use `TlsPolicy` and `TlsCapabilities` to construct cipher suites, named groups, key shares, signature schemes, and certificate signature schemes.

- [x] **Step 3: Validate ServerHello strictly**

Reject cipher/group/signature selections not offered by the client or disallowed by policy.

- [x] **Step 4: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: PASS.

### Task 8: Implement TLS 1.3 KeyUpdate, exporter, and record padding

**Files:**
- Modify: `include/KernelHttp/tls/TlsConnection.h`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `src/KernelHttpLib/tls/TlsContext.cpp`
- Modify: `src/KernelHttpLib/tls/TlsRecord.cpp`
- Test: `tests/tls_record_tests.cpp`
- Test: `tests/tls_handshake_tests.cpp`

- [x] **Step 1: Add failing tests**

Cover inbound KeyUpdate, outbound requested KeyUpdate, exporter labels, and padded TLSInnerPlaintext.

- [x] **Step 2: Add traffic secret update API**

Implement TLS 1.3 application traffic secret update and sequence reset.

- [x] **Step 3: Add exporter API internally**

Expose only if needed by callers; otherwise keep internal tested helper.

- [x] **Step 4: Add padding support**

Decrypt and strip padding; allow sending configured padding length only through explicit option.

- [x] **Step 5: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: PASS.

### Task 9: Complete TLS 1.3 client certificate and post-handshake auth

**Files:**
- Modify: `include/KernelHttp/tls/TlsConnection.h`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `include/KernelHttp/tls/CertificateStore.h`
- Modify: `src/KernelHttpLib/tls/CertificateStore.cpp`
- Modify: `include/KernelHttp/khttp/Types.h`
- Modify: `include/KernelHttp/engine/Engine.h`
- Test: `tests/tls_handshake_tests.cpp`
- Test: `tests/tls_interop_matrix_tests.cpp`

- [x] **Step 1: Add failing CertificateRequest tests**

Cover server requesting client certificate during handshake and post-handshake.

- [x] **Step 2: Add client credential model**

Certificate selection must include certificate chain, private key provider handle, supported schemes, and usage constraints.

- [x] **Step 3: Implement Certificate and CertificateVerify send path**

Use the selected private key provider and transcript hash. If no matching certificate exists and request is optional, send empty Certificate.

- [x] **Step 4: Implement post-handshake authentication**

Only enabled when policy explicitly allows it. Unexpected post-handshake CertificateRequest remains a protocol error.

- [x] **Step 5: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: PASS.

### Task 10: Complete TLS 1.3 PSK, resumption, and 0-RTT

**Files:**
- Modify: `include/KernelHttp/tls/TlsContext.h`
- Modify: `src/KernelHttpLib/tls/TlsContext.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake13.cpp`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Test: `tests/tls_handshake_tests.cpp`
- Test: `tests/tls_interop_matrix_tests.cpp`

- [x] **Step 1: Add failing resumption matrix tests**

Cover PSK-only rejection when policy requires PFS, PSK-DHE acceptance, binder mismatch rejection, ticket age validation, SNI/ALPN/cipher/version binding, and early data accept/reject.

- [x] **Step 2: Harden ticket storage**

Persist ticket metadata with issue time, age add, cipher suite, protocol version, SNI, ALPN, policy identity, and early data size.

- [x] **Step 3: Implement full binder recomputation**

Cover first ClientHello and HRR second ClientHello.

- [x] **Step 4: Implement 0-RTT state machine**

0-RTT remains opt-in and requires replay-safe request classification. Rejection must continue as 1-RTT without losing connection state.

- [x] **Step 5: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: PASS.

## Chunk 4: TLS 1.2 Full Support

### Task 11: Complete TLS 1.2 cipher suite and key exchange matrix

**Files:**
- Modify: `include/KernelHttp/tls/TlsContext.h`
- Modify: `src/KernelHttpLib/tls/TlsContext.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake12.cpp`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Test: `tests/tls_handshake_tests.cpp`
- Test: `tests/tls_interop_matrix_tests.cpp`

- [x] **Step 1: Add failing TLS 1.2 matrix tests**

Cover ECDHE_RSA, ECDHE_ECDSA, DHE_RSA, RSA key exchange, AES-GCM, AES-CBC, and ChaCha20-Poly1305 under ModernDefault and CompatibilityExplicit profiles.

- [x] **Step 2: Add suite metadata**

Each TLS 1.2 suite must declare key exchange, authentication, bulk cipher, MAC, PRF hash, default policy status, and required extensions.

- [x] **Step 3: Implement RSA key exchange**

Only under explicit compatibility policy. Validate server certificate key usage and encrypt premaster secret correctly.

- [x] **Step 4: Implement DHE_RSA**

Use validated FFDHE params. Reject weak or unknown DH params unless compatibility policy explicitly allows legacy custom DH.

- [x] **Step 5: Implement CBC with constant-time MAC handling**

Support AES-CBC only with strict padding/MAC checks. Prefer encrypt-then-MAC when negotiated.

- [x] **Step 6: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: PASS.

### Task 12: Implement TLS 1.2 session resumption and secure renegotiation

**Files:**
- Modify: `include/KernelHttp/tls/TlsContext.h`
- Modify: `src/KernelHttpLib/tls/TlsContext.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake12.cpp`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Test: `tests/tls_handshake_tests.cpp`

- [x] **Step 1: Add failing tests**

Cover session ID resumption, RFC 5077 tickets, secure renegotiation info, renegotiation disabled by default, and client-initiated renegotiation only under compatibility policy.

- [x] **Step 2: Add TLS 1.2 session cache**

Bind sessions to SNI, ALPN, cipher suite, certificate policy, trust store, and protocol version.

- [x] **Step 3: Implement secure renegotiation**

Verify renegotiation_info contents. Reject insecure renegotiation.

- [x] **Step 4: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: PASS.

### Task 13: Implement TLS 1.2 client certificates and OCSP stapling

**Files:**
- Modify: `src/KernelHttpLib/tls/TlsHandshake12.cpp`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `include/KernelHttp/tls/CertificateStore.h`
- Modify: `src/KernelHttpLib/tls/CertificateStore.cpp`
- Test: `tests/tls_handshake_tests.cpp`
- Test: `tests/tls_interop_matrix_tests.cpp`

- [x] **Step 1: Add failing tests**

Cover TLS 1.2 CertificateRequest selection, CertificateVerify signing, empty certificate for optional request, and OCSP stapled response parsing.

- [x] **Step 2: Implement client certificate send path**

Reuse the credential model from TLS 1.3.

- [x] **Step 3: Implement status_request**

Parse and validate OCSP stapled responses when revocation policy requires stapling.

- [x] **Step 4: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: PASS.

## Chunk 5: PKI and Certificate Completeness

### Task 14: Complete X.509 path validation

**Files:**
- Modify: `include/KernelHttp/tls/CertificateValidator.h`
- Modify: `src/KernelHttpLib/tls/CertificateValidator.cpp`
- Modify: `include/KernelHttp/tls/CertificateStore.h`
- Modify: `src/KernelHttpLib/tls/CertificateStore.cpp`
- Test: `tests/khttp_tests.cpp`
- Test: `tests/tls_handshake_tests.cpp`

- [x] **Step 1: Add failing certificate tests**

Cover Name Constraints, policy tree, pathLen, self-issued handling, EKU inheritance, KeyUsage, trust anchor constraints, and unknown critical extensions.

- [x] **Step 2: Implement Name Constraints**

Support DNS, IP, directoryName where represented by current parser; reject unsupported critical forms clearly.

- [x] **Step 3: Implement certificate policy tree**

Support policy OID matching, anyPolicy handling, inhibit/require explicit policy constraints.

- [x] **Step 4: Harden path building**

Do not assume input chain order. Build from leaf to trust anchor using available intermediates and trust store.

- [x] **Step 5: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
```

Expected: PASS.

### Task 15: Implement revocation and IDNA

**Files:**
- Modify: `include/KernelHttp/tls/CertificateValidator.h`
- Modify: `src/KernelHttpLib/tls/CertificateValidator.cpp`
- Modify: `include/KernelHttp/tls/CertificateStore.h`
- Modify: `src/KernelHttpLib/tls/CertificateStore.cpp`
- Modify: `include/KernelHttp/engine/UrlParser.h`
- Modify: `src/KernelHttpLib/engine/UrlParser.cpp`
- Test: `tests/khttp_tests.cpp`
- Test: `tests/high_level_api_tests.cpp`

- [x] **Step 1: Add failing tests**

Cover OCSP good/revoked/unknown, CRL good/revoked/expired, cache expiry, IDNA A-label/U-label matching, and non-ASCII host rejection when IDNA policy is disabled.

- [x] **Step 2: Implement revocation policy**

Support `Off`, `StapledOnly`, and `OnlineRequired`. Online fetching must use bounded WSK/HTTP paths and must avoid recursive trust ambiguity.

- [x] **Step 3: Implement OCSP/CRL cache**

Cache by issuer, serial, thisUpdate/nextUpdate, and responder identity.

- [x] **Step 4: Implement IDNA processing**

Normalize hostnames before SNI and certificate dNSName matching. Keep exact IP literal SAN behavior.

- [x] **Step 5: Run tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'
```

Expected: PASS.

## Chunk 6: Integration and Documentation

### Task 16: Add local TLS interop matrix

**Files:**
- Create: `tests/tls_interop_matrix_tests.cpp`
- Create: `tests/integration/tls_matrix.ps1`
- Modify: `src/KernelHttpTest/KernelHttpTest.vcxproj`
- Modify: `src/KernelHttpTest/KernelHttpTest.vcxproj.filters`

- [x] **Step 1: Add failing harness test**

Add test entries for local TLS 1.2 and TLS 1.3 servers. Initial expected result: FAIL because the harness does not exist.

- [x] **Step 2: Implement local server launcher**

Use OpenSSL/BoringSSL executables discovered from environment or a configured path. Do not contact public endpoints.

- [x] **Step 3: Cover matrix**

At minimum cover:

- TLS 1.3: AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, AES_128_CCM, AES_128_CCM_8.
- TLS 1.3 groups: X25519, X448, P-256, P-384, P-521, FFDHE.
- TLS 1.2: ECDHE_RSA, ECDHE_ECDSA, DHE_RSA, RSA key exchange, AES-GCM, AES-CBC, ChaCha20-Poly1305.
- ALPN h2/http/1.1, SNI, client cert, resumption, 0-RTT, KeyUpdate, renegotiation policy.

- [x] **Step 4: Run local integration**

Run:

```powershell
pwsh -NoLogo -NoProfile -File .\tests\integration\tls_matrix.ps1 -Configuration Debug -Platform x64
```

Expected: PASS on machines with configured local OpenSSL/BoringSSL; SKIP with explicit reason if tooling is absent.

### Task 17: Update public documentation

**Files:**
- Modify: `README.md`
- Modify: `README_en.md`
- Modify: `docs/api-overview.md`
- Modify: `docs/high-level-api.md`
- Modify: `docs/low-level-api.md`
- Modify: `docs/ntstatus-codes.md`

- [x] **Step 1: Document capability matrix**

Replace “TLS 子集” wording with precise capability tables after implementation lands.

- [x] **Step 2: Document policy defaults**

Make clear that legacy TLS 1.2 compatibility features exist but are disabled by default.

- [x] **Step 3: Document NTSTATUS mapping**

Add distinct errors for policy disabled, unsupported local provider, peer alert, revocation failure, and certificate policy failure.

- [x] **Step 4: Review docs for overclaiming**

Ensure docs say exactly what is implemented and tested.

### Task 18: Final verification

**Files:**
- No source edits expected unless failures require fixes.

- [x] **Step 1: Run all user-mode protocol tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_frame_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_frame_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\hpack_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_crypto_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_interop_matrix_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'
```

Expected: PASS.

- [x] **Step 2: Run local TLS matrix**

Run:

```powershell
pwsh -NoLogo -NoProfile -File .\tests\integration\tls_matrix.ps1 -Configuration Debug -Platform x64
```

Expected: PASS or SKIP with explicit missing-tool reason.

- [x] **Step 3: Build Debug and Release**

Run:

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64
```

Expected: 0 errors, 0 warnings. Warnings are treated as errors.

- [ ] **Step 4: Optional ARM64 build**

Run when ARM64 WDK toolchain is available:

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform ARM64
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform ARM64
```

Expected: 0 errors, 0 warnings.

## References

- IANA TLS Parameters: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
- RFC 5246, TLS 1.2: https://www.rfc-editor.org/rfc/rfc5246.html
- RFC 8446, TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446.html
- RFC 7748, X25519/X448: https://www.rfc-editor.org/rfc/rfc7748.html
- RFC 8439, ChaCha20-Poly1305: https://www.rfc-editor.org/rfc/rfc8439.html
- RFC 7919, FFDHE for TLS: https://www.rfc-editor.org/rfc/rfc7919.html
- RFC 5280, X.509 PKI profile: https://www.rfc-editor.org/rfc/rfc5280.html
- Microsoft CNG named elliptic curves: https://learn.microsoft.com/en-us/windows/win32/seccng/cng-named-elliptic-curves

Plan complete and saved to `docs/superpowers/plans/2026-06-10-tls12-13-full-support.md`. Ready to execute after explicit approval.
