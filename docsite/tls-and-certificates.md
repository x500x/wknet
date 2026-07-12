# TLS 与证书

### 版本路径与降级保护

- 客户端**只走单版本路径**：TLS 1.3 在允许范围内则优先（纯 1.3 ClientHello，`supported_versions=0x0304` + key_share），否则直接 1.2。**无握手内自动降级**。
- 1.3 解析失败时，尝试把同一字节当 1.2 ServerHello 重新解释并**分类**（不自动降级）：
  - 需满足门槛——1.2 与 1.3 都在范围内、且未配置 early data。
  - 若能干净解析为合法 1.2 ServerHello 且**无降级哨兵** → 归类 `VersionNegotiation`，连接仍失败，由 `session` 显式重连 1.2。
  - 若 server random 带降级哨兵 → 视为攻击，硬失败 `DecodeError` / `STATUS_INVALID_NETWORK_RESPONSE`。
  - 解析不出合法 1.2 → 不算 1.2 证据。
- 失败分类枚举 `TlsHandshakeFailureCategory{ None, VersionNegotiation, CertificateValidation, AlpnMismatch, NetworkIo, DecodeError, CryptoError, PeerAlert, LocalPolicy }`，可经 `LastHandshakeFailure()` 查询。

### Cipher / 群 / 签名：默认 vs 可选 vs 兼容

依 `TlsCapabilities`，`Default`/`Optional` 视为默认启用，`Legacy` 仅兼容档：

**Cipher（TLS 1.3）**：Default `AES_128_GCM_SHA256`、`AES_256_GCM_SHA384`、`CHACHA20_POLY1305_SHA256`；Optional `AES_128_CCM_SHA256`、`AES_128_CCM_8_SHA256`（注：1.3 默认 offer 列表只含前三件）。
**Cipher（TLS 1.2）**：Default ECDHE-RSA/ECDSA 的 AES128/256-GCM 与 ChaCha20；Optional DHE-RSA 三件；**Legacy（兼容档）** ECDHE-*-AES128-CBC-SHA256、RSA-kx 的 GCM/CBC。
**群**：Default `X25519`、`secp256r1/384r1/521r1`；Optional `X448`、`ffdhe2048/3072/4096/6144/8192`。
**签名**：Default `RSA-PSS-RSAE 256/384/512`、`ECDSA secp256r1/384r1/521r1`、`Ed25519`、`Ed448`；Optional `RSA-PSS-PSS 256/384/512`；Legacy `RSA-PKCS1 256/384/512`、`*-SHA1`。

### 安全策略 `tls::TlsPolicy`

```cpp
struct TlsPolicy {
    TlsSecurityProfile Profile = ModernDefault;   // 或 CompatibilityExplicit
    bool EnableTls12RsaKeyExchange     = false;
    bool EnableTls12Cbc                = false;
    bool EnableTls12Renegotiation      = false;    // 显式兼容开启后允许 TLS 1.2 全量重协商
    bool EnableTls12Sha1Signatures     = false;
    bool EnablePostHandshakeClientAuth = false;
    bool RequireRevocationCheck        = false;
};
```
`ModernDefault` 下若置位前四个兼容开关 → `TlsValidatePolicy` 返回 `STATUS_INVALID_PARAMETER`。`EnableTls12RsaKeyExchange` 放行 RSA-kx 套件、`EnableTls12Cbc` 放行 CBC 套件并驱动是否 offer EtM、`EnableTls12Renegotiation` 放行 TLS 1.2 服务器 `HelloRequest` 触发或低层客户端主动发起的全量 secure renegotiation（次数由 `MaxTls12Renegotiations` 限制；不支持 abbreviated/session resumption；ALPN 按本次重协商结果更新）、`EnableTls12Sha1Signatures` 放行 SHA-1 签名、`EnablePostHandshakeClientAuth` 放行接受 1.3 post-handshake CertificateRequest、`RequireRevocationCheck` 传入证书校验。policy 被哈希为 `PolicyIdentity` 用于会话恢复绑定。

### TLS 1.2 强制加固

ServerHello 必须含 **Extended Master Secret** 与**安全重协商指示**，否则 `LocalPolicy`/`STATUS_NOT_SUPPORTED`；选中 CBC 套件但无 EtM → 失败；始终用 RFC 7627 扩展主密钥；叶证书公钥算法须匹配套件认证类型，KeyUsage（若有）须许可对应用途，否则 `STATUS_TRUST_FAILURE`。始终 offer `status_request`（OCSP stapling）并解析 `CertificateStatus`。

### TLS 1.3 要点

- 初始仅 offer 一个 **X25519** key_share；HelloRetryRequest 时换群并**重算 PSK binder**（按合成 message_hash 转写）。
- offer `signature_algorithms_cert`（ext 50）。
- KeyUpdate：**仅在服务端 `update_requested` 时被动回应并 rekey**，从不主动 rekey。
- record padding 可配（占用最大分片）。

### 0-RTT / early data

- 硬前置：若 `EnableEarlyData` 且有数据但 `EarlyDataReplaySafe=false` → `Connect` 直接返回 `STATUS_NOT_SUPPORTED`。
- 仅在有通告了 `max_early_data_size` 的恢复 ticket、且 `EnableEarlyData && EarlyDataReplaySafe && 数据≤上限` 时才真正发送 early data（在读 ServerHello 前）。被接受才发 `EndOfEarlyData`。
- TLS 1.2 下任何 `EnableEarlyData` → `STATUS_NOT_SUPPORTED`。

### 会话恢复

- TLS 1.3 ticket / 1.2 session（id+ticket）各最多 4 条缓存。选用 ticket 须匹配：**PolicyIdentity、SNI、ALPN、cipher、版本**、未过期；1.3 服务端选了 PSK 则其 cipher 必须等于协商 cipher。`EnableSessionResumption` 默认 true。

### 记录层

AES-GCM(1.2 显式 nonce / 1.3 12 字节 IV XOR 序列号)、AES-CBC **Encrypt-then-MAC**（MAC 常量时间先验后解，padding 常量时间校验）、ChaCha20-Poly1305（走 GCM 代码路径）。`TlsMaxPlaintextLength=16384`；多项抗洪泛上限：每次接收握手记录 ≤16（空记录）/ 单记录握手消息 ≤8 / 握手读 ≤64 记录；序列号溢出 → `STATUS_INVALID_DEVICE_STATE`。alert：close_notify → `STATUS_CONNECTION_DISCONNECTED`，其余 → `STATUS_INVALID_NETWORK_RESPONSE`。

### 证书校验 `tls::CertificateValidator`

在**扩展内核栈**上运行（`KeExpandKernelStackAndCalloutEx`）。`ValidateChain` 有序步骤：输入界限（链 ≤8）→ 解析（`VerifyCertificate=false` 时只解析叶并返回）→ 主机归一化 → 有界候选路径搜索（subject/issuer、AKI/SKI、签名可验证性，多中间与交叉签名回溯）→ 叶 SPKI SHA-256 → Name Constraints → certificatePolicies → 有效期 → EKU serverAuth（可选）→ 叶 basic constraints/KU（须 digitalSignature、非 CA）→ 主机名匹配 → 逐链（DN 链接、CA、keyCertSign、pathLen、签名验证）→ pin → 信任锚（缺失 → `STATUS_TRUST_FAILURE`）→ 撤销。解析期**拒绝重复扩展与未知 critical 扩展**。

**主机名**：SAN dNSName 通配仅限单个最左标签（匹配段不含 `.`）；IP literal **只匹配 iPAddress SAN**，无 CN/dNSName 回退；**从不用 CN 做主机匹配**（CN 仅在无 SAN dNSName 时用于 name-constraint）；IDNA/punycode（标签 ≤63、总 ≤255）。

### 证书存储与锁定 `wknet::http::CertificateStore`

上限：信任锚 16、CA 包 8、pin 32、撤销条目 32。信任锚必须设 `MatchSubjectPublicKey`（强制 SPKI）。公共 API 使用 opaque `CertificateStore*`。PEM 包仅在成员边界完整时隔离单成员格式/能力错误；缺失 END、资源/密码学错误严格失败。单 DER 解析失败严格失败。**SPKI pin**：对配置了 pin 的主机校验叶 SPKI；**未配置 pin 的主机 fail-open**（放行）。

```cpp
wknet::http::CertificateTrustAnchor anchor = {};
anchor.SubjectName = rootSubject; anchor.SubjectNameLength = rootSubjectLen;
RtlCopyMemory(anchor.SubjectPublicKeySha256, rootSpkiHash, 32);
anchor.MatchSubjectPublicKey = true;
wknet::http::CertificatePin pin = { "example.com", 11 };
RtlCopyMemory(pin.LeafSubjectPublicKeySha256, leafSpkiHash, 32);
wknet::http::CertificateStoreOptions o = {};
o.TrustAnchors = &anchor; o.TrustAnchorCount = 1; o.Pins = &pin; o.PinCount = 1;
wknet::http::CertificateStore* store = nullptr;
NTSTATUS status = wknet::http::CertificateStoreCreate(&o, &store);
config.Tls.Store = store;
// SessionClose 后：wknet::http::CertificateStoreClose(store);
```

### 撤销

**纯离线、证据驱动**。OCSP stapling、静态 `CertificateRevocationEntry` 与 `RevocationProvider` 回调都必须提供 OCSP/CRL DER evidence；校验链路会验证 evidence 的签名、issuer/serial 匹配、thisUpdate/nextUpdate 时间窗与 good/revoked/unknown 状态。`OnlineRequired`（或 `RequireRevocationCheck`）时逐证查询：优先 OCSP，缺失才回退 CRL；查不到或 evidence 无效 → **fail-closed**（`STATUS_TRUST_FAILURE`）。`StapledOnly` 无 CRL 回退。库**从不在线抓取**，provider 只负责把外部获取的 DER 证据交回库内验证。

### mTLS 客户端证书

`wknet::http::TlsClientCredential` 携带证书链、`KeyAlgorithm`、支持的签名方案、`AllowsDigitalSignature` 与 `Sign` 回调。**私钥永不进入库**——签名经回调完成（TLS1.2 对 transcript hash 签；TLS1.3 对 `BuildCertificateVerifyInput` 构造的上下文签）。

> ⚠️ 生产环境严禁 `CertPolicy::NoVerify`（会跳过整条链校验，仅算叶 SPKI）。
