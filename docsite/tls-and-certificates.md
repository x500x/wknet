# TLS 与证书 / TLS & Certificates

命名空间 `KernelHttp::tls`。内核自实现 TLS 1.2/1.3，密码学走 CNG/BCrypt（见 [密码学层](cryptography.md)）。

[English](#english) | 简体中文

---

## 简体中文

### 版本与协商

- `TlsProtocol { Tls12, Tls13 }`；线上版本 TLS1.2=`{3,3}`、TLS1.3=`{3,4}`。
- 默认 `MinVersion=Tls12`、`MaxVersion=Tls13`。
- ALPN 结果必须来自 client offer 列表；默认 offer `h2, http/1.1`。
- TLS1.2 选择只有在 TLS1.3 路径取得可验证版本协商证据后才允许；证书错误、ALPN mismatch、超时、解密失败都不算 TLS1.2-only 证据（防降级）。

### Cipher suites（`tls/TlsContext.h`，全列）

**TLS 1.3（5 个）**
`TLS_AES_128_GCM_SHA256` (0x1301)、`TLS_AES_256_GCM_SHA384` (0x1302)、`TLS_CHACHA20_POLY1305_SHA256` (0x1303)、`TLS_AES_128_CCM_SHA256` (0x1304)、`TLS_AES_128_CCM_8_SHA256` (0x1305)。

**TLS 1.2（14 个）**
- RSA kx：`RSA_AES128_CBC_SHA256` (0x003C)、`RSA_AES128_GCM_SHA256` (0x009C)、`RSA_AES256_GCM_SHA384` (0x009D)
- DHE-RSA：`DHE_RSA_AES128_GCM` (0x009E)、`DHE_RSA_AES256_GCM` (0x009F)、`DHE_RSA_CHACHA20` (0xCCAA)
- ECDHE-RSA：`ECDHE_RSA_AES128_GCM` (0xC02F)、`ECDHE_RSA_AES256_GCM` (0xC030)、`ECDHE_RSA_AES128_CBC_SHA256` (0xC027)、`ECDHE_RSA_CHACHA20` (0xCCA8)
- ECDHE-ECDSA：`ECDHE_ECDSA_AES128_GCM` (0xC02B)、`ECDHE_ECDSA_AES256_GCM` (0xC02C)、`ECDHE_ECDSA_AES128_CBC_SHA256` (0xC023)、`ECDHE_ECDSA_CHACHA20` (0xCCA9)

> 默认策略只启用现代 AEAD 套件；CBC 套件需显式开启（见下 TlsPolicy）。

### Named groups / 曲线（`TlsNamedGroup`）

`secp256r1`(23)、`secp384r1`(24)、`secp521r1`(25)、`x25519`(29)、`x448`(30)、`ffdhe2048`(256)、`ffdhe3072`(257)、`ffdhe4096`(258)、`ffdhe6144`(259)、`ffdhe8192`(260)。默认 key share 用 X25519。

### 签名方案（`TlsSignatureScheme`）

RSA-PKCS1 (SHA1/256/384/512)、ECDSA (SHA1/secp256r1/384r1/521r1)、Ed25519、Ed448、RSA-PSS（rsae 与 pss 各 SHA256/384/512）。SHA-1 类默认关闭。

### 安全策略 `tls::TlsPolicy`（`tls/TlsPolicy.h`）

```cpp
struct TlsPolicy {
    TlsSecurityProfile Profile = ModernDefault;   // 或 CompatibilityExplicit
    bool EnableTls12RsaKeyExchange     = false;
    bool EnableTls12Cbc                = false;
    bool EnableTls12Renegotiation      = false;
    bool EnableTls12Sha1Signatures     = false;
    bool EnablePostHandshakeClientAuth = false;
    bool RequireRevocationCheck        = false;
};
```
默认 `ModernDefault`：不启用 RSA kx、CBC、renegotiation、SHA-1。要用这些必须 `Profile = CompatibilityExplicit` 并分别置位对应开关。校验函数 `TlsValidatePolicy` 和 `TlsPolicyAllows*` 用于一致性检查。

> 0-RTT 不在 TlsPolicy 里，而是连接级：`TlsClientConnectionOptions::EnableEarlyData` + `EarlyDataReplaySafe`（默认都 false）。

### TLS 1.3 安全加固

- 严格校验服务器证书签名算法，拒绝弱方案
- 降级保护（防 TLS1.3→1.2）
- PSK/HRR 校验：ticket 绑定签发时间、SNI、ALPN、cipher、版本；HelloRetryRequest 后重算 PSK binder
- 会话结束安全清零密钥材料；信任锚链校验

### 会话恢复

- TLS 1.3：`Tls13SessionCache`（最多 4 张 ticket，最长 7 天）
- TLS 1.2：`Tls12SessionCache`（Session ID + Session Ticket，最多 4 条）
- 连接选项 `EnableSessionResumption` 默认 true。

### 证书存储 `tls::CertificateStore`（`tls/CertificateStore.h`）

```cpp
struct CertificateTrustAnchor {
    const UCHAR* SubjectName; SIZE_T SubjectNameLength;
    UCHAR SubjectPublicKeySha256[32];  bool MatchSubjectPublicKey = false;
};
struct CertificatePin {
    const char* HostName; SIZE_T HostNameLength;
    UCHAR LeafSubjectPublicKeySha256[32];      // SPKI pin
};
struct CertificateAuthorityBundle { const UCHAR* Data; SIZE_T DataLength; };  // PEM bundle 或单 DER
struct CertificateStoreOptions {
    const CertificateTrustAnchor*    TrustAnchors;    SIZE_T TrustAnchorCount;
    const CertificateAuthorityBundle* AuthorityBundles; SIZE_T AuthorityBundleCount;
    const CertificatePin*            Pins;            SIZE_T PinCount;
    const CertificateRevocationEntry* RevocationEntries; SIZE_T RevocationEntryCount;
};
```
上限：信任锚 16、CA 包 8、撤销条目 32。

公开方法：`Initialize(options)`、`Reset()`、`IsTrustedAnchor(...)`、`MatchesPin(...)`、计数与 `AuthorityBundleAt`、`FindRevocationEntry`。

### 证书锁定示例

```cpp
tls::CertificateTrustAnchor anchor = {};
anchor.SubjectName = rootSubject; anchor.SubjectNameLength = rootSubjectLen;
RtlCopyMemory(anchor.SubjectPublicKeySha256, rootSpkiHash, 32);
anchor.MatchSubjectPublicKey = true;

tls::CertificatePin pin = {};
pin.HostName = "example.com"; pin.HostNameLength = 11;
RtlCopyMemory(pin.LeafSubjectPublicKeySha256, leafSpkiHash, 32);

tls::CertificateStoreOptions o = {};
o.TrustAnchors = &anchor; o.TrustAnchorCount = 1;
o.Pins = &pin; o.PinCount = 1;

tls::CertificateStore store;
store.Initialize(o);
config.Tls.Store = &store;
```

### 证书校验 `tls::CertificateValidator`

`CertificateValidator::ValidateChain(chain, options, result)` 做：X.509 解析、链构建到信任锚、主机名匹配（SAN dNSName/iPAddress + 通配符）、有效期、basic constraints、KU/EKU（默认要求 serverAuth）、Name Constraints、certificatePolicies、可选 IDNA、可选撤销（OCSP/CRL 缓存）。
`CertificateValidationOptions` 关键字段：`HostName`、`Store`、`ScratchAllocator`、`ProviderCache`、`VerifyCertificate`、`RequireServerAuthEku`、`RequireRevocationCheck`、`RevocationMode { Off, StapledOnly, OnlineRequired }`、`EnableIdna`。

> IP literal 只匹配 iPAddress SAN，不回退 dNSName/CN。链最长 8。

### 撤销

库层不主动递归在线抓取 OCSP/CRL；支持 OCSP stapling 解析与 OCSP/CRL 撤销缓存（`CertificateRevocationEntry`，Good/Revoked/Unknown）。强撤销判定由调用方提供有界输入或缓存条目驱动。

### 客户端证书（mTLS）

`tls::TlsClientCredential`：携带 `CertificateList`、`KeyAlgorithm`、支持的签名方案，以及一个 `Sign` 回调（私钥由调用方持有，库不接触私钥）。绑定到 `TlsConfig::ClientCredential`。

### ALPN

```cpp
config.Tls.Alpn = "h2"; config.Tls.AlpnLength = 2;   // 或留默认让库 offer h2,http/1.1
```

> ⚠️ 生产环境严禁 `CertPolicy::NoVerify`。

---

## English

In-kernel TLS 1.2/1.3, crypto via CNG/BCrypt. Full enumerations (5 TLS 1.3 + 14 TLS 1.2 cipher suites with codepoints, named groups secp256r1/384r1/521r1 + x25519/x448 + ffdhe2048–8192, signature schemes incl. RSA-PSS/ECDSA/Ed25519/Ed448) are listed in the Chinese section.

**Security policy** `tls::TlsPolicy` defaults to `ModernDefault` and disables TLS 1.2 RSA key exchange, CBC, renegotiation, and SHA-1 signatures; enabling any requires `Profile = CompatibilityExplicit` plus the matching flag. 0-RTT is connection-level (`EnableEarlyData` + `EarlyDataReplaySafe`), not policy-level.

**TLS 1.3 hardening**: signature-scheme validation, downgrade protection, PSK/HRR validation (ticket bound to issue time, SNI, ALPN, cipher, version; binder recomputed after HelloRetryRequest), key zeroization, trust-anchor chain validation. **Resumption** via `Tls13SessionCache` (4 tickets) / `Tls12SessionCache`.

**Certificates**: `CertificateStore` holds trust anchors (max 16), CA bundles (PEM/DER, max 8), SPKI pins, and revocation entries (max 32). `CertificateValidator::ValidateChain` performs X.509 parse, chain build, SAN dNSName/iPAddress hostname match with wildcards (IP literals match iPAddress only), validity, basic constraints, KU/EKU (serverAuth required by default), name constraints, certificate policies, optional IDNA and OCSP/CRL revocation. The library does not fetch OCSP/CRL online. Mutual TLS via `TlsClientCredential` with a caller-held `Sign` callback. Never use `CertPolicy::NoVerify` in production.
