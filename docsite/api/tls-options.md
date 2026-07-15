# 证书与 TLS 选项

命名空间：`wknet::http`（凭据类型别名自 `wknet::crypto`）  
头文件：`wknet/http/Types.h` · `wknet/http/Certificate.h` · `wknet/crypto/TlsCredential.h`

## 职责

会话 / 单次发送 TLS 策略、证书存储、pin、撤销与 mTLS 客户端凭据。

## TlsVersion / CertPolicy

```cpp
enum class TlsVersion : ULONG {
    Tls12 = 0x0303,
    Tls13 = 0x0304
};

enum class CertPolicy : ULONG {
    Verify = 0,
    NoVerify = 1
};
```

生产路径使用 `Verify`。`NoVerify` 仅测试；默认不学习/使用 Alt-Svc。

## TlsSecurityProfile / TlsPolicy

```cpp
enum class TlsSecurityProfile : UCHAR {
    ModernDefault,
    CompatibilityExplicit
};

struct TlsPolicy final {
    TlsSecurityProfile Profile = TlsSecurityProfile::ModernDefault;
    bool EnableTls12RsaKeyExchange = false;
    bool EnableTls12Cbc = false;
    bool EnableTls12Renegotiation = false;
    bool EnableTls12Sha1Signatures = false;
    bool EnablePostHandshakeClientAuth = false;
    bool RequireRevocationCheck = false;
};
```

兼容项默认关闭；需显式打开。

## TlsConfig

```cpp
TlsConfig DefaultTlsConfig() noexcept; // TlsConfig{}

struct TlsConfig final {
    // 默认 Min=TLS1.2、Max=TLS1.3：优先 1.3，对端无法协商时回连 1.2。
    // 设 MinVersion=MaxVersion=Tls13 可仅允许 TLS 1.3。
    TlsVersion MinVersion = TlsVersion::Tls12;
    TlsVersion MaxVersion = TlsVersion::Tls13;
    CertPolicy Certificate = CertPolicy::Verify;
    const CertificateStore* Store = nullptr;
    const char* ServerName = nullptr;
    SIZE_T ServerNameLength = 0;
    const char* Alpn = nullptr;
    SIZE_T AlpnLength = 0;
    bool PreferHttp2 = true;
    TlsPolicy Policy = {};
    const TlsClientCredential* ClientCredential = nullptr;
    ULONG HandshakeTimeoutMs = DefaultTlsHandshakeTimeoutMs;
    ULONG MaxTls12Renegotiations = DefaultMaxTls12Renegotiations; // 1；硬上限 HardMaxTls12Renegotiations=4
};
```

| 字段 | 说明 |
|------|------|
| `MinVersion` / `MaxVersion` | 允许 TLS 版本范围 |
| `Certificate` | 校验策略 |
| `Store` | 信任锚 / pin 存储；库**不**内置系统 CA |
| `ServerName` / `Length` | SNI 与主机名校验；空则从 URL host 推导 |
| `Alpn` / `Length` | 显式 ALPN；空则按 `PreferHttp2` 自动 |
| `PreferHttp2` | 自动 ALPN 时优先 h2 |
| `Policy` | 套件 / 重协商等策略 |
| `ClientCredential` | mTLS |
| `HandshakeTimeoutMs` | 握手超时 |
| `MaxTls12Renegotiations` | TLS1.2 真重协商次数上限 |

使用位置：`SessionConfig.Tls`；`SendOptions.Tls` + `HasTlsOverride=true`；`websocket::ConnectConfig.Tls`。

## CertificateStore 常量

```cpp
constexpr SIZE_T CertificateSha256ThumbprintLength = 32;
constexpr SIZE_T CertificateSha1ThumbprintLength = 20;
constexpr SIZE_T CertificateMaxTrustAnchors = 16;
constexpr SIZE_T CertificateMaxAuthorityBundles = 8;
constexpr SIZE_T CertificateMaxPins = 32;
constexpr SIZE_T CertificateMaxRevocationEntries = 32;
constexpr SIZE_T CertificateMaxRevocationUris = 4;
```

## 信任锚 / Pin / CA 包

```cpp
struct CertificateTrustAnchor final {
    const UCHAR* SubjectName = nullptr;
    SIZE_T SubjectNameLength = 0;
    UCHAR SubjectPublicKeySha256[CertificateSha256ThumbprintLength] = {};
    bool MatchSubjectPublicKey = false;
};

struct CertificatePin final {
    const char* HostName = nullptr;
    SIZE_T HostNameLength = 0;
    UCHAR LeafSubjectPublicKeySha256[CertificateSha256ThumbprintLength] = {};
};

struct CertificateAuthorityBundle final {
    const UCHAR* Data = nullptr;
    SIZE_T DataLength = 0;
};
```

Pin 为 leaf SPKI SHA-256。主机名校验不回退 CN（见产品信任文档）。

## 撤销

```cpp
enum class CertificateRevocationMode : UCHAR { Off, StapledOnly, OnlineRequired };
enum class CertificateRevocationSource : UCHAR { Ocsp, Crl };
enum class CertificateRevocationStatus : UCHAR { Good, Revoked, Unknown };

struct CertificateRevocationEntry final {
    const UCHAR* IssuerName = nullptr;
    SIZE_T IssuerNameLength = 0;
    const UCHAR* SerialNumber = nullptr;
    SIZE_T SerialNumberLength = 0;
    CertificateRevocationSource Source = CertificateRevocationSource::Ocsp;
    CertificateRevocationStatus Status = CertificateRevocationStatus::Unknown;
    long long ThisUpdate = 0;
    long long NextUpdate = 0;
    const UCHAR* EvidenceDer = nullptr;
    SIZE_T EvidenceDerLength = 0;
};

struct CertificateRevocationProviderQuery final {
    const UCHAR* CertificateDer = nullptr;
    SIZE_T CertificateDerLength = 0;
    const UCHAR* IssuerCertificateDer = nullptr;
    SIZE_T IssuerCertificateDerLength = 0;
    const UCHAR* IssuerName = nullptr;
    SIZE_T IssuerNameLength = 0;
    const UCHAR* SerialNumber = nullptr;
    SIZE_T SerialNumberLength = 0;
    const UCHAR* IssuerSubjectPublicKeyInfo = nullptr;
    SIZE_T IssuerSubjectPublicKeyInfoLength = 0;
    UCHAR OcspIssuerNameSha1[CertificateSha1ThumbprintLength] = {};
    UCHAR OcspIssuerKeySha1[CertificateSha1ThumbprintLength] = {};
    const UCHAR* OcspRequestDer = nullptr;
    SIZE_T OcspRequestDerLength = 0;
    const char* OcspUris[CertificateMaxRevocationUris] = {};
    SIZE_T OcspUriLengths[CertificateMaxRevocationUris] = {};
    SIZE_T OcspUriCount = 0;
    const char* CrlDistributionPointUris[CertificateMaxRevocationUris] = {};
    SIZE_T CrlDistributionPointUriLengths[CertificateMaxRevocationUris] = {};
    SIZE_T CrlDistributionPointUriCount = 0;
    CertificateRevocationSource PreferredSource = CertificateRevocationSource::Ocsp;
};

using CertificateRevocationProviderCallback = NTSTATUS(*)(
    _In_opt_ void* context,
    _In_ const CertificateRevocationProviderQuery* query,
    _Out_ CertificateRevocationEntry* entry);
```

## CertificateStoreOptions / API

```cpp
struct CertificateStoreOptions final {
    const CertificateTrustAnchor* TrustAnchors = nullptr;
    SIZE_T TrustAnchorCount = 0;
    const CertificateAuthorityBundle* AuthorityBundles = nullptr;
    SIZE_T AuthorityBundleCount = 0;
    const CertificatePin* Pins = nullptr;
    SIZE_T PinCount = 0;
    const CertificateRevocationEntry* RevocationEntries = nullptr;
    SIZE_T RevocationEntryCount = 0;
    CertificateRevocationProviderCallback RevocationProvider = nullptr;
    void* RevocationProviderContext = nullptr;
};

NTSTATUS CertificateStoreCreate(
    _In_opt_ const CertificateStoreOptions* options,
    _Out_ CertificateStore** store) noexcept;
NTSTATUS CertificateStoreLoadPemBundle(
    _In_ CertificateStore* store,
    _In_reads_bytes_(dataLength) const UCHAR* data,
    SIZE_T dataLength) noexcept;
NTSTATUS CertificateStoreLoadDer(
    _In_ CertificateStore* store,
    _In_reads_bytes_(dataLength) const UCHAR* data,
    SIZE_T dataLength) noexcept;
void CertificateStoreClose(_In_opt_ CertificateStore* store) noexcept;
```

`Store` 指针在引用它的 `Session` / 发送期间须保持有效。

## mTLS · TlsClientCredential

`Certificate.h` 再导出：

```cpp
using TlsClientCredentialKeyAlgorithm = crypto::TlsClientCredentialKeyAlgorithm;
using TlsClientCredentialSignCallback = crypto::TlsClientCredentialSignCallback;
using TlsClientCredential = crypto::TlsClientCredential;
using TlsSignatureScheme = crypto::TlsSignatureScheme;
```

`TlsCredential.h`：

```cpp
enum class TlsClientCredentialKeyAlgorithm : UCHAR {
    Unknown, Rsa, RsaPss, EcdsaP256, EcdsaP384, EcdsaP521, Ed25519, Ed448
};

using TlsClientCredentialSignCallback = NTSTATUS(*)(
    _In_opt_ void* context,
    TlsSignatureScheme scheme,
    _In_reads_bytes_(inputLength) const UCHAR* input, SIZE_T inputLength,
    _Out_writes_bytes_(signatureCapacity) UCHAR* signature, SIZE_T signatureCapacity,
    _Out_ SIZE_T* signatureLength);

struct TlsClientCredential final {
    const UCHAR* CertificateList = nullptr;
    SIZE_T CertificateListLength = 0;
    TlsClientCredentialKeyAlgorithm KeyAlgorithm = TlsClientCredentialKeyAlgorithm::Unknown;
    const TlsSignatureScheme* SupportedSignatureSchemes = nullptr;
    SIZE_T SupportedSignatureSchemeCount = 0;
    TlsClientCredentialSignCallback Sign = nullptr;
    void* SignContext = nullptr;
    bool AllowsDigitalSignature = true;
};
```

将 `const TlsClientCredential*` 赋给 `TlsConfig.ClientCredential`。私钥经 `Sign` 回调，库不持有原始私钥材料。

## 相关链接

- [会话与配置](session-config.md)
- [同步 HTTP · SendOptions.Tls](http-sync.md)
- [TLS 与信任](../tls-and-trust.md)
- [Cookbook](../cookbook.md)
