# TLS Options

Namespace: `wknet::http` (credential types aliased from `wknet::crypto`)  
Headers: `wknet/http/Types.h` · `wknet/http/Certificate.h` · `wknet/crypto/TlsCredential.h`

`TlsConfig`, `CertificateStore`, pins, revocation, and mTLS client credentials.

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

Use `Verify` in production. `NoVerify` is for tests only; Alt-Svc is not learned/used by default with it.

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

Compatibility knobs default off; enable explicitly.

## TlsConfig

```cpp
TlsConfig DefaultTlsConfig() noexcept; // TlsConfig{}

struct TlsConfig final {
    // Default Min=TLS1.2, Max=TLS1.3: prefer 1.3; reconnect with 1.2 only if peer cannot do 1.3.
    // Set MinVersion=MaxVersion=Tls13 to require TLS 1.3 only.
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
    ULONG MaxTls12Renegotiations = DefaultMaxTls12Renegotiations; // 1; hard max HardMaxTls12Renegotiations=4
};
```

| Field | Notes |
|-------|-------|
| `MinVersion` / `MaxVersion` | Allowed TLS range |
| `Certificate` | Verification policy |
| `Store` | Trust anchors / pins; library has **no** built-in system CA |
| `ServerName` / `Length` | SNI and hostname check; empty derives from URL host |
| `Alpn` / `Length` | Explicit ALPN; empty uses `PreferHttp2` |
| `PreferHttp2` | Prefer h2 in auto ALPN |
| `Policy` | Cipher / renegotiation policy |
| `ClientCredential` | mTLS |
| `HandshakeTimeoutMs` | Handshake timeout |
| `MaxTls12Renegotiations` | Cap for TLS 1.2 true renegotiation |

Used as: `SessionConfig.Tls`; `SendOptions.Tls` with `HasTlsOverride=true`; `websocket::ConnectConfig.Tls`.

## CertificateStore constants

```cpp
constexpr SIZE_T CertificateSha256ThumbprintLength = 32;
constexpr SIZE_T CertificateSha1ThumbprintLength = 20;
constexpr SIZE_T CertificateMaxTrustAnchors = 16;
constexpr SIZE_T CertificateMaxAuthorityBundles = 8;
constexpr SIZE_T CertificateMaxPins = 32;
constexpr SIZE_T CertificateMaxRevocationEntries = 32;
constexpr SIZE_T CertificateMaxRevocationUris = 4;
```

## Trust anchors / pins / CA bundles

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

Pins are leaf SPKI SHA-256. Hostname verification does not fall back to CN.

## Revocation

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

`Store` must remain valid while referenced by a session or send.

## mTLS · TlsClientCredential

`Certificate.h` re-exports:

```cpp
using TlsClientCredentialKeyAlgorithm = crypto::TlsClientCredentialKeyAlgorithm;
using TlsClientCredentialSignCallback = crypto::TlsClientCredentialSignCallback;
using TlsClientCredential = crypto::TlsClientCredential;
using TlsSignatureScheme = crypto::TlsSignatureScheme;
```

From `TlsCredential.h`:

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

Assign `const TlsClientCredential*` to `TlsConfig.ClientCredential`. Private keys stay behind `Sign`; the library does not hold raw private key material.

## Examples

### Build a trust store from PEM and use it on a Session

```cpp
#include <wknet/Wknet.h>

NTSTATUS HttpsWithPemTrust(
    _In_reads_bytes_(pemLength) const UCHAR* pem,
    SIZE_T pemLength)
{
    using namespace wknet::http;

    CertificateStore* store = nullptr;
    NTSTATUS status = CertificateStoreCreate(nullptr, &store);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = CertificateStoreLoadPemBundle(store, pem, pemLength);
    if (!NT_SUCCESS(status)) {
        CertificateStoreClose(store);
        return status;
    }

    SessionConfig config = DefaultSessionConfig();
    config.Tls.Certificate = CertPolicy::Verify;
    config.Tls.Store = store; // Store must remain valid for the Session lifetime

    Session* session = nullptr;
    Response* response = nullptr;
    status = SessionCreate(&config, &session);
    if (NT_SUCCESS(status)) {
        status = Get(session, "https://example.com/", &response);
    }

    ResponseRelease(response);
    SessionClose(session);
    CertificateStoreClose(store);
    return status;
}
```

### Per-send TLS override (NoVerify for tests only)

```cpp
SendOptions* options = nullptr;
SendOptionsCreate(&options);
options->HasTlsOverride = true;
options->Tls = DefaultTlsConfig();
options->Tls.Certificate = CertPolicy::NoVerify; // tests only; production: Verify + Store

Response* response = nullptr;
GetEx(session, url, urlLen, nullptr, options, &response);
ResponseRelease(response);
SendOptionsRelease(options);
```

### TLS 1.3 only

```cpp
TlsConfig tls = DefaultTlsConfig();
tls.MinVersion = TlsVersion::Tls13;
tls.MaxVersion = TlsVersion::Tls13;
tls.Certificate = CertPolicy::Verify;
tls.Store = store;

SessionConfig config = DefaultSessionConfig();
config.Tls = tls;
SessionCreate(&config, &session);
```

### SPKI pin (sketch)

```cpp
CertificatePin pin = {};
pin.HostName = "example.com";
pin.HostNameLength = sizeof("example.com") - 1;
// fill pin.LeafSubjectPublicKeySha256 with the leaf SPKI SHA-256

CertificateStoreOptions opts = {};
opts.Pins = &pin;
opts.PinCount = 1;
// usually also supply TrustAnchors or AuthorityBundles

CertificateStore* store = nullptr;
CertificateStoreCreate(&opts, &store);
```

## See also

- [Session & Config](session-config.en.md)
- [Sync HTTP · SendOptions.Tls](http-sync.en.md)
- [TLS & trust](../tls-and-trust.en.md)
- [Cookbook](../cookbook.en.md)
