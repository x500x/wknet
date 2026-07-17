# Codec & Crypto

Namespaces: `wknet::codec` · `wknet::crypto`  
Headers: `wknet/codec/Codec.h` · `wknet/crypto/Aead.h`  
(both included by `Wknet.h`)

Content-coding / EXI / Pack200 decode, and AEAD encrypt/decrypt. HTTP sends can use codec through `SendOptions` Accept-Encoding / coding materials.

---

## Codec · `wknet::codec`

### Coding / materials

```cpp
enum class Coding : UCHAR {
    Identity = 0,
    Gzip = 1,
    Deflate = 2,
    Brotli = 3,
    Compress = 4,
    Zstd = 5,
    DictionaryCompressedBrotli = 6,
    DictionaryCompressedZstd = 7,
    Aes128Gcm = 8,
    Exi = 9,
    Pack200Gzip = 10
};

struct ExternalMaterial final {
    Coding CodingKind = Coding::Identity;
    const UCHAR* Dictionary = nullptr;
    SIZE_T DictionaryLength = 0;
    const UCHAR* Aes128GcmKeyingMaterial = nullptr;
    SIZE_T Aes128GcmKeyingMaterialLength = 0;
};

using MaterialCallback = NTSTATUS(*)(
    _In_opt_ void* context,
    Coding coding,
    _Out_ ExternalMaterial* material);

struct DecodeMaterials final {
    const ExternalMaterial* Items = nullptr;
    SIZE_T ItemCount = 0;
    MaterialCallback Callback = nullptr;
    void* CallbackContext = nullptr;
};

struct DecodeBuffers final {
    char* DecodedBody = nullptr;
    SIZE_T DecodedBodyCapacity = 0;
    char* ScratchBody = nullptr;
    SIZE_T ScratchBodyCapacity = 0;
    const DecodeMaterials* Materials = nullptr;
};

struct DecodeResult final {
    const char* Body = nullptr;
    SIZE_T BodyLength = 0;
    bool AppliedCoding = false;
};
```

### Functions

```cpp
bool DeflateRuntimeAvailable() noexcept;

NTSTATUS DecodeOne(
    Coding coding,
    _In_reads_bytes_(sourceLength) const char* source,
    SIZE_T sourceLength,
    _Out_writes_bytes_(destinationCapacity) char* destination,
    SIZE_T destinationCapacity,
    _Out_ SIZE_T* decodedLength,
    _In_opt_ const DecodeMaterials* materials = nullptr) noexcept;

NTSTATUS DecodeChain(
    _In_reads_(codingCount) const Coding* codings,
    SIZE_T codingCount,
    _In_reads_bytes_(bodyLength) const char* body,
    SIZE_T bodyLength,
    _In_ const DecodeBuffers& buffers,
    _Out_ DecodeResult& result) noexcept;

// Schema-less EXI 1.0 → Infoset-equivalent XML
NTSTATUS DecodeExi(
    _In_reads_bytes_(sourceLength) const UCHAR* source,
    SIZE_T sourceLength,
    _Out_writes_bytes_(destinationCapacity) char* destination,
    SIZE_T destinationCapacity,
    _Out_ SIZE_T* decodedLength) noexcept;

// Pack200 (raw or gzip) → JAR bytes
NTSTATUS DecodePack200(
    _In_reads_bytes_(sourceLength) const UCHAR* source,
    SIZE_T sourceLength,
    _Out_writes_bytes_(destinationCapacity) char* destination,
    SIZE_T destinationCapacity,
    _Out_ SIZE_T* decodedLength) noexcept;
```

| API | Notes |
|-----|-------|
| `DeflateRuntimeAvailable` | Whether Deflate runtime is available |
| `DecodeOne` | Single coding into `destination` |
| `DecodeChain` | Decode chain in **reverse** Content-Encoding order |
| `DecodeExi` | Schema-less EXI 1.0 only; external Schema/strict grammar → `STATUS_NOT_SUPPORTED` |
| `DecodePack200` | Java 5–8 Pack200 150.7/160.1/170.1/171.0; semantic JAR output |

HTTP-layer material types are `http::CodingDecodeMaterials` / `http::ContentCoding` (see [Sync HTTP](http-sync.en.md)).

---

## Crypto AEAD · `wknet::crypto::Aead`

Depends on `BufferView` / `CngProviderCache` from `CngProvider.h`.

```cpp
enum class AeadAlgorithm : UCHAR {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes128Ccm,
    Aes128Ccm8
};

constexpr SIZE_T AeadMaxKeyLength = 32;
constexpr SIZE_T AeadMaxNonceLength = 12;
constexpr SIZE_T AeadMaxTagLength = 16;
constexpr SIZE_T AeadChaCha20Poly1305KeyLength = 32;
constexpr SIZE_T AeadChaCha20Poly1305NonceLength = 12;
constexpr SIZE_T AeadChaCha20Poly1305TagLength = 16;

struct AeadKey final {
    AeadAlgorithm Algorithm = AeadAlgorithm::Aes128Gcm;
    const UCHAR* Key = nullptr;
    SIZE_T KeyLength = 0;
};

struct AeadParameters final {
    BufferView Nonce = {}; // Data / Length
    BufferView Aad = {};
    BufferView Tag = {};
};

class Aead final {
public:
    Aead() = delete;

    static SIZE_T TagLength(AeadAlgorithm algorithm) noexcept;

    static NTSTATUS Encrypt(
        _In_opt_ const CngProviderCache* cache,
        _In_ const AeadKey& key,
        _In_ const AeadParameters& parameters,
        _In_reads_bytes_opt_(plaintextLength) const UCHAR* plaintext,
        SIZE_T plaintextLength,
        _Out_writes_bytes_(ciphertextLength) UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        _Out_writes_bytes_(tagLength) UCHAR* tag,
        SIZE_T tagLength,
        _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

    static NTSTATUS Decrypt(
        _In_opt_ const CngProviderCache* cache,
        _In_ const AeadKey& key,
        _In_ const AeadParameters& parameters,
        _In_reads_bytes_opt_(ciphertextLength) const UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        _Out_writes_bytes_(plaintextLength) UCHAR* plaintext,
        SIZE_T plaintextLength,
        _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;
};
```

| Item | Notes |
|------|-------|
| `cache` | Optional CNG provider cache; `nullptr` opens providers as needed |
| `Encrypt` | Writes ciphertext and tag |
| `Decrypt` | Verifies tag then writes plaintext |
| `TagLength` | Tag size for algorithm |

`BufferView` (`CngProvider.h`): `const UCHAR* Data` + `SIZE_T Length`.

Other `crypto` headers (`Ed25519.h`, `KeyExchange.h`, …) are not aggregated by `Wknet.h`; include as needed.

## Examples

### Codec: single Gzip decode

```cpp
#include <wknet/Wknet.h>

NTSTATUS DecodeGzipBody(
    _In_reads_bytes_(srcLen) const char* src,
    SIZE_T srcLen,
    _Out_writes_bytes_(dstCap) char* dst,
    SIZE_T dstCap,
    _Out_ SIZE_T* outLen)
{
    return wknet::codec::DecodeOne(
        wknet::codec::Coding::Gzip,
        src,
        srcLen,
        dst,
        dstCap,
        outLen,
        nullptr);
}
```

### Codec: Content-Encoding chain (reverse order)

```cpp
// Content-Encoding: gzip, br → decode Brotli first, then Gzip
wknet::codec::Coding codings[] = {
    wknet::codec::Coding::Brotli,
    wknet::codec::Coding::Gzip
};

char decoded[64 * 1024];
char scratch[64 * 1024];
wknet::codec::DecodeBuffers buffers = {};
buffers.DecodedBody = decoded;
buffers.DecodedBodyCapacity = sizeof(decoded);
buffers.ScratchBody = scratch;
buffers.ScratchBodyCapacity = sizeof(scratch);

wknet::codec::DecodeResult result = {};
NTSTATUS status = wknet::codec::DecodeChain(
    codings,
    2,
    body,
    bodyLen,
    buffers,
    result);
// result.Body / result.BodyLength point at decoded output
```

### HTTP send path: negotiate Accept-Encoding

```cpp
using namespace wknet::http;

AcceptEncodingPreference prefs[2] = {};
prefs[0].Coding = AcceptCoding::Brotli;
prefs[0].QValue = AcceptEncodingQValueMax;
prefs[1].Coding = AcceptCoding::Gzip;
prefs[1].QValue = 800;

SendOptions* options = nullptr;
SendOptionsCreate(&options);
options->AcceptEncodingPreferences = prefs;
options->AcceptEncodingPreferenceCount = 2;

Response* response = nullptr;
GetEx(session, url, urlLen, nullptr, options, &response);
// Response Content-Encoding is decoded by the library when materials allow
ResponseRelease(response);
SendOptionsRelease(options);
```

### AEAD: AES-128-GCM encrypt/decrypt (sketch)

```cpp
using namespace wknet::crypto;

UCHAR key[16] = { /* 16-byte key */ };
UCHAR nonce[12] = { /* 12-byte nonce */ };
UCHAR aad[] = { /* optional AAD */ };
UCHAR plaintext[] = { /* ... */ };
UCHAR ciphertext[sizeof(plaintext)];
UCHAR tag[16];

AeadKey aeadKey = {};
aeadKey.Algorithm = AeadAlgorithm::Aes128Gcm;
aeadKey.Key = key;
aeadKey.KeyLength = sizeof(key);

AeadParameters params = {};
params.Nonce.Data = nonce;
params.Nonce.Length = sizeof(nonce);
params.Aad.Data = aad;
params.Aad.Length = sizeof(aad);

SIZE_T written = 0;
NTSTATUS status = Aead::Encrypt(
    nullptr, // optional CngProviderCache*
    aeadKey,
    params,
    plaintext,
    sizeof(plaintext),
    ciphertext,
    sizeof(ciphertext),
    tag,
    sizeof(tag),
    &written);

// Decrypt: params.Tag = { tag, sizeof(tag) }; then Aead::Decrypt(...)
```

## See also

- [Sync HTTP · AcceptEncoding](http-sync.en.md)
- [TLS options](tls-options.en.md)
- [Encoding & crypto](../encoding-and-crypto.en.md)
