# Codec 与 Crypto

命名空间：`wknet::codec` · `wknet::crypto`  
头文件：`wknet/codec/Codec.h` · `wknet/crypto/Aead.h`  
（`Wknet.h` 已包含二者）

## 职责

公开 content-coding / EXI / Pack200 解码与 AEAD 加解密入口。产品 HTTP 路径通常经 `SendOptions` 的 Accept-Encoding / coding materials 间接使用 codec；TLS 记录层间接使用 crypto。

---

## Codec · `wknet::codec`

### Coding / 材料

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

### 函数

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

| API | 说明 |
|-----|------|
| `DeflateRuntimeAvailable` | Deflate 运行时是否可用 |
| `DecodeOne` | 单一 coding → `destination` |
| `DecodeChain` | 按 Content-Encoding **逆序**解码链 |
| `DecodeExi` | 仅 schema-less EXI 1.0；外部 Schema/strict grammar → `STATUS_NOT_SUPPORTED` |
| `DecodePack200` | Java 5–8 Pack200 150.7/160.1/170.1/171.0；输出语义等价 JAR |

HTTP 层对应材料类型为 `http::CodingDecodeMaterials` / `http::ContentCoding`（见 [同步 HTTP](http-sync.md)）。

---

## Crypto AEAD · `wknet::crypto::Aead`

头文件依赖 `CngProvider.h` 中的 `BufferView` / `CngProviderCache`。

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

| 项 | 说明 |
|----|------|
| `cache` | 可选 CNG provider 缓存；`nullptr` 走即时打开路径 |
| `Encrypt` | 写出密文与 tag |
| `Decrypt` | 校验 tag 后写出明文；失败不部分提交可信明文 |
| `TagLength` | 算法 tag 字节数 |

`BufferView`（`CngProvider.h`）：`const UCHAR* Data` + `SIZE_T Length`。

其它 `crypto` 头（`Ed25519.h`、`KeyExchange.h` 等）未由 `Wknet.h` 聚合；按需单独包含。

## 相关链接

- [同步 HTTP · AcceptEncoding](http-sync.md)
- [证书与 TLS](tls-options.md)
- [编码与密码学](../encoding-and-crypto.md)
