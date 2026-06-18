# 密码学层 / Cryptography

命名空间 `KernelHttp::crypto`。全部基于内核态 CNG/BCrypt，不引入第三方密码学库。被 TLS 层使用，也可单独调用。

[English](#english) | 简体中文

---

## 简体中文

### CNG Provider（`crypto/CngProvider.h`）

`CngProvider` 是静态工具类（不可实例化），每个操作有两个重载：带 `const CngProviderCache*`（复用已打开的 provider，推荐）和不带。

**算法枚举**
```cpp
enum class HashAlgorithm      { Sha1, Sha256, Sha384, Sha512 };
enum class EcCurve            { P256, P384, P521 };
enum class SignatureAlgorithm { RsaPkcs1Sha1/256/384/512, RsaPssSha256/384/512,
                                EcdsaSha1/256/384/512, Ed25519, Ed448 };
```

**主要操作**
- 随机数：`GenerateRandom`
- 哈希 / HMAC：`Hash`、`Hmac`
- HKDF：`HkdfExtract`、`HkdfExpand`
- AES-GCM：`AesGcmEncrypt` / `AesGcmDecrypt`
- AES-CBC：`AesCbcEncrypt` / `AesCbcDecrypt`
- 签名验证：`VerifySignature`
- RSA：`EncryptRsaPkcs1`、`ImportRsaPublicKey`
- ECDH：`GenerateEcdhKeyPair`、`ImportEcdhPublicKey`、`DeriveEcdhSecret`
- ECDSA：`ImportEcdsaPublicKey`

**RAII 包装类**
- `CngAlgorithmProvider`：包 `BCRYPT_ALG_HANDLE`（`Open`/`Close`/`IsOpen`）
- `CngKey`：包 `BCRYPT_KEY_HANDLE`（`ImportPublicKey`/`ExportPublicKey`）
- `CngHashContext`：增量哈希（`Initialize`/`Update`/`Finish`/`Reset`）

### Provider 缓存（`crypto/CngProviderCache.h`）

`CngProviderCache` 预打开并缓存常用 provider，避免每次操作重复 `BCryptOpenAlgorithmProvider`。会话创建时分配一个，整库高频复用。

```cpp
NTSTATUS Initialize() noexcept;  void Shutdown() noexcept;
const CngAlgorithmProvider* Aes() / Hash(alg) / Hmac(alg) / Rsa() / Ecdsa(curve) / Ecdh(curve);
```
缓存项覆盖 AES、SHA1/256/384/512、对应 HMAC、RSA、ECDSA/ECDH P256/P384/P521。

### AEAD（`crypto/Aead.h`）

```cpp
enum class AeadAlgorithm { Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, Aes128Ccm, Aes128Ccm8 };
class Aead {
    static SIZE_T   TagLength(AeadAlgorithm);
    static NTSTATUS Encrypt(cache, key, params, plaintext.., ciphertext.., tag..);
    static NTSTATUS Decrypt(cache, key, params, ciphertext.., plaintext..);
};
```
常量：max key 32、max nonce 12、max tag 16；ChaCha20-Poly1305 key/nonce/tag = 32/12/16。

### 密钥交换（`crypto/KeyExchange.h`）

```cpp
enum class KeyExchangeGroup : USHORT {
    Secp256r1=23, Secp384r1=24, Secp521r1=25, X25519=29, X448=30,
    Ffdhe2048=256, Ffdhe3072=257, Ffdhe4096=258, Ffdhe6144=259, Ffdhe8192=260
};
class KeyExchange {
    static bool     IsSupportedGroup(group);  IsRawKeyShareGroup(group);
    static SIZE_T   PublicKeyLength(group);   SharedSecretLength(group);
    static NTSTATUS GenerateKeyPair(cache, group, keyPair);
    static NTSTATUS DerivePublicKey(...);     DeriveSharedSecret(...);
    static NTSTATUS ValidateFiniteFieldPublicKey(...);  // FFDHE 公钥校验
};
```
X25519 私钥 32、X448 56；FFDHE 2048..8192 对应 256..1024 字节。

### 设计要点

- 所有密码学操作返回 `NTSTATUS`、`noexcept`、不抛异常。
- 私钥材料用 `CngKey` RAII 持有，作用域结束清理；TLS 会话结束统一清零密钥。
- 优先通过 `CngProviderCache` 调用，避免重复打开 provider。
- 用户态测试构建（`KERNEL_HTTP_USER_MODE_TEST`）下 `bcrypt.h` 类型被 stub。

---

## English

Namespace `KernelHttp::crypto`, entirely on kernel CNG/BCrypt. `CngProvider` is a static utility (each op has a `CngProviderCache`-taking overload for reuse): random, hash/HMAC, HKDF (extract/expand), AES-GCM, AES-CBC, signature verify, RSA PKCS#1 encrypt + public-key import, ECDH keygen/import/derive, ECDSA import. RAII wrappers: `CngAlgorithmProvider`, `CngKey`, `CngHashContext`.

`CngProviderCache` pre-opens and caches providers (AES, SHA-1/256/384/512 + HMAC, RSA, ECDSA/ECDH P256/P384/P521); one per session, reused library-wide.

`Aead` covers Aes128Gcm/Aes256Gcm/ChaCha20Poly1305/Aes128Ccm/Aes128Ccm8. `KeyExchange` covers secp256r1/384r1/521r1, x25519, x448, ffdhe2048–8192, with key-pair generation, public-key derivation, shared-secret derivation, and finite-field public-key validation.

All operations are `noexcept`, return `NTSTATUS`, hold private keys in RAII `CngKey`, and zeroize key material at scope/session end. Under `KERNEL_HTTP_USER_MODE_TEST`, `bcrypt.h` types are stubbed.
