# 密码学层

### CNG vs 软件实现

| 原语 | 实现 |
|------|------|
| SHA-1/256/384/512、HMAC、HKDF | CNG（HKDF 在 HMAC 上自实现；Expand 限 `out≤摘要×255`、`info≤256`） |
| AES-GCM | CNG（tag 16；key 16/32） |
| **ChaCha20-Poly1305** | **纯软件**（ChaCha20 20 轮 + Poly1305 5×26-bit；解密前常量时间验 tag） |
| **AES-CCM / CCM8** | **纯软件 AES-128 + CCM**（tag 16/8；nonce 7–13；tag 不符清零明文） |
| NIST P-256/384/521 ECDH/ECDSA | CNG（公钥未压缩点 `0x04`，导入校验长度/前缀） |
| **X25519 / X448** | **纯软件** Montgomery ladder（常量时间 cswap，标量 clamp，拒绝全零 peer/共享密钥） |
| **FFDHE 2048–8192** | **纯软件**模幂（Montgomery；RFC 7919 素数；公钥范围校验 2≤y≤p-2） |
| RSA-PKCS1 / RSA-PSS 验签 | CNG（PSS salt=摘要长 32/48/64） |
| ECDSA 验签 | CNG（DER→raw R‖S 转换，长度 64/96/132） |
| Ed25519 验签 | 纯软件 PureEdDSA（RFC 8032），对完整消息执行内部 SHA-512；证书链与 TLS CertificateVerify 路径均使用原始输入验签 |
| Ed448 验签 | 纯软件 PureEdDSA（RFC 8032），对完整消息执行内部 SHAKE256；证书链与 TLS CertificateVerify/ServerKeyExchange 路径均使用原始输入验签，并在默认 `signature_algorithms` 中宣称 |

### 枚举

```cpp
enum class HashAlgorithm      { Sha1, Sha256, Sha384, Sha512 };
enum class EcCurve            { P256, P384, P521 };
enum class SignatureAlgorithm { RsaPkcs1Sha1/256/384/512, RsaPssSha256/384/512,
                                EcdsaSha1/256/384/512, Ed25519, Ed448 };
enum class AeadAlgorithm      { Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, Aes128Ccm, Aes128Ccm8 };
enum class KeyExchangeGroup : USHORT { Secp256r1=23, Secp384r1=24, Secp521r1=25,
                                X25519=29, X448=30, Ffdhe2048=256..Ffdhe8192=260 };
```

### 约束与硬化

- **最小 RSA 模数 2048 位**（`KhMinRsaModulusBits`），在 SPKI 解析与 RSA 导入两处强制；RSA 指数须 ≥3 且为奇。
- **FFDHE 公钥校验**：拒绝 `y∈{0,1}` 或 `y≥p-1`，每次派生共享密钥都做。
- **密钥清零**：AEAD scratch、X25519/X448 中间量、ECDSA raw、RSA blob、HKDF 中间量、ECDH 共享密钥、SPKI 哈希等全部 `RtlSecureZeroMemory`；`KeyExchangeKeyPair::Reset` 清私/公钥。
- 共享密钥从 CNG 小端原始值转成大端并左零填充。

### Provider 缓存 `CngProviderCache`

预打开并持有 AES、SHA1/256/384/512、对应 HMAC、RSA、ECDSA/ECDH P256/384/521 各一个 `BCRYPT_ALG_HANDLE`（`Initialize` 需 `PASSIVE_LEVEL`）。各 CNG 操作带可选 `const CngProviderCache*`，命中则复用句柄而非新开 provider。会话创建时分配一个，整库高频复用。**软件路径（ChaCha/CCM/X25519/X448/FFDHE）不使用缓存**。

### RAII 包装

`CngAlgorithmProvider`（`BCRYPT_ALG_HANDLE`）、`CngKey`（`BCRYPT_KEY_HANDLE`，私钥 RAII，作用域结束清理）、`CngHashContext`（增量哈希，`Finish` 复制句柄保持可重用）。

### 用户态测试

`WKNET_USER_MODE_TEST` 下 `bcrypt.h` 类型被 stub，并提供软件 SHA-1/SHA-256 实现以便无内核环境跑通。
