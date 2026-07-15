# 编码与密码学

讲 Content-Encoding / Transfer-Encoding 的解码策略，以及公开的 codec / crypto 面。产品路径一般经 HTTP/TLS 间接用到；直接调用见 [Codec 与 Crypto API](api/codec-crypto.md)。

## 结论

| 主题 | 行为 |
|------|------|
| Content-Encoding | `gzip` `deflate` `br` `compress` `zstd` `dcz` `aes128gcm` `exi` `pack200-gzip` `identity` |
| 链长 | 最多 **2** 级；**反序**解码 |
| 解压炸弹 | 单级膨胀比 ≤ **64**（`MaxDecodeExpansionRatio`）；总量跟响应/调用方容量 |
| Transfer-Encoding | `chunked`/`gzip`/`deflate`/`compress`（≤4）；**`br` 仅 CE 不支持 TE** |
| EXI | 无外部 Schema 流 → Infoset 等价 XML；外部 Schema/strict → `STATUS_NOT_SUPPORTED` |
| Pack200 | Java 5–8 稳定格式 → 语义等价 JAR |
| Crypto | CNG 优先；ChaCha/CCM/X25519/X448/FFDHE/Ed* 为内核内软件实现 |

## Content-Encoding

无调用方 `Accept-Encoding` 时，引擎注入默认  
`gzip, deflate, br, zstd, identity`（deflate 运行时不可用则 `br, identity`）。  
`SendOptions.AcceptEncodingPreferences` 可带 qvalue，并驱动响应 CE **fail-closed** 校验（含 `identity;q=0` / `*;q=0`）。

| coding | 要点 |
|--------|------|
| `gzip` | RFC 1952；校验头 CRC16、尾 CRC32、ISIZE |
| `deflate` | zlib 自动识别 + Adler-32；裸 DEFLATE 走内核路径并运行时探测 `DeflateRuntimeAvailable` |
| `br` | 内置 Brotli |
| `compress` | 完整 LZW（`.Z`） |
| `zstd` | 内置 Zstandard |
| `dcz` | 调用方提供 zstd 字典；缺字典 fail-closed |
| `aes128gcm` | RFC 8188 keying material；缺 key 或认证失败 fail-closed |
| `exi` | 见下 |
| `pack200-gzip` | 见下 |
| `identity` | 跳过 |

- 未知 coding → `STATUS_NOT_SUPPORTED`。  
- 字典 / AES keying material：经 `CodingDecodeMaterials` 或 `wknet::codec::DecodeMaterials`（静态表或回调）提供。  
- 公开解码入口：`wknet::codec::DecodeOne` / `DecodeChain` / `DecodeExi` / `DecodePack200`（`include/wknet/codec/Codec.h`）。

### 解压炸弹

- decoded aggregate 跟随响应缓冲或调用方 `MaxResponseBytes` / 目标容量。  
- **单级**膨胀比 ≤ 64；超限 → `STATUS_INVALID_NETWORK_RESPONSE`。  
- WebSocket `permessage-deflate` 另受 `MaxMessageBytes` 与同类膨胀约束。

### EXI 边界

- 范围：W3C EXI 1.0 Second Edition **无外部 Schema** 流。  
- 支持：四种 alignment、Options、保真项、内建 XML Schema 类型、`xsi:type` / `xsi:nil`。  
- 输出：Infoset 等价 XML。  
- **非目标 / 拒绝**：外部 Schema、strict grammar → `STATUS_NOT_SUPPORTED`。

### Pack200 边界

- 范围：Java 5–8 稳定格式 `150.7` / `160.1` / `170.1` / `171.0`。  
- 输入：裸 Pack200 或 gzip 包装；多 segment、class/file/bytecode、自定义 attribute layout、overflow index、常量池与 BCI relocation。  
- 输出：语义等价 JAR。  
- 专项测试使用离线语料并校验 `SHA256SUMS` 与 provenance。

## Transfer-Encoding

- 识别 `chunked` / `gzip` / `deflate` / `compress`，最多 4 级；反序解码。  
- `identity` → `STATUS_INVALID_NETWORK_RESPONSE`。  
- **`br` → `STATUS_NOT_SUPPORTED`**（`br` 只作为 Content-Encoding）。  
- 仅最外层 chunked 收 trailer；重复 `chunked`、带参数 token → 非法。  
- 请求侧用户手写 `Transfer-Encoding` / `TE` 一律拒绝；framing 由库生成。

## 公开 codec 面

命名空间 `wknet::codec`：

- `Coding` 枚举与上表 CE 对齐（含 `DictionaryCompressedZstd` / `Aes128Gcm` / `Exi` / `Pack200Gzip`）。  
- `ExternalMaterial`：字典与 AES-128-GCM keying material。  
- `DecodeOne`：单 coding；`DecodeChain`：按 CE 列表反序。  
- `DecodeExi` / `DecodePack200`：专项解码。  
- `DeflateRuntimeAvailable()`：探测内核 deflate 路径是否可用。

HTTP 层等价类型为 `ContentCoding` / `AcceptCoding` / `CodingDecodeMaterials`（`Types.h`），由会话在响应路径上调用同一解码逻辑。

## 公开 crypto 面与 CNG vs 软件

命名空间 `wknet::crypto`（头文件在 `include/wknet/crypto/`）。**优先内核态 CNG/BCrypt**；下列原语为内核内软件补齐。

| 原语 | 实现 |
|------|------|
| SHA-1/256/384/512、HMAC、HKDF | CNG（HKDF 基于 HMAC；Expand 限 `out≤digest×255`） |
| AES-GCM | CNG（tag 16；key 16/32） |
| ChaCha20-Poly1305 | **软件**（解密前常量时间验 tag） |
| AES-CCM / CCM8 | **软件** |
| NIST P-256/384/521 ECDH/ECDSA | CNG |
| X25519 / X448 | **软件** Montgomery ladder |
| FFDHE 2048–8192 | **软件**模幂（RFC 7919；公钥范围校验） |
| RSA-PKCS1 / RSA-PSS 验签 | CNG（PSS salt=摘要长；最小模数 **2048**） |
| Ed25519 / Ed448 验签 | **软件** PureEdDSA（完整消息，非预哈希 digest） |

公开入口摘要：

- `Aead`：`Encrypt` / `Decrypt`（`Aead.h`）  
- `KeyExchange`：密钥对与共享密钥（`KeyExchange.h`）  
- `Ed25519Verify` / `Ed448Verify`  
- `CngProviderCache`：会话级预打开 BCrypt 算法句柄；**软件路径不使用缓存**  
- `TlsClientCredential`：mTLS 签名回调，**私钥不进入库**

硬化惯例：密钥与中间量 `RtlSecureZeroMemory`；FFDHE 拒绝非法 `y`；SPKI/导入路径强制 RSA 下限。

## 与协议栈的关系

- HTTP 响应 CE 失败 → 请求失败（fail-closed），不会静默当 identity 用。  
- TLS 记录层与证书路径使用同一 crypto 原语；信任锚与 pin 由调用方提供（见 TLS 文档）。  
- 不把 WinHTTP / WinINet / SChannel 作为内核主路径。  
- 能力分类措辞以 [能力账本](capability-matrix.md) 为准。
