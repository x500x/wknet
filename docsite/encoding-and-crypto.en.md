# Encoding & Crypto

Decode policy for Content-Encoding / Transfer-Encoding, plus the public codec / crypto surface. Product paths usually reach these through HTTP/TLS; for direct calls see [Codec & Crypto API](api/codec-crypto.md).

## Summary

| Topic | Behavior |
|-------|----------|
| Content-Encoding | `gzip` `deflate` `br` `compress` `zstd` `dcz` `aes128gcm` `exi` `pack200-gzip` `identity` |
| Chain length | At most **2** codings; decoded in **reverse** order |
| Decompression bomb | Per-step expansion ≤ **64** (`MaxDecodeExpansionRatio`); aggregate follows response/caller capacity |
| Transfer-Encoding | `chunked`/`gzip`/`deflate`/`compress` (≤4); **`br` only as Content-Encoding** |
| EXI | Schema-less streams → Infoset-equivalent XML; external Schema/strict → `STATUS_NOT_SUPPORTED` |
| Pack200 | Java 5–8 stable formats → semantically equivalent JAR |
| Crypto | CNG first; ChaCha/CCM/X25519/X448/FFDHE/Ed* are in-kernel software |

## Content-Encoding

When the caller supplies no `Accept-Encoding`, the engine injects  
`gzip, deflate, br, zstd, identity` (or `br, identity` if deflate is unavailable at runtime).  
`SendOptions.AcceptEncodingPreferences` may carry qvalues and drive **fail-closed** response CE validation (including `identity;q=0` / `*;q=0`).

| coding | Notes |
|--------|-------|
| `gzip` | RFC 1952; verifies header CRC16, trailer CRC32, ISIZE |
| `deflate` | zlib autodetection + Adler-32; raw DEFLATE uses the kernel path with `DeflateRuntimeAvailable` probe |
| `br` | Bundled Brotli |
| `compress` | Full LZW (`.Z`) |
| `zstd` | Bundled Zstandard |
| `dcz` | Caller-provided zstd dictionary; missing dictionary fails closed |
| `aes128gcm` | RFC 8188 keying material; missing key or auth failure fails closed |
| `exi` | See below |
| `pack200-gzip` | See below |
| `identity` | No-op |

- Unknown coding → `STATUS_NOT_SUPPORTED`.  
- Dictionaries / AES keying material: via `CodingDecodeMaterials` or `wknet::codec::DecodeMaterials` (static table or callback).  
- Public decode entry points: `wknet::codec::DecodeOne` / `DecodeChain` / `DecodeExi` / `DecodePack200` (`include/wknet/codec/Codec.h`).

### Decompression bombs

- Decoded aggregate follows the response buffer or caller `MaxResponseBytes` / destination capacity.  
- **Per-step** expansion ratio ≤ 64; over limit → `STATUS_INVALID_NETWORK_RESPONSE`.  
- WebSocket `permessage-deflate` is additionally bounded by `MaxMessageBytes` and the same class of expansion limits.

### EXI bounds

- Scope: W3C EXI 1.0 Second Edition **schema-less** streams.  
- Supported: all four alignments, Options, fidelity features, built-in XML Schema types, `xsi:type` / `xsi:nil`.  
- Output: Infoset-equivalent XML.  
- **Unsupported / refused**: external Schema or strict grammar → `STATUS_NOT_SUPPORTED`.

### Pack200 bounds

- Scope: Java 5–8 stable formats `150.7` / `160.1` / `170.1` / `171.0`.  
- Input: raw Pack200 or gzip-wrapped; multi-segment, class/file/bytecode, custom attribute layouts, overflow indexes, constant-pool and BCI relocation.  
- Output: a semantically equivalent JAR.  
- Dedicated tests load offline corpora and verify `SHA256SUMS` plus provenance.

## Transfer-Encoding

- Recognizes `chunked` / `gzip` / `deflate` / `compress`, up to 4 codings; reverse-decoded.  
- `identity` → `STATUS_INVALID_NETWORK_RESPONSE`.  
- **`br` → `STATUS_NOT_SUPPORTED`** (`br` is Content-Encoding only).  
- Only the outermost chunked layer accepts trailers; repeated `chunked` or parameterized tokens are illegal.  
- Caller-supplied request `Transfer-Encoding` / `TE` is always rejected; framing is library-generated.

## Public codec surface

Namespace `wknet::codec`:

- `Coding` enum aligns with the CE table above (including `DictionaryCompressedZstd` / `Aes128Gcm` / `Exi` / `Pack200Gzip`).  
- `ExternalMaterial`: dictionary and AES-128-GCM keying material.  
- `DecodeOne`: single coding; `DecodeChain`: reverse CE-list order.  
- `DecodeExi` / `DecodePack200`: specialized decoders.  
- `DeflateRuntimeAvailable()`: probes whether the kernel deflate path is usable.

HTTP-layer equivalents are `ContentCoding` / `AcceptCoding` / `CodingDecodeMaterials` (`Types.h`); the session invokes the same decode logic on the response path.

## Public crypto surface and CNG vs software

Namespace `wknet::crypto` (headers under `include/wknet/crypto/`). **Kernel CNG/BCrypt is preferred**; the primitives below are filled in by in-kernel software.

| Primitive | Implementation |
|-----------|----------------|
| SHA-1/256/384/512, HMAC, HKDF | CNG (HKDF on HMAC; Expand limited to `out≤digest×255`) |
| AES-GCM | CNG (tag 16; key 16/32) |
| ChaCha20-Poly1305 | **Software** (constant-time tag check before decrypt) |
| AES-CCM / CCM8 | **Software** |
| NIST P-256/384/521 ECDH/ECDSA | CNG |
| X25519 / X448 | **Software** Montgomery ladder |
| FFDHE 2048–8192 | **Software** modexp (RFC 7919; public-key range checks) |
| RSA-PKCS1 / RSA-PSS verify | CNG (PSS salt = digest length; min modulus **2048**) |
| Ed25519 / Ed448 verify | **Software** PureEdDSA (full message, not a pre-hash digest) |

Public entry summary:

- `Aead`: `Encrypt` / `Decrypt` (`Aead.h`)  
- `KeyExchange`: key pairs and shared secrets (`KeyExchange.h`)  
- `Ed25519Verify` / `Ed448Verify`  
- `CngProviderCache`: session-scoped pre-opened BCrypt algorithm handles; **software paths do not use the cache**  
- `TlsClientCredential`: mTLS sign callback; private keys remain with the caller

Hardening habits: `RtlSecureZeroMemory` on keys and intermediates; FFDHE rejects illegal `y`; SPKI/import paths enforce the RSA floor.

## Relation to the stack

- Failed HTTP response CE → request failure (fail-closed); never silently treated as identity.  
- The TLS record layer and certificate path use the same crypto primitives; trust anchors and pins are caller-supplied (see TLS docs).  
- WinHTTP / WinINet / SChannel are not the kernel main path.  
- See the [capability matrix](capability-matrix.md) for support scope.
