# 术语表 / Glossary

[English](#english) | 简体中文

---

## 简体中文

| 术语 | 含义 |
|------|------|
| **WSK** | Windows Sockets Kernel，内核态 socket 框架；本库网络主路径（[传输层](transport-layer.md)） |
| **CNG / BCrypt** | Cryptography Next Generation，内核态密码学；本库密码学主路径（[密码学层](cryptography.md)） |
| **SChannel** | 系统 TLS 实现；本库**不**用它，TLS 自实现 |
| **IRQL** | Interrupt Request Level；同步 HTTP/WS/TLS/证书路径要求 `PASSIVE_LEVEL` |
| **PASSIVE_LEVEL** | 最低 IRQL，可阻塞等待、分页可用；本库同步 API 的调用前提 |
| **NTSTATUS** | 内核统一返回码；用 `NT_SUCCESS()` 判断（[错误码](ntstatus-reference.md)） |
| **ITransport** | 字节流传输抽象，统一明文/TLS（[传输层](transport-layer.md)） |
| **Workspace** | 会话常驻的可复用缓冲集合，避免反复分配（[内存模型](memory-model.md)） |
| **HeapObject / HeapArray** | RAII 堆封装，替代裸 `new/delete` |
| **连接池 / Pool** | 连接复用，按 `KhConnectionPoolKey` 匹配（[连接池](connection-pool.md)） |
| **khttp / kws / engine** | 高层 HTTP / 高层 WebSocket / 底层 ABI 命名空间 |
| **ALPN** | Application-Layer Protocol Negotiation；协商 `h2` / `http/1.1` |
| **SNI** | Server Name Indication；TLS 握手中的目标主机名 |
| **h2 / h2c** | HTTP/2 over TLS / HTTP/2 明文（prior knowledge 或 Upgrade） |
| **HPACK** | HTTP/2 头压缩（RFC 7541），含 Huffman + 动态表（[HTTP/2](http2.md)） |
| **AEAD** | 带关联数据的认证加密（AES-GCM / ChaCha20-Poly1305 / AES-CCM） |
| **HKDF** | 基于 HMAC 的密钥派生（TLS 1.3 密钥调度） |
| **ECDHE / DHE** | (椭圆曲线) 临时 Diffie-Hellman 密钥交换 |
| **SPKI pin** | Subject Public Key Info 哈希锁定，用于证书锁定（[TLS 与证书](tls-and-certificates.md)） |
| **Trust Anchor** | 信任锚，链校验的可信根 |
| **0-RTT / early data** | TLS 1.3 提前数据；默认关闭，需显式 replay-safe |
| **Session Ticket** | TLS 会话恢复票据（1.2/1.3 缓存） |
| **chunked** | HTTP/1.1 分块传输编码 |
| **close-delimited** | 以连接关闭界定 body 结束的 HTTP/1.x 响应；不回连接池 |
| **Drain** | `KhEngineDrainAsync`，卸载前等待在飞异步操作（[异步模型](async-model.md)） |
| **WDK** | Windows Driver Kit，构建内核驱动所需 |

---

## English

| Term | Meaning |
|------|---------|
| **WSK** | Windows Sockets Kernel — the network main path |
| **CNG / BCrypt** | Kernel cryptography — the crypto main path |
| **SChannel** | System TLS; **not** used here (TLS is self-implemented) |
| **IRQL / PASSIVE_LEVEL** | Interrupt Request Level; sync HTTP/WS/TLS/cert paths require `PASSIVE_LEVEL` |
| **NTSTATUS** | Kernel return code; test with `NT_SUCCESS()` |
| **ITransport** | Byte-stream transport abstraction (plaintext/TLS) |
| **Workspace** | Session-resident reusable buffers |
| **HeapObject / HeapArray** | RAII heap wrappers replacing raw new/delete |
| **Connection pool** | Connection reuse keyed by `KhConnectionPoolKey` |
| **khttp / kws / engine** | High-level HTTP / high-level WebSocket / low-level ABI namespaces |
| **ALPN / SNI** | Protocol negotiation (`h2`/`http/1.1`) / target hostname in TLS |
| **h2 / h2c** | HTTP/2 over TLS / cleartext HTTP/2 |
| **HPACK** | HTTP/2 header compression (RFC 7541) |
| **AEAD / HKDF / ECDHE** | Authenticated encryption / HMAC key derivation / ephemeral DH |
| **SPKI pin / Trust Anchor** | Public-key-hash pinning / trusted chain root |
| **0-RTT / Session Ticket** | TLS 1.3 early data (off by default) / resumption ticket |
| **chunked / close-delimited** | HTTP/1.1 chunked encoding / body ended by connection close (not pooled) |
| **Drain** | `KhEngineDrainAsync` — wait for in-flight async before unload |
| **WDK** | Windows Driver Kit |
