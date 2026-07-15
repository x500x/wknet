# 术语表

| 术语 | 含义 |
|------|------|
| **wknet** | 本库：Windows 内核态 HTTP/WebSocket 客户端协议栈 |
| **WSK** | Windows Sockets Kernel；传输主路径 |
| **CNG / BCrypt** | 内核密码学 API；密码学主路径 |
| **SChannel / WinHTTP / WinINet** | 系统 TLS/HTTP 组件；**本库主路径不使用** |
| **IRQL / PASSIVE_LEVEL** | 中断请求级；同步 HTTP/WS/TLS/证书路径要求 `PASSIVE_LEVEL` |
| **NTSTATUS** | 内核返回码；用 `NT_SUCCESS()` 判断（见 [错误码与 FAQ](errors-and-faq.md)） |
| **Session** | 策略与资源所有者：池、TLS 默认、代理、H3、可选 cache |
| **连接池** | 按 origin/TLS/代理身份复用连接；close-delimited 与 101 不回池 |
| **ConnPolicy** | `ReuseOrCreate` / `ForceNew` / `NoPool` |
| **Transport** | opaque 字节流服务，统一明文与 TLS I/O |
| **Workspace** | 会话常驻可复用缓冲，减少热路径分配 |
| **ALPN** | TLS 应用层协议协商（如 `h2`、`http/1.1`） |
| **SNI** | TLS 目标主机名扩展 |
| **h2 / h2c** | HTTP/2 over TLS / 明文 HTTP/2（prior knowledge 或 Upgrade，默认关） |
| **HPACK / QPACK** | HTTP/2 / HTTP/3 头压缩 |
| **Alt-Svc** | 替代服务通告；H3 Auto **仅从已认证 HTTPS 响应**学习精确 `h3` |
| **HTTP/3 / QUIC** | 基于 UDP/QUIC v1 的 HTTP；默认 Auto 主路径之一 |
| **AEAD** | 认证加密（AES-GCM、ChaCha20-Poly1305 等） |
| **Trust Anchor** | 调用方提供的信任锚；库不硬编码系统 CA |
| **SPKI pin** | 叶证书 Subject Public Key Info 哈希锁定 |
| **0-RTT / early data** | TLS 1.3 提前数据；默认关，须声明 replay-safe |
| **chunked** | HTTP/1.1 分块传输编码（库生成请求 framing） |
| **close-delimited** | 以连接关闭结束 body 的响应；**不回池** |
| **stale retry** | 复用连接失败后对 GET/HEAD/OPTIONS 恰好一次的 ForceNew 重试 |
| **RFC 8441** | WebSocket over HTTP/2 extended CONNECT |
| **Drain / Destroy** | 卸载前排空在飞异步操作：`wknet::http::Destroy()` |
| **WDK** | Windows Driver Kit |

能力分类见 [能力账本](capability-matrix.md)。
