# KernelHttp Wiki

**面向 Windows 内核驱动的纯内核态 HTTP/HTTPS 客户端库**

KernelHttp 是一个纯内核态的 HTTP/HTTPS 客户端库，专为 Windows 内核驱动开发设计。它从底层开始构建，实现了内核可用的客户端协议栈：HTTP/1.1、HTTP/2、WebSocket，以及 TLS 1.2/1.3 握手、记录保护和证书验证。

- 🔒 **纯内核态**：不依赖 WinHTTP / WinINet / SChannel
- 🌐 **WSK 传输** + 🔐 **CNG/BCrypt 密码学**
- 🎯 **两层 API**：高层 `khttp` / `kws` 与底层 `engine`（`Kh*`）
- 🔄 连接池、异步、证书锁定、响应解码（gzip/deflate/br/compress）

### 📚 导航

**入门**
- [快速开始](getting-started.md) · [构建与测试](build-and-test.md)

**协议参考**
- [能力边界](capability-matrix.md)（**必读**）· [架构总览](architecture.md)
- [HTTP/1.1 协议](http1.md) · [HTTP/2 与 HPACK](http2.md) · [WebSocket 协议](websocket.md)
- [TLS 与证书](tls-and-certificates.md) · [密码学层](cryptography.md)

**API 参考**
- [高层 API（khttp/kws）](high-level-api.md) · [底层 API（engine）](low-level-api.md)
- [配置项与常量](configuration.md) · [客户端类](client-classes.md)
- [传输层（ITransport/WSK）](transport-layer.md) · [NTSTATUS 错误码](ntstatus-reference.md)

**机制**
- [连接池](connection-pool.md) · [异步模型](async-model.md) · [内存模型](memory-model.md)

**实战 / 项目**
- [Cookbook 样例](cookbook.md) · [常见问题 FAQ](faq.md)
- [路线图与非目标](roadmap.md) · [术语表](glossary.md) · [贡献指南](contributing.md)
