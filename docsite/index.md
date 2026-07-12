# wknet

**面向 Windows 内核驱动的 HTTP/HTTPS/WebSocket 客户端库**

wknet 使用 WSK 作为内核主传输、CNG/BCrypt 作为密码学主路径，实现 HTTP/1.1、HTTP/2、WebSocket、TLS 1.2/1.3、证书校验与内容编解码。

- 公共 API：`wknet::http`、`wknet::websocket`、`wknet::crypto`、`wknet::codec`
- 内部分层：`rtl`、`net`、`tls`、`http1`、`http2`、`ws`、`transport`、`session`
- Trace 默认关闭；测试与 wknettest 设置为 Max
- 公共头只位于 `include/wknet`；内部实现头保持 src-local
- 不存在平行 client 类或兼容 API

## 导航

- [快速开始](getting-started.md) · [构建与测试](build-and-test.md)
- [能力账本](capability-matrix.md) · [架构](architecture.md)
- [HTTP/1.1](http1.md) · [HTTP/2](http2.md) · [WebSocket](websocket.md)
- [TLS 与证书](tls-and-certificates.md) · [密码学](cryptography.md)
- [产品 API](high-level-api.md) · [内部接口边界](low-level-api.md)
- [模块边界](client-classes.md) · [传输层](transport-layer.md)
- [连接池](connection-pool.md) · [异步模型](async-model.md) · [内存模型](memory-model.md)
