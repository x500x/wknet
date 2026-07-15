# 路线图

这里只记方向。已实现 / 默认关 / 安全拒绝 / 非目标的完整分类在 [能力账本](capability-matrix.md)，本页不复述。

## 当前主路径（已落地）

- 内核客户端：HTTP/1.1、HTTP/2、**HTTP/3（QUIC v1 + QPACK）**、WebSocket（含 RFC 8441 可选路径）。
- 传输 WSK + 密码学 CNG；TLS 1.2/1.3 自实现；信任锚调用方提供。
- H3 默认 `Auto`：从**已认证** Alt-Svc 学习后可优先 QUIC；代理/明文/WS/`NoVerify` 等不进入 H3。
- Session 拥有池、重定向（默认 10 跳）、安全方法 stale 重试一次、异步 4 线程队列。

## 刻意边界

- **客户端 only**；无 server / 入站 parser。
- 无 WinHTTP / SChannel 主路径；无独立 client 层。
- 在线 OCSP/CRL 抓取、磁盘 HTTP cache、H2 本地 priority 调度、WS 其它扩展、QUIC v2 / 迁移 / 多路径 / WebTransport / WS-over-H3 等为**非目标**（详见账本 §4）。
- 默认关的能力（pipeline、h2c、0-RTT、兼容 TLS、PING 保活等）见账本「默认关闭」一节；代码已有，只是默认不打开。

## 后续方向（摘要）

- 继续收紧超时、取消、帧/控制信令与恶意输入的有界防护；普通 buffered 响应默认不设过低的库级总量硬顶。
- 热路径减少重复分配（Workspace / lookaside / 连接常驻缓冲）。
- 代理路径：保持明文 absolute-form 与 HTTPS CONNECT 分离，审计 opaque 鉴权透传边界。
- H3/QUIC：互操作、性能与诊断增强；不以回退兼容层替代协议设计。

评估集成适用性时：先读 [架构](architecture.md)、[会话与连接池](session-and-pool.md)、[TLS 与信任](tls-and-trust.md)，再以 [能力账本](capability-matrix.md) 核对边界。
