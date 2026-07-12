# 常见问题

**Q：为什么不直接用 WinHTTP / WinINet / SChannel？**
A：本项目定位为内核驱动可用的纯内核态协议栈。这些组件并非内核主路径可依赖的对象，因此 HTTP/HTTPS、TLS record/handshake、证书校验都按内核自实现路线推进。传输层优先 WSK，密码学优先 CNG/BCrypt。

**Q：调用必须在什么 IRQL？**
A：同步 HTTP、WebSocket、TLS 和证书验证路径都要求在 `PASSIVE_LEVEL` 调用；RAII 守卫的析构同样要求 `PASSIVE_LEVEL`（它会调用 Release/Close）。

**Q：是否支持服务端 / 入站请求解析？**
A：不支持。项目定位为客户端协议栈，不提供入站 request parser / server role。

**Q：支持 HTTP 代理 / CONNECT / TRACE 吗？**
A：支持。`SessionConfig.Proxy` 可配置代理地址、authority 和 opaque `Proxy-Authorization` 值；HTTPS 走 HTTP/1.1 CONNECT 隧道，明文 HTTP over proxy 发送 absolute-form request target，不建立 CONNECT。

**Q：为什么我的 0-RTT 没有生效 / 返回 `STATUS_NOT_SUPPORTED`？**
A：TLS 1.3 0-RTT 默认关闭；即使启用 early data，也必须由调用方显式声明该请求 replay-safe，否则返回 `STATUS_NOT_SUPPORTED` 且不发送 early data。

**Q：能关闭证书校验吗？**
A：技术上有 `CertPolicy::NoVerify`，但生产环境严禁使用。样例一律演示开启校验。

**Q：POST 失败后会自动重试吗？**
A：不会。reused stale 连接失败只对 `GET`/`HEAD`/`OPTIONS` 等安全/幂等请求自动 fresh retry；POST/PUT/PATCH/DELETE 不会自动重放。

**Q：为什么 HTTPS 自动跳转到 HTTP 被拒绝？**
A：自动 redirect 默认拒绝 HTTPS→HTTP 降级；跨 scheme/host/port 还会清理 `Authorization`、`Cookie`、`Proxy-Authorization`。

**Q：支持 WebSocket over HTTP/2（RFC 8441）吗？**
A：支持，且 `wss` 默认自动选择。默认会 offer `h2,http/1.1`，协商到 h2 且对端启用 `SETTINGS_ENABLE_CONNECT_PROTOCOL` 时走 RFC 8441 extended CONNECT；不支持时按 Auto 规则回到 HTTP/1.1 Upgrade，显式 `Http11Only` 可强制 HTTP/1.1，`ws://` 不隐式走 h2c。`permessage-deflate` 支持显式 opt-in，但默认关闭；未请求或非法扩展会拒绝。

**Q：WebSocket 支持分片吗？**
A：支持。发送用 `wknet::websocket::SendContinuation`（或 `SendTextEx/SendBinaryEx` 传 `FinalFragment=false`），接收用 `wknet::websocket::ReceiveOptions.OnMessage` 回调逐片处理；不设回调则默认聚合为完整消息。文本会跨分片做增量 UTF-8 校验。

**Q：重定向次数用尽会怎样？**
A：达到最大跳数（默认 10）时**不报错**，直接把当前那个 3xx 响应返回给你，由你自行处理 `Location`。

**Q：WebSocket API 到底在哪个命名空间？**
A：`wknet::websocket`（`Connect`/`SendText`/`Receive`/`Close`），头文件 `<wknet/websocket/WebSocket.h>`。Session 仍是 `wknet::http::Session`。

**Q：库为什么不让用栈 / new-delete？**
A：内核环境约束。库内禁止用栈（请用堆，高频缓冲常驻 Workspace），`new/delete` 也不直接用（除非在 lib 内重载）。统一用 `HeapObject<T>` / `HeapArray<T>`。

**Q：用了异步 API，卸载驱动要注意什么？**
A：高层调用方卸载前调用 `wknet::http::Destroy()` 等待异步 worker 结束，再释放 WSK。同步-only 路径可不调用，但可无条件调用。
