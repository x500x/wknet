# 常见问题 / FAQ

[English](#english) | 简体中文

---

## 简体中文

**Q：为什么不直接用 WinHTTP / WinINet / SChannel？**
A：本项目定位为内核驱动可用的纯内核态协议栈。这些组件并非内核主路径可依赖的对象，因此 HTTP/HTTPS、TLS record/handshake、证书校验都按内核自实现路线推进。传输层优先 WSK，密码学优先 CNG/BCrypt。

**Q：调用必须在什么 IRQL？**
A：同步 HTTP、WebSocket、TLS 和证书验证路径都要求在 `PASSIVE_LEVEL` 调用；RAII 守卫的析构同样要求 `PASSIVE_LEVEL`（它会调用 Release/Close）。

**Q：是否支持服务端 / 入站请求解析？**
A：不支持。项目定位为客户端协议栈，不提供入站 request parser / server role。

**Q：支持 HTTP 代理 / CONNECT / TRACE 吗？**
A：不在当前内核客户端主路径内。

**Q：为什么我的 0-RTT 没有生效 / 返回 `STATUS_NOT_SUPPORTED`？**
A：TLS 1.3 0-RTT 默认关闭；即使启用 early data，也必须由调用方显式声明该请求 replay-safe，否则返回 `STATUS_NOT_SUPPORTED` 且不发送 early data。

**Q：能关闭证书校验吗？**
A：技术上有 `CertPolicy::NoVerify`，但生产环境严禁使用。样例一律演示开启校验。

**Q：POST 失败后会自动重试吗？**
A：不会。reused stale 连接失败只对 `GET`/`HEAD`/`OPTIONS` 等安全/幂等请求自动 fresh retry；POST/PUT/PATCH/DELETE 不会自动重放。

**Q：为什么 HTTPS 自动跳转到 HTTP 被拒绝？**
A：自动 redirect 默认拒绝 HTTPS→HTTP 降级；跨 scheme/host/port 还会清理 `Authorization`、`Cookie`、`Proxy-Authorization`。

**Q：支持 WebSocket over HTTP/2（RFC 8441）吗？**
A：不支持，已延期；WebSocket 主路径是 HTTP/1.1 Upgrade。permessage-deflate 等扩展也不在目标内。

**Q：库为什么不让用栈 / new-delete？**
A：内核环境约束。库内禁止用栈（请用堆，高频缓冲常驻 Workspace），`new/delete` 也不直接用（除非在 lib 内重载）。统一用 `HeapObject<T>` / `HeapArray<T>`。

**Q：用了异步 API，卸载驱动要注意什么？**
A：卸载前必须 `engine::KhEngineDrainAsync()` 等待异步 worker 结束，再释放 WSK。

---

## English

**Q: Why not just use WinHTTP / WinINet / SChannel?**
A: This is a pure kernel-mode stack for kernel drivers. Those components are not dependable on the kernel main path, so HTTP/HTTPS, TLS record/handshake, and certificate validation are self-implemented. Transport prefers WSK, cryptography prefers CNG/BCrypt.

**Q: What IRQL must I call at?**
A: Synchronous HTTP, WebSocket, TLS, and certificate validation require `PASSIVE_LEVEL`; RAII guard destruction also requires `PASSIVE_LEVEL` (it calls Release/Close).

**Q: Server / inbound request parsing?**
A: Not supported — this is a client protocol stack.

**Q: HTTP proxy / CONNECT / TRACE?**
A: Outside the current kernel client main path.

**Q: Why is my 0-RTT ignored / returning `STATUS_NOT_SUPPORTED`?**
A: TLS 1.3 0-RTT is off by default; even with early data enabled, the caller must mark the request replay-safe, otherwise it returns `STATUS_NOT_SUPPORTED` and sends no early data.

**Q: Can I disable certificate verification?**
A: `CertPolicy::NoVerify` exists but must never be used in production. Samples always verify.

**Q: Are failed POSTs retried automatically?**
A: No. Only safe/idempotent `GET`/`HEAD`/`OPTIONS` get a fresh retry on reused stale connections; POST/PUT/PATCH/DELETE are never replayed.

**Q: Why is an HTTPS→HTTP redirect rejected?**
A: Auto-redirect rejects HTTPS→HTTP downgrade by default and strips `Authorization`/`Cookie`/`Proxy-Authorization` across scheme/host/port.

**Q: WebSocket over HTTP/2 (RFC 8441)?**
A: Not supported (deferred); the WebSocket main path is HTTP/1.1 Upgrade. Extensions like permessage-deflate are out of scope.

**Q: Why no stack / new-delete in the library?**
A: Kernel constraints. The library forbids stack buffers (use heap; hot buffers resident in Workspace) and raw `new/delete` (unless overloaded in the lib). Use `HeapObject<T>` / `HeapArray<T>`.

**Q: Anything special on driver unload after async APIs?**
A: Call `engine::KhEngineDrainAsync()` before releasing WSK.
