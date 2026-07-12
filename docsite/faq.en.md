# FAQ

**Q: Why not just use WinHTTP / WinINet / SChannel?**
A: This is a pure kernel-mode stack for kernel drivers. Those components are not dependable on the kernel main path, so HTTP/HTTPS, TLS record/handshake, and certificate validation are self-implemented. Transport prefers WSK, cryptography prefers CNG/BCrypt.

**Q: What IRQL must I call at?**
A: Synchronous HTTP, WebSocket, TLS, and certificate validation require `PASSIVE_LEVEL`; RAII guard destruction also requires `PASSIVE_LEVEL` (it calls Release/Close).

**Q: Server / inbound request parsing?**
A: Not supported — this is a client protocol stack.

**Q: HTTP proxy / CONNECT / TRACE?**
A: Yes. High-level `SessionConfig.Proxy` / low-level `KhSessionOptions.Proxy` configure proxy address, authority, and an opaque `Proxy-Authorization` value. HTTPS uses an HTTP/1.1 CONNECT tunnel; plaintext HTTP over proxy sends an absolute-form request target without CONNECT. TRACE requires explicit `SendFlagAllowTrace`, and bodies, trailers, and sensitive headers are still rejected.

**Q: Why is my 0-RTT ignored / returning `STATUS_NOT_SUPPORTED`?**
A: TLS 1.3 0-RTT is off by default; even with early data enabled, the caller must mark the request replay-safe, otherwise it returns `STATUS_NOT_SUPPORTED` and sends no early data.

**Q: Can I disable certificate verification?**
A: `CertPolicy::NoVerify` exists but must never be used in production. Samples always verify.

**Q: Are failed POSTs retried automatically?**
A: No. Only safe/idempotent `GET`/`HEAD`/`OPTIONS` get a fresh retry on reused stale connections; POST/PUT/PATCH/DELETE are never replayed.

**Q: Why is an HTTPS→HTTP redirect rejected?**
A: Auto-redirect rejects HTTPS→HTTP downgrade by default and strips `Authorization`/`Cookie`/`Proxy-Authorization` across scheme/host/port.

**Q: WebSocket over HTTP/2 (RFC 8441)?**
A: Yes, and `wss` uses automatic selection by default. The client offers `h2,http/1.1` and uses RFC 8441 extended CONNECT when h2 is negotiated and the peer enables `SETTINGS_ENABLE_CONNECT_PROTOCOL`; Auto returns to HTTP/1.1 Upgrade when RFC 8441 is unsupported, `Http11Only` forces HTTP/1.1, and `ws://` does not implicitly use h2c. `permessage-deflate` is still explicit opt-in and remains off by default; unrequested or invalid extensions are rejected.

**Q: Why no stack / new-delete in the library?**
A: Kernel constraints. The library forbids stack buffers (use heap; hot buffers resident in Workspace) and raw `new/delete` (unless overloaded in the lib). Use `HeapObject<T>` / `HeapArray<T>`.

**Q: Anything special on driver unload after async APIs?**
A: Call `wknet::http::Destroy()` before releasing WSK. Synchronous-only paths do not require it, but may call it unconditionally.
