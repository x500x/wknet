# Configuration & Constants

Use `khttp::DefaultSessionConfig()` / `DefaultTlsConfig()` for value configs, and create per-call `SendOptions` with `SendOptionsCreate()`. The full field tables and default values are in the Chinese section (language-neutral). Highlights: response aggregation is unlimited by default (0 = unlimited and grows on heap), request buffer 16 KiB, WebSocket message default 1 MiB, pool capacity 8, max 2 connections per host, 30 s idle timeout, explicit HTTPS CONNECT proxy support, TLS 1.2–1.3 with `Verify`, 120 s handshake timeout, ALPN prefers HTTP/2.

The low-level `KhSessionOptions` has **no** Default factory (zero-init and set explicitly) and adds `MaxResponseHeaders` (64, configurable up to 200) and `Http2MaxHeaderBlockBytes` (32 KiB, up to 64 KiB).

Global constants (`KernelHttpConfig.h`) include the pool tag `'ptHK'`, WSK timeouts (3 s capture / 30 s op / 3 s close), TLS handshake deadline 120 s, minimum RSA modulus 2048 bits, and anti-flood/parse limits (max header line 8192, header section 65536, 200 headers, 8192 chunks, 256 trailers, 100 control frames per receive). Engine defaults mirror these in `engine/Engine.h`.
