# Configuration & Constants

Use `wknet::http::DefaultSessionConfig()` / `DefaultTlsConfig()` for value configs, and create per-call `SendOptions` with `SendOptionsCreate()`. The full field tables and default values are in the Chinese section (language-neutral). Highlights: response aggregation is unlimited by default (0 = unlimited and grows on heap), request buffer 16 KiB, WebSocket message default 1 MiB, pool capacity 8, max 2 connections per host, 30 s idle timeout, explicit HTTP proxy support (HTTPS CONNECT and plaintext absolute-form), session opt-in HTTP/1.1 pipelining through `EnableHttp11Pipeline`, TLS 1.2–1.3 with `Verify`, 120 s handshake timeout, ALPN prefers HTTP/2, HTTP/2 background PING keepalive is session opt-in through `Http2KeepAlive`, and per-call options can explicitly set h2c mode plus HTTP/2 per-request priority.

Internal session options add `MaxResponseHeaders` (64, configurable up to 200) and `Http2MaxHeaderBlockBytes` (32 KiB, up to 64 KiB). They are source-local and not a second public API. HTTP/1.1 pipelining uses the public session fields `EnableHttp11Pipeline`, `Http11PipelineMaxDepth`, and `Http11PipelineMethodMask`.

Global constants in `WknetConfig.h`, `WknetLimits.h`, and source-local session headers define the pool tag `'tenW'`, WSK/TLS timeouts, minimum RSA modulus, and anti-flood/parse limits.
