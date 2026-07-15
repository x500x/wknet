# Session & Pool

`Session` owns request policy and resources: TLS defaults, proxy, HTTP/2 keepalive, HTTP/3, connection-pool quotas, and an optional RFC 9111 in-memory cache. Per-send `SendOptions` may override TLS, connection policy, redirect limits, and similar knobs without creating a second lifecycle.

## Session defaults (caller view)

| Field | Default | Notes |
|-------|---------|-------|
| `PoolCapacity` | 8 | Pool slot limit (hard cap is an implementation constant) |
| `MaxConnsPerHost` | 2 | Concurrent connections per host |
| `IdleTimeoutMs` | 30000 | Idle eviction; `0` disables idle-based eviction |
| `EnableHttp11Pipeline` | false | Explicit opt-in |
| `Http2KeepAlive.Enabled` | false | Explicit opt-in |
| `Http3.Mode` | **Auto** | Prefer H3 after learning authenticated Alt-Svc |
| `Tls` | TLS 1.2–1.3, `CertPolicy::Verify` | Trust anchors come from `Tls.Store` |
| `Proxy.Enabled` | false | Configure Host/Port/Authority/AuthHeader explicitly |
| `Cache` | nullptr | Caller attaches an in-memory cache object |

`ResponsePool` currently accepts only `NonPaged`; `Paged` is a reserved ABI value and is rejected at create time.

## Pool keys and quotas

Match keys include scheme, host, port, address family, TLS version/policy/certificate identity, SNI, ALPN, and proxy identity. Auto-ALPN requests may reuse same-origin connections after the negotiated ALPN is written back.

**Per-host quota** keys are coarser (scheme+host+port+family, ignoring TLS/ALPN). On overflow the pool first tries to close an idle same-host connection; if still over quota it returns `STATUS_INSUFFICIENT_RESOURCES`.

## Acquire / Release

| `ConnPolicy` | Behavior |
|--------------|----------|
| `ReuseOrCreate` (default) | Prefer reuse; return to pool when successful and reusable |
| `ForceNew` | Always create; close on release |
| `NoPool` | Bypass the pool; **never displaces active connections**; close on release |

- HTTP/2: same-origin connections may share multiple stream leases up to local/peer concurrency limits.
- HTTP/3: the pool does not merge across origins. Alternatives are used for DNS/UDP only; SNI, certificates, and `:authority` remain bound to the origin.
- These responses are not returned to the pool: close-delimited bodies, status **101**, `Connection: close`, unread bytes, non-keep-alive HTTP/1.0, and H2/H3 connections the protocol marks non-reusable.
- Idle eviction runs lazily at acquire when `IdleTimeoutMs ≠ 0` (no background timer).

## Safe retry and redirects

**Stale-connection retry** (exactly once, rebuilt with `ForceNew`):

- Methods limited to **`GET` / `HEAD` / `OPTIONS`**
- Failure on a reused connection with `ReuseOrCreate`
- Status is a connection-close family, `STATUS_RETRY`, or `STATUS_IO_TIMEOUT`
- `POST` / `PUT` / `PATCH` / `DELETE` are **never** auto-replayed

**HTTP/2 GOAWAY / `REFUSED_STREAM`**: unprocessed streams may surface `STATUS_RETRY`; the high level again fresh-retries safe methods only once.

**Redirects** (`MaxRedirects` defaults to **10**; disable with `SendFlagDisableAutoRedirect`):

- 301/302: POST→GET only; 303: →GET except HEAD; 307/308: keep method and body
- Cross-origin clears `Authorization` / `Cookie` / `Proxy-Authorization`
- **HTTPS→HTTP is rejected by default**
- **Exhausted hop count is not an error** — the current 3xx is returned for the caller to handle `Location`

## Proxy

`ProxyConfig`: `Host` / `Port` / `Family` / `Authority` / `AuthHeader`.

- HTTPS: HTTP/1.1 **CONNECT** tunnel, then TLS
- Cleartext HTTP over proxy: absolute-form request-target, no CONNECT
- `Proxy-Authorization` comes only from the explicit opaque configured value
- When a proxy is enabled, HTTP/3 Auto does not select H3

## HTTP/3 and the pool

Default `Http3ConnectMode::Auto`:

1. Without prior knowledge, the first HTTPS request uses TCP TLS
2. Only an exact `h3` Alt-Svc from a response that already passed certificate and TLS-policy checks is cached
3. Later requests with the same security identity may prefer H3; on probe failure, TCP fallback is allowed only while the request is still unsent or the one-replay safety rules apply

`Disabled` turns learning and use off; `Required` is prior-knowledge (no Alt-Svc read, no automatic TCP fallback). Details: [HTTP/3 & QUIC](http3-quic.en.md).
