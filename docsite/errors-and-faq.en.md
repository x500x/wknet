# Errors & FAQ

Check `NT_SUCCESS(status)` first, then branch by scenario. Release/Close accept `nullptr` — free on failure paths too.

## Common NTSTATUS values

### General

| NTSTATUS | Typical meaning |
|----------|-----------------|
| `STATUS_SUCCESS` | Success (prefer `NT_SUCCESS`; do not only compare `== SUCCESS`) |
| `STATUS_INVALID_PARAMETER` | Bad URL, forbidden header, out-of-range config, `Paged` pool type, etc. |
| `STATUS_NOT_SUPPORTED` | Unsupported scheme, caller TE, 0-RTT without replay-safe, WS 3xx/401/407, disabled capability |
| `STATUS_INSUFFICIENT_RESOURCES` | Allocation failure, async queue full (256), per-host connection quota |
| `STATUS_INTEGER_OVERFLOW` | Length/size arithmetic overflow |
| `STATUS_INVALID_DEVICE_REQUEST` | Call not at **PASSIVE_LEVEL** |
| `STATUS_INVALID_DEVICE_STATE` | Bad handle state, WSK not ready, sequence overflow |
| `STATUS_DEVICE_NOT_READY` | WSK not initialized / async runtime stopped |

### Network / HTTP

| NTSTATUS | Typical meaning |
|----------|-----------------|
| `STATUS_IO_TIMEOUT` | Send/receive/handshake/wait timeout |
| `STATUS_CONNECTION_DISCONNECTED` | Peer close, short write, non-zero GOAWAY, RST |
| `STATUS_BUFFER_TOO_SMALL` | Response over `MaxResponseBytes`, WS message over limit, buffer too small |
| `STATUS_INVALID_NETWORK_RESPONSE` | Protocol violation (status/headers/frames/HPACK/obs-fold/decode failure) |
| `STATUS_RETRY` | Retryable (e.g. clean GOAWAY for unprocessed stream); high level auto-retries safe methods once |
| `STATUS_CANCELLED` | Async cancel completed |
| `STATUS_NOT_FOUND` | No resolved address / no response to take |

### TLS / certificates

| NTSTATUS | Typical meaning |
|----------|-----------------|
| `STATUS_TRUST_FAILURE` | Chain/validity/hostname/pin/anchor/revocation fail-closed |
| `STATUS_INVALID_SIGNATURE` | MAC / AEAD / CBC MAC failure |
| `STATUS_NOT_SUPPORTED` | Version/policy refusal, weak algorithms, 0-RTT policy |

```cpp
NTSTATUS s = wknet::http::GetEx(session, url, urlLen, nullptr, nullptr, &resp);
if (!NT_SUCCESS(s)) {
    switch (s) {
    case STATUS_IO_TIMEOUT:              /* timeout policy */ break;
    case STATUS_TRUST_FAILURE:           /* check Store/hostname/revocation */ break;
    case STATUS_CONNECTION_DISCONNECTED: /* reconnect or switch peer */ break;
    case STATUS_BUFFER_TOO_SMALL:        /* raise MaxResponseBytes */ break;
    case STATUS_RETRY:                   /* safe methods may retry */ break;
    default:                             /* log 0x%08X */ break;
    }
}
```

## FAQ

**Q: Required IRQL?**  
A: Synchronous HTTP / WebSocket / TLS / certificate paths must run at **`PASSIVE_LEVEL`**. RAII destructors require the same (they call Release/Close).

**Q: Server role?**  
A: No. Client only; no inbound request parser.

**Q: How is proxy configured?**  
A: Configure `SessionConfig.Proxy` with `Host` / `Port` / `Family` / `Authority` / `AuthHeader`. HTTPS uses a CONNECT tunnel; cleartext HTTP uses absolute-form. HTTP/3 Auto is not selected when a proxy is enabled.

**Q: Is HTTP/3 on by default?**  
A: Default is `Http3ConnectMode::Auto`. The first HTTPS request uses TCP; after validated Alt-Svc is learned, later requests may prefer H3. `Disabled` turns it off; `Required` is prior-knowledge.

**Q: Are POSTs auto-retried?**  
A: No. Stale retry is **GET/HEAD/OPTIONS** only, once. POST/PUT/PATCH/DELETE are never auto-replayed.

**Q: Redirect hop budget exhausted?**  
A: Default **10** hops; exhaustion is **not an error** — the current 3xx is returned for you to handle `Location`. HTTPS→HTTP is rejected by default.

**Q: Can certificate checks be disabled?**  
A: `CertPolicy::NoVerify` exists but is forbidden in production. No system CAs are bundled; supply trust anchors. IP literals match iPAddress SAN only; DNS names never fall back to CN.

**Q: Can the product API enable TLS 1.3 0-RTT?**  
A: No. `EnableEarlyData` / `EarlyDataReplaySafe` are internal TLS connection options and are not mapped onto `TlsConfig` / `SendOptions`. HTTP/3 application-data 0-RTT is also unsupported.

**Q: WebSocket namespace?**  
A: `wknet::websocket` (`Connect`/`SendText`/`Receive`/`Close`); sessions remain `wknet::http::Session`. `wss` may use RFC 8441 or HTTP/1.1 Upgrade.

**Q: How do I unload a driver that used async APIs?**  
A: On the unload path call `wknet::http::Destroy()`, then release WSK and handles. After `AsyncCancel`, still call `AsyncWait` + `AsyncRelease`.

**Q: Are close-delimited responses pooled?**  
A: No. close-delimited bodies and **101** never return to the pool.

Full capability classes: [Capability Matrix](capability-matrix.en.md).
