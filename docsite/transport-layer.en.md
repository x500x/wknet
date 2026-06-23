# Transport Layer

`core::ITransport` is the byte-stream abstraction (`Send`/`Receive`/`ReceiveWithTimeout`) unifying plaintext and TLS. Adapters: `WskTransport` (over `net::WskSocket`, `WSK_FLAG_NODELAY`, cancellation token) for plaintext, `TlsTransport` (wraps an inner `ITransport` + `tls::TlsConnection`) for auto encrypt/decrypt. Stack: WskSocket → WskTransport → (TlsTransport for HTTPS) → protocol layer. `IScratchAllocator` (`Acquire`/`Release`/`EnsureBuffer`) is implemented by `WorkspaceScratchAllocator`.

WSK layer: `WskClient` (register + `Resolve`/`ResolveAll` up to 8 addresses, `WskAddressFamily` Any/Ipv4/Ipv6), `WskSocket` (`Connect`/`Send`/`Receive` with 30 s default timeout/`Disconnect`/`Close`, cancellation token forwarded to IRPs), `WskBuffer` (MDL-backed pooled buffer). Implement `ITransport` to inject a custom/mock transport — used by the low-level API and test hooks (`KhTestSetHttpTransport`) for deterministic, network-free unit tests.
