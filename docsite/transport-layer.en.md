# Transport Layer

`core::ITransport` is the byte-stream abstraction (`Send`/`Receive`/`ReceiveWithTimeout`) unifying plaintext and TLS. Adapters: `WskTransport` (over `net::WskSocket`, `WSK_FLAG_NODELAY`, cancellation token) for plaintext, `TlsTransport` (wraps an inner `ITransport` + `tls::TlsConnection`) for auto encrypt/decrypt. Stack: WskSocket → WskTransport → (TlsTransport for HTTPS) → protocol layer. `IScratchAllocator` (`Acquire`/`Release`/`EnsureBuffer`) is implemented by `WorkspaceScratchAllocator`.

WSK layer: `WskClient` owns registration and resolution; `WskSocket` owns connect/send/receive/disconnect/close and forwards cancellation to IRPs. `transport::ITransport` is used by narrow `WKNET_USER_MODE_TEST` hooks for deterministic protocol tests.
