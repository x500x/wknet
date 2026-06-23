# Architecture

### Layered architecture

Top to bottom: high-level `khttp` (HTTP) / `kws` (WebSocket) → low-level `engine` (`Kh*`, stable ABI) → client wrappers → core abstractions → protocol implementations → infrastructure (WSK / CNG / connection pool / Workspace). The high-level layer is a thin bridge over the engine handle ABI (`khttp/Detail.h`).

### Request lifecycle (sync GET)

`SessionCreate` creates a hidden WSK runtime and engine session (Workspace + provider cache + pool) → `GetEx`/`SendEx` receives the send handle, method, URL, headers/body/options and parses the URL → acquire a connection by `KhConnectionPoolKey` (reuse or build: WSK connect → optional TLS handshake → optional HTTP/2 init) → build/send/parse inside Workspace buffers (decode Transfer-/Content-Encoding) → release connection per keep-alive → return independent `Response` handle → `ResponseRelease`/`SessionClose`.

### Core abstractions

| Abstraction | Header | Role |
|-------------|--------|------|
| `core::ITransport` | `core/ITransport.h` | Byte-stream: `Send`/`Receive`/`ReceiveWithTimeout` |
| `core::WskTransport` | `core/WskTransport.h` | Plaintext WSK adapter |
| `core::TlsTransport` | `core/TlsTransport.h` | TLS adapter (auto encrypt/decrypt) |
| `core::IScratchAllocator` | `core/IScratchAllocator.h` | `Acquire`/`Release`/`EnsureBuffer` |
| `core::WorkspaceScratchAllocator` | `core/WorkspaceScratchAllocator.h` | Bounded buffers from a `KhWorkspace`, no on-demand alloc |
| `engine::KhWorkspace` | `engine/Workspace.h` | Session-resident reusable buffers |
| `engine::KhConnectionPool` | `engine/ConnectionPool.h` | Reuse, per-host cap, idle timeout |

See [Transport Layer](transport-layer.md), [Memory Model](memory-model.md), [Connection Pool](connection-pool.md).

### Kernel-constrained design

No exceptions, no RTTI; avoid raw `new/delete` (the lib overrides them to non-paged pool in `KernelHttpConfig.cpp`); heap via `HeapObject<T>`/`HeapArray<T>`; no stack buffers in the lib; hot buffers resident in the Workspace; synchronous paths at `PASSIVE_LEVEL`; all public functions `noexcept` with SAL annotations.
