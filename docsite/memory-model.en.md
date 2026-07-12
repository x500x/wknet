# Memory Model

Kernel constraints: no exceptions, no RTTI, no raw `new/delete`, **no stack buffers in the lib** — everything on heap, hot buffers resident in the Workspace. Global `new`/`delete` are overridden in `WknetConfig.cpp` to non-paged pool under tag `'tenW'`.

Heap wrappers (`http/HttpTypes.h`): `HeapArray<T>` and `HeapObject<T>` (RAII, non-copyable) over `AllocateNonPagedObject/Array/Bytes` helpers with overflow validation.

`KhWorkspace` (`engine/Workspace.h`) is a session-resident bundle of reusable buffers — Request 16 KiB, Response 4 KiB (grows on demand; capped only by a nonzero `MaxResponseBytes`), DecodedBody 16 KiB, HttpHeaderScratch 12 KiB, Http2HeaderScratch 16 KiB, TlsHandshakeScratch 32 KiB, CertificateScratch 64 KiB, WebSocketFrameScratch 16 KiB, plus a growable WS payload buffer — managed by `Create`/`Reset`/`Release`/`Ensure*Capacity`/`AppendResponse`.

`WorkspaceScratchAllocator` (`IScratchAllocator`) vends bounded buffers per `BufferKind` (TlsHandshake/Certificate/Http2Header/WebSocketFrame) and never allocates on demand (returns `STATUS_BUFFER_TOO_SMALL` if exceeded). TLS keys are zeroized at session end; private keys held in RAII `CngKey`. Each handle has an `InFlight` counter + `DrainEvent` so it is not freed while in use.
