# Memory Model

Kernel constraints: no exceptions, no RTTI, no raw `new/delete`, **no stack buffers in the lib** — everything on heap, hot buffers resident in the Workspace. Global `new`/`delete` are overridden in `WknetConfig.cpp` to non-paged pool under tag `'tenW'`.

Heap wrappers (`http/HttpTypes.h`): `HeapArray<T>` and `HeapObject<T>` (RAII, non-copyable) over `AllocateNonPagedObject/Array/Bytes` helpers with overflow validation.

`session::Workspace` is a session-resident bundle of reusable heap buffers. Response aggregation grows on demand and is capped only by a nonzero caller `MaxResponseBytes`; protocol scratch and WebSocket payload buffers are retained and reset between operations.

`WorkspaceScratchAllocator` (`IScratchAllocator`) vends bounded buffers per `BufferKind` (TlsHandshake/Certificate/Http2Header/WebSocketFrame) and never allocates on demand (returns `STATUS_BUFFER_TOO_SMALL` if exceeded). TLS keys are zeroized at session end; private keys held in RAII `CngKey`. Each handle has an `InFlight` counter + `DrainEvent` so it is not freed while in use.
