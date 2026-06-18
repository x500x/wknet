# 内存模型 / Memory Model

内核环境内存约束、堆封装、Workspace 常驻缓冲。

[English](#english) | 简体中文

---

## 简体中文

### 内核约束

- **无异常、无 RTTI**；避免直接 `new/delete`。
- **lib 内禁止栈缓冲**——一切走堆；高频缓冲常驻 Workspace（避免反复分配）。
- 全局 `new`/`delete` 在 `KernelHttpConfig.cpp` 被重载，路由到**非分页池**，统一池标记 `KERNEL_HTTP_POOL_TAG = 'ptHK'`。

### 堆封装（`http/HttpTypes.h`）

```cpp
template<class T> class HeapArray {   // RAII 拥有数组，不可复制
    explicit HeapArray(SIZE_T count);  NTSTATUS Allocate(SIZE_T count);
    void Reset(); bool IsValid(); T* Get(); SIZE_T Count(); T& operator[](SIZE_T);
};
template<class T> class HeapObject {  // RAII 拥有单对象，不可复制
    HeapObject(); NTSTATUS Allocate(); void Reset(); bool IsValid();
    T* Get(); T& operator*(); T* operator->();
};
```
底层分配器：`AllocateNonPagedObject<T>` / `AllocateNonPagedArray<T>` / `AllocateNonPagedPoolBytes` 及对应 Free，并带 `NonPagedArrayCountIsValid<T>` 溢出校验。

### Workspace（`engine/Workspace.h`）

`KhWorkspace` 是会话常驻的一组可复用缓冲，覆盖一次事务的各阶段，按需增长，`Reset` 清每次操作状态，随会话创建/释放。

| 缓冲 | 默认大小 |
|------|---------|
| `Request` | 16 KiB |
| `Response`（初始） | 4 KiB（按需增长，受 `MaxResponseBytes` 限制） |
| `DecodedBody` | 16 KiB |
| `HttpHeaderScratch` | 12 KiB |
| `Http2HeaderScratch` | 16 KiB |
| `TlsHandshakeScratch` | 32 KiB |
| `CertificateScratch` | 64 KiB |
| `WebSocketFrameScratch` | 16 KiB |
| `WebSocketPayloadScratch` | 按需增长 |

函数：`KhWorkspaceCreate`、`KhWorkspaceReset`、`KhWorkspaceRelease`、`KhWorkspaceEnsureResponseCapacity`、`KhWorkspaceAppendResponse`、`KhWorkspaceEnsureDecodedBodyCapacity`、`KhWorkspaceEnsureWebSocketPayloadCapacity`。

### Scratch 分配器（`core/WorkspaceScratchAllocator.h`）

`WorkspaceScratchAllocator` 实现 `IScratchAllocator`，从 Workspace 取**定长有界**缓冲（按 `BufferKind { TlsHandshake, Certificate, Http2Header, WebSocketFrame }`），**不按需分配**——请求超过该缓冲返回 `STATUS_BUFFER_TOO_SMALL`。TLS 握手、证书校验、HPACK、WS 帧由此获得无栈、无重复分配的工作内存。

### 安全清零

TLS 会话结束安全清零所有密钥材料；私钥用 `crypto::CngKey` RAII 持有，作用域结束清理。

### 句柄收尾

每个 `Kh*` 句柄含 `volatile LONG InFlight` 与（内核构建）`KEVENT DrainEvent`，配合 `KhEngineDrainAsync` 保证仍在使用时不被释放（见 [异步模型](async-model.md)）。

---

## English

Kernel constraints: no exceptions, no RTTI, no raw `new/delete`, **no stack buffers in the lib** — everything on heap, hot buffers resident in the Workspace. Global `new`/`delete` are overridden in `KernelHttpConfig.cpp` to non-paged pool under tag `'ptHK'`.

Heap wrappers (`http/HttpTypes.h`): `HeapArray<T>` and `HeapObject<T>` (RAII, non-copyable) over `AllocateNonPagedObject/Array/Bytes` helpers with overflow validation.

`KhWorkspace` (`engine/Workspace.h`) is a session-resident bundle of reusable buffers — Request 16 KiB, Response 4 KiB (grows, capped by `MaxResponseBytes`), DecodedBody 16 KiB, HttpHeaderScratch 12 KiB, Http2HeaderScratch 16 KiB, TlsHandshakeScratch 32 KiB, CertificateScratch 64 KiB, WebSocketFrameScratch 16 KiB, plus a growable WS payload buffer — managed by `Create`/`Reset`/`Release`/`Ensure*Capacity`/`AppendResponse`.

`WorkspaceScratchAllocator` (`IScratchAllocator`) vends bounded buffers per `BufferKind` (TlsHandshake/Certificate/Http2Header/WebSocketFrame) and never allocates on demand (returns `STATUS_BUFFER_TOO_SMALL` if exceeded). TLS keys are zeroized at session end; private keys held in RAII `CngKey`. Each handle has an `InFlight` counter + `DrainEvent` so it is not freed while in use.
