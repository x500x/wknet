# 异步模型 / Async Model

`engine/Async.h`，`KernelHttp::engine`。高层 `khttp`/`kws` 的 `*Async` 入口即基于此。

[English](#english) | 简体中文

---

## 简体中文

### 运行时

- **固定 4 个系统线程**工作池（`KhAsyncWorkerCount=4`），FIFO 队列，**最大深度 256**（`KhMaxAsyncQueueDepth`）；队满 → `STATUS_INSUFFICIENT_RESOURCES`。运行时经 CAS 惰性初始化。

### 状态机

```cpp
enum class KhAsyncOperationKind { HttpSend, WebSocketConnect };
enum class KhAsyncState { Pending, Running, Completed };
```
操作创建后处于 `Pending`、`Status=STATUS_PENDING`、`ReferenceCount=1`，入队后 `Pending → Running → Completed`。已取消的 pending 入队会立即以 `STATUS_CANCELLED` 完成。

### 生命周期

1. **创建**：高层 `GetAsync`/`PostAsync`/`SendAsync`、`kws::ConnectAsync`（底层 `KhHttpSendAsync`/`KhWebSocketConnectAsync`）产生一个 `KH_ASYNC_OPERATION`。
2. **入队执行**：内部 `KhAsyncOperationQueue` 调度 `WorkerRoutine`。
3. **等待**：`AsyncWait(op, timeoutMs)` 等完成事件；或轮询 `AsyncGetStatus`/`AsyncIsCompleted`。
4. **取结果**：按 `Kind` 调 `AsyncGetResponse`（HTTP）或 `kws::AsyncGetWebSocket`（WebSocket）。
5. **释放**：`AsyncRelease`（引用计数归零时清理）。

### 引用计数与取消

- 用户句柄持 1 个引用；内部 worker 持独立引用，使其在用户标记 `Closed` 后仍存活，从而能继续观察取消标志。
- **取消** `AsyncCancel`：`Pending` 立即完成；`Running` 的 HTTP/WebSocket worker 观察 `Canceled` 标志并将其传入 WSK 传输等待，底层支持时取消活跃 IRP。
- 取消是协作式的——取消后仍需 `AsyncWait` 收尾等待，再 `AsyncRelease`。

### 卸载约束

```cpp
NTSTATUS KhEngineDrainAsync() noexcept;   // 等待全部在飞异步操作结束
```
高层调用方使用 `khttp::Destroy()` 作为卸载收尾入口；它内部等待全部在飞异步操作结束。**用过异步 API 后，驱动卸载前必须先 `khttp::Destroy()`**，再释放 WSK / 关闭句柄。同步-only 路径可不调用，但可无条件调用。每个句柄含 `volatile LONG InFlight` 计数与 `KEVENT DrainEvent` 做收尾同步，确保操作仍在使用时句柄不被释放。

### 高层异步函数速查

```cpp
khttp::GetAsync / PostAsync / SendAsync  → khttp::AsyncOp*
khttp::AsyncWait / AsyncCancel / AsyncGetStatus / AsyncIsCompleted / AsyncIsCanceled
khttp::AsyncGetResponse / AsyncRelease
kws::ConnectAsync → khttp::AsyncOp* ; kws::AsyncGetWebSocket
```

### 示例

```cpp
khttp::AsyncOp* op = nullptr;
khttp::GetAsync(session, url, urlLen, &op);
if (khttp::AsyncWait(op, 30000) == STATUS_SUCCESS) {
    khttp::Response* r = nullptr;
    if (NT_SUCCESS(khttp::AsyncGetResponse(op, &r))) {
        // ... 用 r ...
        khttp::ResponseRelease(r);
    }
}
khttp::AsyncRelease(op);
// 驱动卸载路径：khttp::Destroy();
```

---

## English

`engine/Async.h`. Kinds `HttpSend`/`WebSocketConnect`; states `Pending→Running→Completed`. An op is created via `*Async` entry points (`GetAsync`/`PostAsync`/`SendAsync`/`kws::ConnectAsync`), queued to run its worker, awaited via `AsyncWait` (or polled via `AsyncGetStatus`/`AsyncIsCompleted`), then results fetched per kind (`AsyncGetResponse` / `kws::AsyncGetWebSocket`), then `AsyncRelease`.

Reference counting: the user handle holds one reference; an internal worker holds another, keeping the object alive after the user marks it closed so it can still observe cancellation. `AsyncCancel` completes a pending op immediately and signals a running HTTP/WS worker, which forwards the flag into WSK transport waits to cancel the active IRP where supported — cancellation is cooperative, so still `AsyncWait` then `AsyncRelease`.

**After using async APIs, call `khttp::Destroy()` before driver unload** (then release WSK / close handles). Synchronous-only paths do not require it, but may call it unconditionally. Each handle carries a `volatile LONG InFlight` counter and a `KEVENT DrainEvent` so handles are not freed while operations still use them.
