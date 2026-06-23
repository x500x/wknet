# 异步模型

### 运行时

- **固定 4 个系统线程**工作池（`KhAsyncWorkerCount=4`），FIFO 队列，**最大深度 256**（`KhMaxAsyncQueueDepth`）；队满 → `STATUS_INSUFFICIENT_RESOURCES`。运行时经 CAS 惰性初始化。

### 状态机

```cpp
enum class KhAsyncOperationKind { HttpSend, WebSocketConnect };
enum class KhAsyncState { Pending, Running, Completed };
```
操作创建后处于 `Pending`、`Status=STATUS_PENDING`、`ReferenceCount=1`，入队后 `Pending → Running → Completed`。已取消的 pending 入队会立即以 `STATUS_CANCELLED` 完成。

### 生命周期

1. **创建**：高层 `AsyncGet`/`AsyncPost`/`AsyncSend`、`kws::ConnectAsync`（底层 `KhHttpSendAsync`/`KhWebSocketConnectAsync`）产生一个 `KH_ASYNC_OPERATION`。
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
khttp::AsyncGet / AsyncPost / AsyncSend  → khttp::AsyncOp*
khttp::AsyncWait / AsyncCancel / AsyncGetStatus / AsyncIsCompleted / AsyncIsCanceled
khttp::AsyncGetResponse / AsyncRelease
kws::ConnectAsync → khttp::AsyncOp* ; kws::AsyncGetWebSocket
```

### 示例

```cpp
khttp::AsyncOp* op = nullptr;
khttp::AsyncGetEx(session, url, urlLen, nullptr, nullptr, &op);
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
