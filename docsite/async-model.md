# 异步模型

异步 API 把同步 `Send*` / WebSocket 连接搬到**固定 4 线程**工作池执行；调用方持有 opaque `AsyncOp`，用等待/轮询/取消收尾。同步路径不受异步运行时影响。

## 运行时

| 项 | 值 |
|----|-----|
| 工作线程 | 固定 **4**（`AsyncWorkerCount`） |
| 队列 | FIFO，最大深度 **256** |
| 队满 | `STATUS_INSUFFICIENT_RESOURCES` |
| 初始化 | CAS 惰性启动 |

种类：`HttpSend`、`WebSocketConnect`。状态：`Pending → Running → Completed`。

## 生命周期

1. **创建**：`AsyncGet` / `AsyncPost` / `AsyncSend` 或 `wknet::websocket::ConnectAsync` → `AsyncOp*`，初始 `STATUS_PENDING`，引用计数 1。
2. **入队**：worker 执行；若入队前已取消，立即以 `STATUS_CANCELLED` 完成。
3. **等待**：`AsyncWait(op, timeoutMs)`，或轮询 `AsyncGetStatus` / `AsyncIsCompleted`。
4. **取结果**：HTTP 用 `AsyncGetResponse`；WebSocket 用 `wknet::websocket::AsyncGetWebSocket`。
5. **释放**：`AsyncRelease`（引用归零时清理）。

```cpp
wknet::http::AsyncOp* op = nullptr;
NTSTATUS s = wknet::http::AsyncGetEx(session, url, urlLen, nullptr, nullptr, &op);
if (NT_SUCCESS(s) && wknet::http::AsyncWait(op, 30000) == STATUS_SUCCESS) {
    wknet::http::Response* r = nullptr;
    if (NT_SUCCESS(wknet::http::AsyncGetResponse(op, &r))) {
        // 使用 r
        wknet::http::ResponseRelease(r);
    }
}
wknet::http::AsyncRelease(op);
```

## 引用计数与取消

- 用户句柄持 1 个引用；worker 另持 1 个，保证用户标记关闭后仍可观察取消标志。
- `AsyncCancel`：`Pending` 立即完成；`Running` 将 `Canceled` 传入传输等待，底层支持时取消活跃 IRP。
- **取消是协作式的**：调用 `AsyncCancel` 后仍须 `AsyncWait` 收尾，再 `AsyncRelease`。

## 完成回调

`AsyncOptions.OnComplete`（及测试路径下的完成回调）在操作进入 `Completed` 时调用。回调内不要做重活或再次同步等待同一 op；适合投递上层队列。

## 卸载约束

用过异步 API 后，驱动卸载前**必须**先：

```cpp
wknet::http::Destroy();  // 排空在飞异步操作与 worker
// 再释放 WSK / 关闭 session 与其它句柄
```

同步-only 路径可不调用，但可无条件调用。每个 session/相关句柄用在飞计数与 drain 事件防止“操作仍在使用时释放句柄”。

## 与同步 API 的关系

| | 同步 `Get*` / `Send*` | 异步 `Async*` |
|--|----------------------|---------------|
| 调用 IRQL | `PASSIVE_LEVEL` | 提交/等待在 `PASSIVE_LEVEL` |
| 阻塞点 | 调用线程 | worker 线程 |
| 取消 | 无公开中途取消 | `AsyncCancel` |
| 连接池 / 重定向 / H3 | 同一 session 策略 | 同一 session 策略 |

异步不改变协议语义：stale 重试、redirect 上限、H3 Auto、证书校验规则与同步路径一致。
