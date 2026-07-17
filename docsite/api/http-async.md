# 异步 HTTP

命名空间：`wknet::http`  
头文件：`HttpAsync.h` · `AsyncOp.h` · `Options.h` · `Lifecycle.h` · `Types.h`

非阻塞发送、`AsyncOp` 等待/取消/取结果，以及驱动卸载路径上的 `Destroy`。

## AsyncOptions

```cpp
NTSTATUS AsyncOptionsCreate(_Out_ AsyncOptions** options) noexcept;
void AsyncOptionsRelease(_In_opt_ AsyncOptions* options) noexcept;

struct AsyncOptions final {
    SendOptions Send;
    CompletionCallback OnComplete;
    void* CompletionContext;
};
```

| 字段 | 默认 | 说明 |
|------|------|------|
| `Send` | `DefaultSendOptions()` | 内嵌同步发送选项（Flags、TLS、缓存等） |
| `OnComplete` | `nullptr` | 完成回调：`void (*)(void* context, NTSTATUS status)` |
| `CompletionContext` | `nullptr` | 传给 `OnComplete` |

`SendOptions` 字段见 [同步 HTTP](http-sync.md)。

## AsyncSend / 按方法异步发送

### 签名

```cpp
NTSTATUS AsyncSend(
    _In_ Session* session,
    Method method,
    _In_z_ const char* url,
    _In_opt_ const Headers* headers,
    _In_opt_ const Body* body,
    _In_opt_ const AsyncOptions* options,
    _Out_ AsyncOp** operation) noexcept;

NTSTATUS AsyncSendEx(
    _In_ Session* session,
    Method method,
    _In_reads_bytes_(urlLength) const char* url,
    SIZE_T urlLength,
    _In_opt_ const Headers* headers,
    _In_opt_ const Body* body,
    _In_opt_ const AsyncOptions* options,
    _Out_ AsyncOp** operation) noexcept;
```

另有首参 `Request*` 的 `AsyncSend` / `AsyncSendEx`。

| 方法（Session / Request） | `*Ex` |
|---------------------------|------|
| `AsyncGet` / `AsyncHead` / `AsyncDelete` / `AsyncTrace` | `*Ex(..., headers, options, operation)` |
| `AsyncPost` / `AsyncPut` / `AsyncPatch` | `*Ex(..., headers, body, options, operation)` |
| `AsyncOptionsRequest` | `AsyncOptionsRequestEx`（避免与类型 `AsyncOptions` 冲突） |

### 参数

| 参数 | 说明 |
|------|------|
| `options` | 可选；`nullptr` 使用默认 `AsyncOptions` |
| `operation` | 输出 `AsyncOp*`；调用方负责 `AsyncRelease` |

### 返回

| 状态 | 含义 |
|------|------|
| `STATUS_SUCCESS` | 已排队；完成与否看 `AsyncOp` |
| `STATUS_INVALID_PARAMETER` | 参数非法 |
| `STATUS_INVALID_DEVICE_REQUEST` | 非 `PASSIVE_LEVEL` |
| `STATUS_INSUFFICIENT_RESOURCES` | 队列/分配失败 |

`Body` / `Headers` 指针须保持到操作完成或取消。

## AsyncOp

### 签名

```cpp
NTSTATUS AsyncWait(_In_ AsyncOp* operation, ULONG timeoutMs) noexcept;
NTSTATUS AsyncCancel(_In_ AsyncOp* operation) noexcept;
NTSTATUS AsyncGetStatus(_In_opt_ const AsyncOp* operation) noexcept;
bool AsyncIsCompleted(_In_opt_ const AsyncOp* operation) noexcept;
bool AsyncIsCanceled(_In_opt_ const AsyncOp* operation) noexcept;
NTSTATUS AsyncGetResponse(_In_ AsyncOp* operation, _Out_ Response** response) noexcept;
void AsyncRelease(_In_opt_ AsyncOp* operation) noexcept;
```

### 参数 / 返回

| API | 说明 |
|-----|------|
| `AsyncWait` | `timeoutMs` 毫秒；`0` 为非阻塞探测语义以实现为准；超时返回超时状态 |
| `AsyncCancel` | 请求取消；已完成则无操作或返回相应状态 |
| `AsyncGetStatus` | 最近一次完成状态；空操作返回错误状态 |
| `AsyncIsCompleted` / `AsyncIsCanceled` | 查询标志；空指针为 `false` |
| `AsyncGetResponse` | 成功完成后取出 `Response*`（所有权转交调用方） |
| `AsyncRelease` | 释放操作；未取走的响应一并释放 |

### 备注

- 完成回调可能在工作线程上下文触发；勿在回调内做长时间阻塞或提升 IRQL。
- `AsyncGetResponse` 宜在完成且成功后调用一次。
- WebSocket 异步连接共用 `AsyncOp`，见 [WebSocket](websocket.md) 的 `AsyncGetWebSocket`。

## Destroy

```cpp
// Lifecycle.h
void Destroy() noexcept;
```

### 备注

- 在驱动卸载路径调用，等待异步 worker 与队列结束后再释放资源。
- 使用过 `Async*` 时调用；纯同步路径可不调用。
- 调用后不要再提交新的异步操作。

## 示例

### 异步 GET + Wait + 取 Response

```cpp
#include <wknet/Wknet.h>

NTSTATUS AsyncGetAndWait(wknet::http::Session* session)
{
    using namespace wknet::http;

    AsyncOp* op = nullptr;
    Response* response = nullptr;

    NTSTATUS status = AsyncGet(session, "https://example.com/", &op);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = AsyncWait(op, 30000); // 毫秒；超时返回超时状态
    if (NT_SUCCESS(status)) {
        status = AsyncGetResponse(op, &response);
    }
    if (NT_SUCCESS(status) && response != nullptr) {
        const ULONG code = ResponseStatusCode(response);
        UNREFERENCED_PARAMETER(code);
    }

    ResponseRelease(response);
    AsyncRelease(op); // 未取走的 Response 一并释放
    return status;
}
```

### 会话无关异步 + 完成回调

```cpp
static void OnComplete(void* context, NTSTATUS status)
{
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(status);
    // 可能在工作线程；勿长时间阻塞或提升 IRQL
}

AsyncOptions* options = nullptr;
AsyncOptionsCreate(&options);
options->OnComplete = OnComplete;
options->CompletionContext = nullptr;

AsyncOp* op = nullptr;
NTSTATUS status = AsyncGetEx(
    "https://example.com/",
    sizeof("https://example.com/") - 1,
    nullptr,
    options,
    &op);
// ... AsyncWait / AsyncGetResponse ...
AsyncRelease(op);
AsyncOptionsRelease(options);
// 使用过 Async* 时，卸载路径调用 wknet::http::Destroy();
```

### 取消

```cpp
AsyncOp* op = nullptr;
NTSTATUS status = AsyncGet(session, "https://example.com/slow", &op);
if (NT_SUCCESS(status)) {
    (void)AsyncCancel(op);
    (void)AsyncWait(op, 5000); // 取消后仍应 Wait + Release
    AsyncRelease(op);
}
```

## 相关链接

- [同步 HTTP](http-sync.md)
- [请求与响应](request-response.md)
- [WebSocket](websocket.md)
- [Cookbook](../cookbook.md)
- [第一个请求](../first-request.md)
