# SSE API

命名空间：`wknet::sse`  
头文件：`wknet/sse/Sse.h` · 配置类型在 `wknet/http/Types.h` 与 `Sse.h` 内并列

`Connect` / `Receive` / `Close`，依赖已有 `http::Session`。实现为 WHATWG `text/event-stream` 客户端：解析事件、跟踪 `Last-Event-ID`、可选断线自动重连。

## ConnectConfig

```cpp
ConnectConfig DefaultConnectConfig() noexcept;

struct ConnectConfig final {
    const char* Url = nullptr;
    SIZE_T UrlLength = 0;
    const Header* Headers = nullptr;
    SIZE_T HeaderCount = 0;
    wknet::http::TlsConfig Tls = {};
    wknet::http::AddressFamily Family = wknet::http::AddressFamily::Any;

    const char* LastEventId = nullptr;
    SIZE_T LastEventIdLength = 0;

    bool AutoReconnect = true;
    ULONG MaxReconnectAttempts = 0;       // 0 = 直到 Close 无上限
    ULONG InitialReconnectDelayMs = 1000;
    ULONG MaxReconnectDelayMs = 30000;

    ULONG ConnectTimeoutMs = 30000;
    ULONG IdleTimeoutMs = 0;              // 0 = 不限 body 空闲
    ULONG ReceiveTimeoutMs = 0;           // 0 = 不限单次 Receive 等待

    SIZE_T MaxEventBytes = 1 * 1024 * 1024;
    SIZE_T MaxParserBufferBytes = 256 * 1024;

    bool RequireEventStreamContentType = true;

    EventCallback OnEvent = nullptr;
    ReconnectCallback OnReconnect = nullptr;
    void* CallbackContext = nullptr;
};
```

| 字段 | 说明 |
|------|------|
| `Url` / `UrlLength` | `http://` 或 `https://` 流端点（**GET only**） |
| `Headers` / `HeaderCount` | 调用方 opening 头（如 `Authorization`）；库控制头 `Accept` / `Last-Event-ID` / `Cache-Control` 冲突时拒绝 |
| `Tls` / `Family` | HTTPS TLS 与地址族 |
| `LastEventId` | 初始 `Last-Event-ID`（可选） |
| `AutoReconnect` | 断线后自动重连；**4xx open 失败不重连** |
| `MaxReconnectAttempts` | `0` 表示直到 `Close` |
| `InitialReconnectDelayMs` / `MaxReconnectDelayMs` | 指数退避；尊重服务端 `retry:` 字段 |
| `ConnectTimeoutMs` | 等到响应头 / open 完成的上限 |
| `IdleTimeoutMs` | body 字节空闲超时；`0` 禁用 |
| `ReceiveTimeoutMs` | 单次 `Receive` 等待事件上限；`0` 不限 |
| `MaxEventBytes` / `MaxParserBufferBytes` | 单事件与解析缓冲上限 |
| `RequireEventStreamContentType` | 要求 `Content-Type` 以 `text/event-stream` 开头 |
| `OnEvent` / `OnReconnect` | 可选回调（在交付路径上调用） |

### 辅助类型

```cpp
struct Event final {
    const char* Type = nullptr; SIZE_T TypeLength = 0;  // 默认 "message"
    const char* Data = nullptr; SIZE_T DataLength = 0;  // 多行 data 以 \n 拼接
    const char* Id   = nullptr; SIZE_T IdLength = 0;
};

struct Header final {
    const char* Name = nullptr; SIZE_T NameLength = 0;
    const char* Value = nullptr; SIZE_T ValueLength = 0;
};

typedef NTSTATUS (*EventCallback)(void* context, const Event* event);
typedef void (*ReconnectCallback)(
    void* context, ULONG attempt, ULONG delayMs, NTSTATUS lastError,
    const char* lastEventId, SIZE_T lastEventIdLength);

struct ReceiveOptions final {
    SIZE_T MaxEventBytes = 0;
    EventCallback OnEvent = nullptr;
    void* CallbackContext = nullptr;
};
```

## Connect

```cpp
NTSTATUS Connect(
    _In_ wknet::http::Session* session,
    _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength,
    _Out_ SseClient** client) noexcept;

NTSTATUS Connect(
    _In_ wknet::http::Session* session,
    _In_ const ConnectConfig* config,
    _Out_ SseClient** client) noexcept;

NTSTATUS ConnectEx(
    _In_ wknet::http::Session* session,
    _In_ const ConnectConfig* config,
    _Out_ SseClient** client) noexcept;

NTSTATUS ConnectAsync(...);           // 返回 AsyncOp*
NTSTATUS ConnectAsyncEx(...);
NTSTATUS AsyncGetSseClient(
    _In_ wknet::http::AsyncOp* operation,
    _Out_ SseClient** client) noexcept;
```

成功时 `*client` 有效：已收到 2xx 且（若要求）`Content-Type` 可接受。库注入 `Accept: text/event-stream` 与 `Cache-Control: no-cache`；有 last-event-id 时注入 `Last-Event-ID`。

| 典型失败 | 含义 |
|----------|------|
| `STATUS_INVALID_PARAMETER` | URL/头/地址族非法，或调用方覆盖库控制头 |
| `STATUS_INVALID_NETWORK_RESPONSE` | 非 event-stream Content-Type（当 Require 时） |
| `STATUS_ACCESS_DENIED` | HTTP 4xx（**不自动重连**） |
| `STATUS_IO_TIMEOUT` | open 超时 |

## Receive

```cpp
NTSTATUS Receive(_In_ SseClient* client, _Out_ Event* event) noexcept;
NTSTATUS ReceiveEx(
    _In_ SseClient* client,
    _In_opt_ const ReceiveOptions* options,
    _Out_opt_ Event* event) noexcept;
```

阻塞直到：

1. 有完整事件可交付 → `STATUS_SUCCESS`，`Event` 字段指向**客户端内部缓冲**（下次成功 Receive / Close 前有效）；或  
2. 流结束且不可/不再重连 → 断开或最终错误状态；或  
3. `ReceiveTimeoutMs` 到期 → `STATUS_IO_TIMEOUT`；或  
4. `Close` → `STATUS_CANCELLED`。

`Event.Type` 缺省为 `"message"`。多行 `data:` 以 `\n` 拼接。`id:` 更新 last-event-id；含 `\0` 的 id 按规范忽略。`retry:` 影响后续重连 delay。

## 查询 / Close

```cpp
NTSTATUS GetLastEventId(
    _In_ SseClient* client,
    _Outptr_result_bytebuffer_(*idLength) const char** id,
    _Out_ SIZE_T* idLength) noexcept;

NTSTATUS GetReconnectAttempt(
    _In_ SseClient* client,
    _Out_ ULONG* attempt) noexcept;

NTSTATUS Close(_In_opt_ SseClient* client) noexcept;
```

`Close` 接受 `nullptr`，可中止阻塞 `Receive` 与重连 delay。关闭后句柄失效。

## 行为要点

| 主题 | 行为 |
|------|------|
| 方法 | **仅 GET** |
| Content-Encoding | 首版要求 **identity**（非 identity 在流路径拒绝） |
| 协议 | 与 Session HTTP 栈一致，可走 H1 / H2 / H3（受 Session / TLS / Alt-Svc 策略约束） |
| 重连 | open 失败 4xx **不**重连；其它可恢复断开可重连并带 `Last-Event-ID` |
| 连接策略 | 每次 open 使用 `ForceNew`，避免半死 keep-alive |
| 并发 | 同一 `SseClient` **不要**多线程并行 `Receive` |
| IRQL | 全部入口 `PASSIVE_LEVEL` |

## 与流式 OnBody 的关系

SSE 建立在 session 真增量响应体之上：`SendOptions.OnBody` 在启用时会按到达顺序**多次**回调，`finalChunk` 仅在真正结束时为 true。若只要聚合 body，不要设 `OnBody`。详见 [同步 HTTP](http-sync.md)。

## 相关链接

- [能力边界](../capability-matrix.md)
- [同步 HTTP](http-sync.md)
- [Cookbook](../cookbook.md)
- [日志与诊断](../logging.md)
