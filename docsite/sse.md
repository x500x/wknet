# Server-Sent Events（SSE）

`wknet::sse` 提供 WHATWG `text/event-stream` **客户端**。API 形态对齐 WebSocket：`Connect` / `Receive` / `Close`，依赖已有 `http::Session`。

完整签名见 [SSE API](api/sse.md)。

## 结论

| 主题 | 行为 |
|------|------|
| 方法 | 仅 **GET** |
| Content-Type | 默认要求 `text/event-stream`（可 `RequireEventStreamContentType=false`） |
| 解析 | 半包、CRLF/`\n`、comment、`id`/`event`/`data`/`retry`、多 data 行 |
| Last-Event-ID | 解析器跟踪；重连时自动注入请求头 |
| 重连 | 默认开；指数退避 + 尊重 `retry:`；**4xx 不重连** |
| 超时 | `ConnectTimeoutMs` / `IdleTimeoutMs` / `ReceiveTimeoutMs` 分字段 |
| 传输 | 复用 Session 的 H1/H2/H3 路径（受策略约束） |
| 非目标 | SSE 服务端、POST body 型 SSE、流式 gzip/br 响应体（首版） |

## 最小示例

```cpp
#include <wknet/Wknet.h>

wknet::http::Session* session = nullptr;
wknet::http::SessionCreate(nullptr, &session);

wknet::sse::ConnectConfig cfg = wknet::sse::DefaultConnectConfig();
cfg.Url = "https://example.com/events";
cfg.UrlLength = 28;
// cfg.IdleTimeoutMs = 0;           // 长空闲流
// cfg.AutoReconnect = true;
// cfg.LastEventId = "42"; cfg.LastEventIdLength = 2;

wknet::sse::SseClient* client = nullptr;
NTSTATUS st = wknet::sse::ConnectEx(session, &cfg, &client);
if (NT_SUCCESS(st)) {
    for (;;) {
        wknet::sse::Event event = {};
        st = wknet::sse::Receive(client, &event);
        if (!NT_SUCCESS(st)) {
            break; // 取消、最终失败或不再重连的断开
        }
        // event.Type / Data / Id 在下次 Receive 或 Close 前有效
    }
    wknet::sse::Close(client);
}
wknet::http::SessionClose(session);
```

## 与「整包 HTTP」的区别

| | 普通 `Get` / `Send` | SSE `SseClient` |
|--|---------------------|-----------------|
| 完成条件 | 整响应结束 | 长期流；事件增量交付 |
| body | 聚合到 `Response` | 不聚合为完整 Response body |
| 超时 | 历史路径偏「整次」 | open / idle / receive 分字段 |
| 重试 | 仅安全方法连接级一次 `STATUS_RETRY` | 应用层重连 + `Last-Event-ID` |

底层：若你用 `SendOptions.OnBody` 做通用流式下载，回调可能**多次**到达，`finalChunk` 仅在结束时为 true。见 [同步 HTTP](api/http-sync.md)。

## 重连语义

1. 流正常结束或可恢复网络错误且 `AutoReconnect` → 调度 delay（`retry:` 或指数退避）。  
2. `OnReconnect` 可选通知 attempt / delay / lastError / lastEventId（**不**含事件 data）。  
3. 新请求带 `Last-Event-ID`（若有）；`ForceNew` 连接。  
4. open 得到 **4xx** → 失败，**不**进入重连循环。  
5. `Close` 中止 sleep 与阻塞 `Receive`。

## 边界

- 库注入 `Accept` / `Cache-Control` /（有 id 时）`Last-Event-ID`；调用方不得覆盖这些受控头。  
- 不记录事件正文到 Trace（见 [日志](logging.md)）。  
- 同一 client 单线程 `Receive`；多线程并行未定义。  
- 支持范围见 [能力边界](capability-matrix.md)。
