# Cookbook 样例

### 文件清单

```
samples/KhttpScopeGuard.h     —— RAII 句柄守卫（仅头文件，可复用）
samples/CookbookSamples.h     —— 范例集声明
samples/CookbookSamples.cpp   —— 范例集实现（7 组范例）
tests/KhtTest.h               —— 轻量测试框架（无异常/无 RTTI）
tests/CookbookMockTransport.h —— 确定性 mock 传输（HTTP + WebSocket 回显）
tests/cookbook_tests.cpp      —— 测试套件（9 用例、51 断言）
tests/run-cookbook-tests.ps1  —— 一键编译并运行测试
```

### 范例清单

| 范例 | 演示内容 | 关键 API |
|------|---------|---------|
| QuickGet | 最简正确 GET：调用 + 检查状态 + 守卫释放 | `Get` / `ResponseStatusCode` / `ResponseRelease` |
| SessionReuse | 同主机连续多请求，命中连接池 keep-alive | `Get`（同一 Session） |
| PostJson | POST JSON + 自定义头 + 读响应头 | `BodyCreateJson` / `HeadersAdd` / `SendEx` / `ResponseGetHeader` |
| StreamingDownload | 回调式流式接收，不缓存整包 | `SendOptions.OnHeader/OnBody` |
| HttpsTls | HTTPS + 显式 TLS：SNI、ALPN、始终开启证书校验 | `SendOptions.Tls` / `TlsConfig` |
| AsyncRequest | 异步发起 → 等待 → 取响应 | `AsyncGetEx` / `AsyncWait` / `AsyncGetResponse` |
| AsyncCancel | 协作式取消（取消后仍需收尾等待） | `AsyncCancel` / `AsyncWait` / `AsyncGetStatus` |
| WebSocketEcho | 连接→发→收→关，含全双工时序说明 | `wknet::websocket::Connect` / `wknet::websocket::SendText` / `wknet::websocket::Receive` / `wknet::websocket::Close` |

每个范例独立运行，单个失败不阻断后续；入口返回首个失败状态用于汇总。

> 公开 WebSocket API 位于 `wknet::websocket`，头文件为 `<wknet/websocket/WebSocket.h>`。

### RAII 资源守卫（KhttpScopeGuard.h）

| 守卫 | 管理对象 | 析构调用 |
|------|---------|---------|
| `SessionGuard` | `wknet::http::Session` | `SessionClose` |
| `RequestGuard` | `wknet::http::Request` | `RequestRelease` |
| `ResponseGuard` | `wknet::http::Response` | `ResponseRelease` |
| `AsyncOpGuard` | `wknet::http::AsyncOp` | `AsyncRelease` |
| `WebSocketGuard` | `wknet::websocket::WebSocket` | `wknet::websocket::Close` |

常用成员：`Receive()`（取地址传给 `_Out_` 句柄，接收前先释放已持有的）、`Get()`（取裸指针）、`Detach()`（放弃所有权）、`Reset()`（立即释放）、`operator bool`。守卫不可复制、可移动。析构调用 Release/Close，须在 `PASSIVE_LEVEL`。

### 接入步骤（简要）

1. 参考 `src/wknettest/samples/HighLevelApiSamples.cpp` 的公共 API 调用模式。
2. 在自己的驱动工程中只包含 `<wknet/Wknet.h>` 或所需的细分公共头。
3. 将同步/异步句柄释放与驱动卸载顺序纳入同一所有权设计。

### 注意事项

1. **IRQL**：所有调用与守卫析构都在 `PASSIVE_LEVEL`。
2. **所有权**：`Response` 与 `Request`/`AsyncOp` 独立生命周期，分别释放。
3. **卸载**：用异步 API 后卸载前必须 `wknet::http::Destroy()`；同步-only 路径可不调用，但可无条件调用。
4. **WebSocket 全双工时序**：`wknet::websocket::Close` 不得与同句柄「新 I/O 发起」并发；最安全是单线程内 连接→发→收→关。
5. **`wknet::websocket::Receive` 的 `message.Data`** 指向内部缓冲，下次收/关前有效，关闭后勿引用。

完整可编译样例位于 `src/wknettest/samples/`，用户态 API 回归位于 `tests/high_level_api_tests.cpp`。
