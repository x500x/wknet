# Cookbook

按任务索引可编译示例。源码在 `src/wknettest/samples` 与用户态测试中。

## 示例位置

| 路径 | 内容 |
|------|------|
| `src/wknettest/samples/HighLevelApiSamples.cpp` | Session、同步/异步 HTTP、Body、TLS、HTTP/2、WebSocket、SSE |
| `src/wknettest/samples/AdvancedScenarioSamples.cpp` | 重定向、错误状态、大响应、并发异步、超时、TLS 失败、WS 分片 |
| `src/wknettest/samples/ExternalTrustStore.cpp` | 外部信任库 / 证书 |
| `src/wknettest/samples/HttpApiSamples.cpp` | 驱动侧样例入口 |
| `tests/high_level_api_tests.cpp` | 用户态 API 回归 |
| `tests/sse_parser_tests.cpp` / `sse_client_tests.cpp` | SSE 解析器与客户端假传输回归 |

公共头：`#include <wknet/Wknet.h>`。WebSocket 也可 `#include <wknet/websocket/WebSocket.h>`；SSE 也可 `#include <wknet/sse/Sse.h>`。

## 场景

| 场景 | 参考 | 主要 API |
|------|------|----------|
| 最简 GET | [第一个请求](first-request.md)、`HighLevelApiSamples` | `Get` / `ResponseStatusCode` / `ResponseRelease` |
| 同主机多请求（连接池） | 同一 `Session` 连续 `Get` | `SessionCreate` + 复用 |
| POST JSON / 表单 / 文件 | `HighLevelApiSamples` Body 段 | `BodyCreateJson*` / `BodyCreateForm` / `BodyCreateFile*` |
| 自定义请求头 | `HeadersAdd` + `SendEx` | `HeadersCreate` / `SendEx` |
| 流式下载 | `SendOptions.OnHeader` / `OnBody`（可多次回调） | `SendOptionsCreate` + `SendEx` |
| HTTPS + TLS | `ExternalTrustStore`、[TLS 与信任](tls-and-trust.md) | `TlsConfig` / `CertificateStore` |
| 异步请求 | `HighLevelApiSamples` Async 段 | `AsyncGetEx` / `AsyncWait` / `AsyncGetResponse` |
| 异步取消 | Advanced 并发/取消段 | `AsyncCancel` 后仍须 `AsyncWait` + `AsyncRelease` |
| WebSocket 回显 | `HighLevelApiSamples` WS 段 | `websocket::Connect` / `SendText` / `Receive` / `Close` |
| SSE 事件流 | `HighLevelApiSamples` SSE 段、[SSE](sse.md) | `sse::Connect` / `Receive` / `Close` |
| HTTP/3 Auto | [HTTP/3 与 QUIC](http3-quic.md) | `SessionConfig.Http3.Mode` |

## 公共约定

- 调用与释放在 `PASSIVE_LEVEL`
- `Response` 与产生它的 `Request` / `AsyncOp` 分开释放
- 使用过异步 API 时，在卸载路径调用 `wknet::http::Destroy()`
- WebSocket：`Close` 不与同句柄新 I/O 并发；`Message.Data` 在下次收/关前有效
- SSE：`Event` 字段在下次 `Receive` / `Close` 前有效；同一 client 不要并行 `Receive`
- `BodyCreateJson*` 只透传字节，不解析 JSON

句柄规则见 [API 总览](api/overview.md)；错误语义见 [错误码与 FAQ](errors-and-faq.md)。
