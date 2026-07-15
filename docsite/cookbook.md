# Cookbook

按任务索引。可编译范例在 `src/wknettest/samples` 和用户态测试里；仓库没有单独的 `samples/Cookbook*` 目录。

## 样例源（真值）

| 路径 | 内容 |
|------|------|
| `src/wknettest/samples/HighLevelApiSamples.cpp` | Session、同步/异步 HTTP 全方法、Body 形态、TLS、HTTP/2、WebSocket |
| `src/wknettest/samples/AdvancedScenarioSamples.cpp` | 重定向、错误状态、大响应、并发异步、超时、TLS 失败、WS 分片 |
| `src/wknettest/samples/ExternalTrustStore.cpp` | 外部信任库 / 证书场景 |
| `src/wknettest/samples/HttpApiSamples.cpp` | 驱动侧样例总入口 |
| `tests/high_level_api_tests.cpp` | 用户态 API 回归 |

入口头：`#include <wknet/Wknet.h>`。WebSocket 亦可 `#include <wknet/websocket/WebSocket.h>`。

## 场景索引

| 场景 | 看哪里 | 关键 API |
|------|--------|---------|
| 最简 GET | [第一个请求](first-request.md)、`HighLevelApiSamples` | `Get` / `ResponseStatusCode` / `ResponseRelease` |
| 同主机多请求（池复用） | 同一 `Session` 连续 `Get` | `SessionCreate` + 复用 |
| POST JSON / 表单 / 文件 | `HighLevelApiSamples` Body 段 | `BodyCreateJson*` / `BodyCreateForm` / `BodyCreateFile*` |
| 自定义请求头 | `HeadersAdd` + `SendEx` | `HeadersCreate` / `SendEx` |
| 流式下载（不整包缓存） | `SendOptions.OnHeader` / `OnBody` | `SendOptionsCreate` + `SendEx` |
| HTTPS + 显式 TLS | `ExternalTrustStore`、[TLS 与信任](tls-and-trust.md) | `TlsConfig` / `CertificateStore` |
| 异步请求 | `HighLevelApiSamples` Async 段 | `AsyncGetEx` / `AsyncWait` / `AsyncGetResponse` |
| 异步取消 | Advanced 并发/取消段 | `AsyncCancel` 后仍须 `AsyncWait` + `AsyncRelease` |
| WebSocket 回显 | `HighLevelApiSamples` WS 段 | `websocket::Connect` / `SendText` / `Receive` / `Close` |
| HTTP/3 Auto | [HTTP/3 与 QUIC](http3-quic.md) | `SessionConfig.Http3.Mode` |

## 纪律（所有场景通用）

1. **IRQL**：调用与守卫式释放均在 `PASSIVE_LEVEL`。
2. **所有权**：`Response` 与发起它的 `Request`/`AsyncOp` 分开释放。
3. **卸载**：用过异步 API 后，卸载前 `wknet::http::Destroy()`。
4. **WebSocket 时序**：`Close` 不与同句柄新 I/O 并发；`Message.Data` 生命周期到下次收/关。
5. **JSON**：库不解析 JSON，只透传字节。

更细的句柄规则见 [API 总览](api/overview.md)；错误语义见 [错误码与 FAQ](errors-and-faq.md)。
