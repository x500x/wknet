# HTTP/2 协议指南

HTTP/2 在 TLS 上经 ALPN `h2` 作为默认安全多路复用路径；同源连接池以 stream 租约复用。无 server push；h2c、后台 PING 与 per-request priority 均为显式能力。

公开入口见 [HTTP 同步](api/http-sync.md) / [会话配置](api/session-config.md)。WebSocket 隧道见 [WebSocket](websocket.md)。

## 结论

| 主题 | 行为 |
|------|------|
| 默认路径 | TLS ALPN `h2`（`PreferHttp2` 默认 true） |
| h2c | **opt-in**：`SendOptions.Http2CleartextMode` = `PriorKnowledge` 或 `Upgrade` |
| 多流复用 | 同源 H2 连接承载多个活动请求；受本地与 peer `MAX_CONCURRENT_STREAMS` 限制 |
| Server push | **不支持**；任何 `PUSH_PROMISE` → 协议错误 |
| Extended CONNECT | RFC 8441；`wss` 默认使用（见 WebSocket） |
| GOAWAY / RST | 未处理 stream 可映射 `STATUS_RETRY`；仅安全方法 fresh retry 一次 |
| 后台 PING | session `Http2KeepAlive.Enabled` 默认 **关** |
| Priority | `SendOptions.Http2Priority` **显式**；不维护本地依赖树调度 |

## 连接与 SETTINGS

- 客户端发送 preface 与 SETTINGS；`ENABLE_PUSH=0`；立即 ACK，不阻塞等待对端 ACK。
- 对端 `ENABLE_PUSH != 0`、非法窗口/帧大小、非法 `ENABLE_CONNECT_PROTOCOL` → 协议/流控错误。
- 缺 ACK 且后续读超时 → GOAWAY `SETTINGS_TIMEOUT`。
- CONTINUATION 洪泛防护：≤64 帧、≤4 空帧（CVE-2024-27316 类）。
- 头块累计超容量 → `ENHANCE_YOUR_CALM` / `STATUS_BUFFER_TOO_SMALL`。
- 连接专属头（`connection`/`transfer-encoding`/`upgrade` 等）禁止；`te` 仅允许 `trailers`。

## 多流与 body

- 连接池对同源 H2 做 stream 租约；帧循环按 stream id 分发 HEADERS/DATA/WINDOW_UPDATE/RST。
- 请求 body 由 body source 驱动，按 `min(连接发送窗口, 流远端窗口, peer MaxFrameSize)` 切 DATA。
- 请求 trailers：body 结束后以 trailing HEADERS + END_STREAM 发送（HTTP/2 头块，有别于 HTTP/1.1 chunked trailer）；拒绝 trailer 伪头；禁止字段规则与 HTTP/1.1 对齐。
- 流控：连接级 + per-stream；`InitialWindowSize` 更新同步到活动流；越界 → `FLOW_CONTROL_ERROR`。
- 1xx interim：拒绝 `:status 101` 与 interim+END_STREAM；其余 interim 重置后继续读最终响应。

## RFC 8441 extended CONNECT

- 形态：`:method: CONNECT` + `:protocol: websocket`。
- 发送前要求 peer `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`，否则 `STATUS_NOT_SUPPORTED` 且不分配 stream。
- 收到 `2xx` 后双向 DATA 作为隧道 payload。
- 这是 HTTP/2 隧道原语；`wknet::websocket` 在 `wss` 默认自动选择，可用 `Http11Only` 强制 HTTP/1.1 Upgrade。

## GOAWAY / RST 与重试

| 条件 | 高层语义 |
|------|----------|
| clean GOAWAY 且活动流 id > lastStreamId | stream **未处理** → `STATUS_RETRY` |
| `REFUSED_STREAM` 且可证明未处理 | `STATUS_RETRY` |
| GOAWAY 错误码非 0 / 其它 RST | 连接断开类失败 |

高层仅对 **安全方法**（`GET`/`HEAD`/`OPTIONS`）做 **一次** fresh retry；带 body 的非幂等方法不自动重放。连接级错误广播给活动流。

## h2c（默认关）

| 模式 | 要点 |
|------|------|
| `PriorKnowledge` | 明文直接 HTTP/2 preface + SETTINGS |
| `Upgrade` | HTTP/1.1 Upgrade；**禁止请求体**；保留 stream 1，重放 101 后残留字节 |
| 默认 | `http://` **不**自动 h2c |

显式非 HTTP ALPN，或设置了 HTTP/2 priority 的请求，不会选用 HTTP/3（见 [HTTP/3 与 QUIC](http3-quic.md)）。

## Priority 与 PING

- **Priority**：`SendOptions.Http2Priority` 在首个 HEADERS 携带 weight/dependency/exclusive（权重 1..256）；拒绝自依赖。不实现复杂本地 priority tree 或带宽调度。
- **后台 PING**：`SessionConfig.Http2KeepAlive.Enabled=true` 显式开启；只扫描 idle 且可复用的池化 H2 连接；ACK 超时或协议错误关闭该 idle 连接。默认 idle/interval 30s，ACK 超时 5s。

## HPACK（行为边界）

- 动态表大小更新仅限块首且 ≤协商值；header-list 按 `name+value+32` 计。
- 编码端对 `authorization` / `cookie` / `proxy-authorization` **强制 Never-Indexed**。
- Huffman 拒绝过长码 / EOS / 非法 padding。

## 默认关闭一览

| 能力 | 开启方式 |
|------|----------|
| h2c | `SendOptions.Http2CleartextMode` |
| 后台 PING | `Http2KeepAlive.Enabled=true` |
| per-request priority | `SendOptions.Http2Priority` |

支持范围见 [能力边界](capability-matrix.md)。
