# WebSocket 协议指南

`wknet::websocket` 提供 `ws` / `wss` 客户端。`wss` 默认经 TLS ALPN `h2,http/1.1` 协商，优先 RFC 8441 extended CONNECT over HTTP/2；失败则 Auto 回落 HTTP/1.1 Upgrade。`ws://` **不**隐式 h2c。

API 签名见 [WebSocket API](api/websocket.md)；HTTP/2 隧道原语见 [HTTP/2](http2.md)。

## 结论

| 主题 | 行为 |
|------|------|
| 传输 | `TransportMode::Auto`（默认）；`Http11Only` 强制 H1 Upgrade |
| `wss` | 默认 offer `h2,http/1.1`；h2 + `ENABLE_CONNECT_PROTOCOL` → RFC 8441 |
| 分片发送 | `Send*Ex` + `FinalFragment=false` / `SendContinuation` |
| 分片接收 | 默认聚合完整消息；`DeliverFragments=true` 按 wire 交付 |
| permessage-deflate | **opt-in**；默认关；未请求扩展一律拒绝 |
| Close | 主动发 close 后等 peer（3s）；被动 echo 后关 transport |
| `Message.Data` | 指向内部缓冲；**下次 Receive / Close 前**有效 |

## 连接与握手

```cpp
wknet::websocket::ConnectConfig cfg = wknet::websocket::DefaultConnectConfig();
cfg.Url = "wss://echo.example/ws";
cfg.UrlLength = 21;
// cfg.TransportMode = wknet::http::WebSocketTransportMode::Http11Only;
// cfg.PerMessageDeflate.Enable = true;
wknet::websocket::WebSocket* ws = nullptr;
wknet::websocket::ConnectEx(session, &cfg, &ws);
```

- `ConnectConfig.Headers` 可带 `Origin` / `Authorization` / `Cookie` 等。
- **库受控头被拒**：`Host`、`Connection`、`Upgrade`、`Content-Length`、`Transfer-Encoding`、全部 `Sec-WebSocket-*`。
- `Sec-WebSocket-Accept` **常量时间**比对；子协议须为已请求之一。
- 默认**不**跟随 opening-handshake 的 3xx / 401 / 407：返回 `STATUS_NOT_SUPPORTED` 并保留状态码；其它非 101 → `STATUS_INVALID_NETWORK_RESPONSE`。
- 解析 ≤8 地址逐个尝试；取消令牌贯穿；同步路径 `PASSIVE_LEVEL`。

| 传输 | 掩码 |
|------|------|
| HTTP/1.1 Upgrade | 客户端帧**始终掩码**（每帧新随机键） |
| RFC 8441 over H2 | 按规范**无掩码** DATA 隧道 |
| 收到被掩码的服务端帧 | 协议错误 → close **1002** |

## 分片

### 发送

- `SendText` / `SendBinary` 默认整消息、`FinalFragment=true`。
- `*Ex` 设 `FinalFragment=false` 开启分片；后续用 `SendContinuation` / `SendContinuationEx`。
- 库按帧缓冲自动切块：首帧真实 opcode，后续 Continuation。
- 文本消息**跨分片增量 UTF-8 校验**；最终片不完整码点 → `STATUS_INVALID_PARAMETER`。

### 接收

| `DeliverFragments` | 交付形态 |
|--------------------|----------|
| `false`（默认） | 客户端重组完整消息；`FinalFragment=true` |
| `true` | 按 wire：首帧 Text/Binary，续帧 Continuation；`FinalFragment` = 真实 FIN |

文本仍跨片 UTF-8 校验；最终片非法 → close **1007** / `STATUS_INVALID_NETWORK_RESPONSE`。

### `Message.Data` 生命周期

`Message.Data` / `DataLength` 指向库内缓冲，在**同句柄下一次成功 Receive 或 Close 之前**可读。需要跨调用保留时请自行拷贝。

## permessage-deflate（默认关）

- 开启：`ConnectConfig.PerMessageDeflate.Enable=true`。
- 可配 `ClientNoContextTakeover` / `ServerNoContextTakeover` / `ClientMaxWindowBits` / `ServerMaxWindowBits`（仅 `8..15`）。
- H1 Upgrade 与 RFC 8441 共用同一 offer/校验路径；调用方不得手写 `Sec-WebSocket-Extensions`。
- 发送：仅压缩 Text/Binary **首片**设 RSV1；Continuation / 控制帧不设 RSV1。
- 接收：未协商、控制帧、Continuation 上的 RSV1 → 协议错误关闭。
- 解压受 `MaxMessageBytes`、输出容量与膨胀比限制；其它 WebSocket 扩展为**非目标**。

## 控制帧与 Close

| 事件 | 处理 |
|------|------|
| Ping | `AutoReplyPing` 默认开 → 自动 Pong |
| 单次接收控制帧 >100 | close **1008** |
| 被掩码帧 / 分片状态错 | close **1002** |
| 非法 UTF-8（文本/close） | close **1007** |
| 超 `MaxMessageBytes` | close **1009**（`STATUS_BUFFER_TOO_SMALL`） |

合法入站 close 码：1000–1014（除 1004/1005/1006）或 3000–4999；长度恰为 1 的 close payload → 协议错误。

**Close 时序**

1. **主动** `Close` / `CloseEx`：发 close（`CloseEx` reason ≤123 字节）→ 等待 peer close（默认 3s；超时/终止吞为成功）→ 关 transport。  
2. **被动**：收到 peer close → echo → 关 transport。  
3. **并发约束**：`Close` 不得与同句柄「新 I/O 发起」并发；最安全为单线程 连接→发→收→关。

## 边界

- 无默认压缩；无默认握手 redirect / 401/407 跟随。  
- 不支持 WebSocket over HTTP/3（见 [HTTP/3](http3-quic.md) 非目标）。  
- 能力分类措辞以 [能力账本](capability-matrix.md) 为准。
