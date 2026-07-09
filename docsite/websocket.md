# WebSocket 协议

### 帧编解码（`websocket/WebSocketFrame.cpp`）

```cpp
enum class WebSocketOpcode : UCHAR {
    Continuation=0x0, Text=0x1, Binary=0x2, Close=0x8, Ping=0x9, Pong=0xA
};
```
常量：client key 16 字节（base64 24）、Accept 28、掩码键 4、帧头最大 14、控制帧 payload ≤125。

`WebSocketCodec`（静态）：
- `GenerateClientKey`：16 随机字节（CNG）→ base64，用后清零。
- `ComputeAcceptValue`：SHA-1(`key + 258EAFA5-...`) → base64。
- `ValidateServerHandshake`：要求 `101`、HTTP/1.1、`Connection: Upgrade`、`Upgrade: websocket`、**恰好一个** `Sec-WebSocket-Accept`（**常量时间**比对）；只接受已请求且参数合法的 `permessage-deflate`，未请求扩展、未知扩展、重复/非法参数一律拒绝；子协议须为请求过的之一。
- `EncodeClientFrame`：客户端帧**必掩码**（payload XOR 4 字节键）；控制帧必须 FIN 且 ≤125。
- `DecodeFrameHeader`：RSV2/RSV3 必须为 0；RSV1 仅供已协商的 `permessage-deflate` 首个 Text/Binary 片使用；**被掩码的服务端帧 → `STATUS_INVALID_NETWORK_RESPONSE`**；扩展长度强制最短编码。

### 高层 API（`kws`，见 [高层 API](high-level-api.md)）

```cpp
// 连接（同步/异步，URL 或 ConnectConfig）
kws::Connect / ConnectEx / ConnectAsync / ConnectAsyncEx ; kws::AsyncGetWebSocket
// 发送（各有 *Ex 带 SendOptions{ bool FinalFragment }）
kws::SendText / SendBinary / SendContinuation / SendPing / SendPong
// 接收 / 关闭 / 查询
kws::Receive / ReceiveEx ; kws::Close / CloseEx ; kws::SelectedSubprotocol
```
```cpp
enum class kws::MsgType { Text, Binary, Close, Continuation, Ping, Pong };
struct kws::Message { MsgType Type; const UCHAR* Data; SIZE_T DataLength; bool Final; bool FinalFragment; };
struct kws::ReceiveOptions { SIZE_T MaxMessageBytes; bool AutoAllocate=true; MessageCallback OnMessage; void* CallbackContext; bool DeliverFragments=false; };
struct kws::Header { const char* Name; SIZE_T NameLength; const char* Value; SIZE_T ValueLength; };
struct kws::ConnectConfig { const char* Url; SIZE_T UrlLength; const char* Subprotocol; SIZE_T SubprotocolLength;
                            const Header* Headers; SIZE_T HeaderCount;
                            websocket::PerMessageDeflateOptions PerMessageDeflate;
                            khttp::TlsConfig Tls; khttp::AddressFamily Family; SIZE_T MaxMessageBytes; bool AutoReplyPing=true; };
```

### Opening handshake headers

- `ConnectConfig.Headers` 可传调用方自定义握手头，例如 `Origin`、`Authorization`、`Cookie`。
- 为防止握手被篡改，库受控头会被拒绝：`Host`、`Connection`、`Upgrade`、`Content-Length`、`Transfer-Encoding`、`Sec-WebSocket-Key`、`Sec-WebSocket-Version`、`Sec-WebSocket-Protocol`、`Sec-WebSocket-Extensions`。
- 字段名/值走普通 HTTP header 文本校验，拒绝空名、超限长度、控制字符与 CRLF 注入。
- 默认不跟随 opening-handshake 的 redirect、401/407 challenge：3xx/401/407 返回 `STATUS_NOT_SUPPORTED` 并保留握手状态码；其它非 101 响应返回 `STATUS_INVALID_NETWORK_RESPONSE`。跨源 redirect、认证重放等若未来支持，必须通过显式 opt-in 并沿用 HTTP redirect 安全规则。

### permessage-deflate（显式 opt-in）

- 默认关闭：`DefaultConnectConfig()` 不启用压缩，零初始化配置也不启用压缩；未请求时服务端返回任何扩展都会拒绝。
- 启用方式：设置 `ConnectConfig.PerMessageDeflate.Enable=true`。可配置 `ClientNoContextTakeover`、`ServerNoContextTakeover`、`ClientMaxWindowBits`、`ServerMaxWindowBits`，window bits 只接受 `8..15`，非法配置返回 `STATUS_INVALID_PARAMETER`。
- 握手：HTTP/1.1 Upgrade 与 RFC 8441 HTTP/2 Extended CONNECT 使用同一 offer 生成逻辑；调用方仍不能在 `Headers` 中手写 `Sec-WebSocket-Extensions`。
- 数据路径：发送 Text/Binary 首片压缩并设置 RSV1，Continuation 不设置 RSV1；接收时只允许首片 Text/Binary 携带 RSV1，control frame、Continuation、未协商压缩时出现 RSV1 均按协议错误关闭。
- 安全边界：解压受 `MaxMessageBytes`、输出容量与膨胀比限制约束；context takeover 按协商结果保留或在每条消息后重置。

### 分片（**已支持**）

- **发送**：`kws::SendContinuation(Ex)` 续帧；`SendText/SendBinary` 的 `*Ex` 可带 `FinalFragment=false` 开启分片。客户端会按帧缓冲自动分块（首帧用真实 opcode，后续用 Continuation），并对文本消息**跨分片增量 UTF-8 校验**，最终片不完整码点 → `STATUS_INVALID_PARAMETER`。
- **接收**：默认 `ReceiveOptions.DeliverFragments=false`，`ReceiveOptions.OnMessage` 回调或默认返回式都返回**客户端已重组的完整消息**，`finalFragment=true`。显式设置 `DeliverFragments=true` 后，接收路径按 wire fragment 交付：首帧返回 Text/Binary，续帧返回 Continuation，`finalFragment` 承载真实 FIN；文本消息仍跨分片做增量 UTF-8 校验，最终片不完整码点 → close 1007 / `STATUS_INVALID_NETWORK_RESPONSE`。`Message.Data` 指向内部缓冲，下次收/关前有效。

### 行为与时序

- 控制帧：`AutoReplyPing`（默认开）自动回 Pong；单次接收控制帧 > 100 → close 1008（`KhWsMaxControlFramesPerReceive`）。
- 校验失败均以 close 帧失败连接：被掩码帧/分片状态错 → **1002**；文本/close payload 非法 UTF-8 → **1007**；累计超 `MaxMessageBytes` → **1009**（`STATUS_BUFFER_TOO_SMALL`）。
- 合法接收 close 码：1000–1014（除 1004/1005/1006）或 3000–4999；长度恰为 1 的 close payload → 协议错误。
- close 握手：主动 `Close` 发空 close 后 `WaitForPeerClose`（`WskCloseTimeoutMilliseconds = 3000` 超时，吞掉终止/超时为成功）；被动收到 peer close 则 echo 后关 transport。`CloseEx` reason ≤123 字节。
- 连接：解析 ≤8 地址逐个尝试；默认 WS 握手 ALPN 为 `http/1.1`；`AllowWebSocketOverHttp2` 对 `wss` offer `h2,http/1.1`，协商到 h2 后走 RFC 8441，协商到其它未 offer 协议 → `STATUS_NOT_SUPPORTED`；每地址都做 TLS1.2 确认重连；取消令牌贯穿。
- **全双工时序**：`Close` 不得与同句柄「新 I/O 发起」并发；最安全单线程内 连接→发→收→关。

### 边界 / 非目标

高层 `kws` 默认仍是 HTTP/1.1 Upgrade；支持自定义 opening headers；`permessage-deflate` 仅显式 opt-in，默认不协商；`wss` 设置 `ConnectConfig.AllowWebSocketOverHttp2=true` 后可通过 RFC 8441 extended CONNECT over HTTP/2 建立隧道，peer 未启用 `SETTINGS_ENABLE_CONNECT_PROTOCOL` 时 fail-closed；`ws://` 不隐式走 h2c；不跟随握手 redirect/401/407。

### 示例

```cpp
kws::WebSocket* ws = nullptr;
if (NT_SUCCESS(kws::Connect(session, "wss://echo.example/ws", 21, &ws))) {
    kws::SendText(ws, "hello", 5);
    kws::Message msg = {};
    if (NT_SUCCESS(kws::Receive(ws, &msg)) && msg.Type == kws::MsgType::Text) {
        // 使用 msg.Data / msg.DataLength（下次收/关前有效）
    }
    kws::Close(ws);
}
```
