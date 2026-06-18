# WebSocket 协议 / WebSocket Protocol

帧编解码在 `KernelHttp::websocket`，高层 API 在 `KernelHttp::kws`，客户端实现类见 [客户端类](client-classes.md)。RFC 6455，主路径 HTTP/1.1 Upgrade。内容依据实现代码。

[English](#english) | 简体中文

---

## 简体中文

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
- `ValidateServerHandshake`：要求 `101`、HTTP/1.1、`Connection: Upgrade`、`Upgrade: websocket`、**恰好一个** `Sec-WebSocket-Accept`（**常量时间**比对）；**任何 `Sec-WebSocket-Extensions` 一律拒绝**；子协议须为请求过的之一。
- `EncodeClientFrame`：客户端帧**必掩码**（payload XOR 4 字节键）；控制帧必须 FIN 且 ≤125。
- `DecodeFrameHeader`：保留位 `0x70` 必须为 0；**被掩码的服务端帧 → `STATUS_INVALID_NETWORK_RESPONSE`**；扩展长度强制最短编码。

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
struct kws::ReceiveOptions { SIZE_T MaxMessageBytes; bool AutoAllocate=true; MessageCallback OnMessage; void* CallbackContext; };
struct kws::ConnectConfig { const char* Url; SIZE_T UrlLength; const char* Subprotocol; SIZE_T SubprotocolLength;
                            khttp::TlsConfig Tls; khttp::AddressFamily Family; SIZE_T MaxMessageBytes; bool AutoReplyPing=true; };
```

### 分片（**已支持**）

- **发送**：`kws::SendContinuation(Ex)` 续帧；`SendText/SendBinary` 的 `*Ex` 可带 `FinalFragment=false` 开启分片。客户端会按帧缓冲自动分块（首帧用真实 opcode，后续用 Continuation），并对文本消息**跨分片增量 UTF-8 校验**，最终片不完整码点 → `STATUS_INVALID_PARAMETER`。
- **接收**：`ReceiveOptions.OnMessage` 回调或默认返回式，二者都返回**客户端已重组的完整消息**（内核路径上回调的 `finalFragment` 恒为 true，即按消息回调，而非逐 wire 分片）。`Message.Data` 指向内部缓冲，下次收/关前有效。

### 行为与时序

- 控制帧：`AutoReplyPing`（默认开）自动回 Pong；单次接收控制帧 > 100 → close 1008（`KhWsMaxControlFramesPerReceive`）。
- 校验失败均以 close 帧失败连接：被掩码帧/分片状态错 → **1002**；文本/close payload 非法 UTF-8 → **1007**；累计超 `MaxMessageBytes` → **1009**（`STATUS_BUFFER_TOO_SMALL`）。
- 合法接收 close 码：1000–1014（除 1004/1005/1006）或 3000–4999；长度恰为 1 的 close payload → 协议错误。
- close 握手：主动 `Close` 发空 close 后 `WaitForPeerClose`（`WskCloseTimeoutMilliseconds = 3000` 超时，吞掉终止/超时为成功）；被动收到 peer close 则 echo 后关 transport。`CloseEx` reason ≤123 字节。
- 连接：解析 ≤8 地址逐个尝试；WS 握手 ALPN 固定 `http/1.1`（协商到非 http/1.1 → `STATUS_NOT_SUPPORTED`）；每地址都做 TLS1.2 确认重连；取消令牌贯穿。
- **全双工时序**：`Close` 不得与同句柄「新 I/O 发起」并发；最安全单线程内 连接→发→收→关。

### 边界 / 非目标

主路径 HTTP/1.1 Upgrade；不支持自定义 opening headers、扩展协商（permessage-deflate 拒绝）、RFC 8441 over HTTP/2、握手 redirect/401 跟随。

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

---

## English

Framing in `KernelHttp::websocket`, high-level API in `KernelHttp::kws`. `WebSocketOpcode` Continuation/Text/Binary/Close/Ping/Pong. `WebSocketCodec`: `GenerateClientKey` (16 random bytes→base64, wiped), `ComputeAcceptValue` (SHA-1 of key+GUID), `ValidateServerHandshake` (requires 101/HTTP1.1/Upgrade, exactly one `Sec-WebSocket-Accept` compared **constant-time**, **rejects any `Sec-WebSocket-Extensions`**), `EncodeClientFrame` (always masked), `DecodeFrameHeader` (reserved bits must be 0; **masked server frame → error**).

**Fragmentation**: send is fully granular via `kws::SendContinuation(Ex)` / `FinalFragment=false` (auto-chunked to the frame buffer, with incremental cross-fragment UTF-8 validation of text). Receive (via `ReceiveOptions.OnMessage` callback or the default return form) always delivers a **client-reassembled complete message** — on the kernel path the callback's `finalFragment` is always true (per-message, not per-wire-fragment). `Message.Data` is valid until the next receive/close.

Behavior: auto-Pong (toggleable); >100 control frames per receive → close **1002** lineage (masked/fragment-state errors), **1007** (bad UTF-8), **1008** (control flood), **1009** (over `MaxMessageBytes`). Valid incoming close codes 1000–1014 (minus 1004/1005/1006) or 3000–4999. Active close sends an empty close then waits for peer close (3 s timeout, swallowed as success); passive close echoes then closes. WS handshake ALPN is forced to `http/1.1`. Never run `Close` concurrently with new I/O on the same handle. Boundaries: HTTP/1.1 Upgrade only, no custom opening headers, no extension negotiation, no RFC 8441, no handshake redirect/401 following.
