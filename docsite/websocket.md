# WebSocket 协议 / WebSocket Protocol

帧编解码在 `KernelHttp::websocket`，高层 API 在 `KernelHttp::kws`，客户端实现类见 [客户端类](client-classes.md)。RFC 6455，主路径 HTTP/1.1 Upgrade。

[English](#english) | 简体中文

---

## 简体中文

### 帧编解码（`websocket/WebSocketFrame.h`）

```cpp
enum class WebSocketOpcode : UCHAR {
    Continuation=0x0, Text=0x1, Binary=0x2, Close=0x8, Ping=0x9, Pong=0xA
};
struct WebSocketFrameHeader {
    bool Fin, Masked; WebSocketOpcode Opcode; ULONGLONG PayloadLength;
    UCHAR MaskingKey[4]; SIZE_T HeaderLength;
};
```
常量：client key 16 字节（base64 24）、Accept 值 28、掩码键 4、帧头最大 14、控制帧 payload ≤125。

`WebSocketCodec`（静态）：
- 握手：`GenerateClientKey`、`ComputeAcceptValue`、`ValidateServerHandshake`（校验状态、Accept、子协议）
- 帧：`EncodeClientFrame`（带掩码）、`DecodeFrameHeader`、`DecodeFramePayload`（去掩码）

> 无专门 close-code 枚举；close 状态码以原始 `USHORT` 传递。

### 高层 API（`kws`，见 [高层 API](high-level-api.md)）

`kws::Connect` / `ConnectAsync`、`SendText` / `SendBinary` / `SendContinuation` / `SendPing` / `SendPong`（各有 `*Ex` 带 `SendOptions{ FinalFragment }`）、`Receive` / `ReceiveEx`、`Close` / `CloseEx`、`SelectedSubprotocol`、`AsyncGetWebSocket`。

```cpp
enum class kws::MsgType { Text, Binary, Close, Continuation, Ping, Pong };
struct kws::Message { MsgType Type; const UCHAR* Data; SIZE_T DataLength; bool Final; };
struct kws::ConnectConfig {
    const char* Url; SIZE_T UrlLength;
    const char* Subprotocol; SIZE_T SubprotocolLength;
    khttp::TlsConfig Tls; khttp::AddressFamily Family;
    SIZE_T MaxMessageBytes; bool AutoReplyPing = true;
};
```

### 行为与时序

- 客户端帧**始终掩码**；发送文本帧做 UTF-8 校验。
- 默认接收聚合为完整消息；`AutoReplyPing` 默认自动回 Pong。
- 主动 close：发送 close frame 后关闭 transport；收到 peer close 则 echo 后关闭。
- `Receive` 返回的 `Message.Data` 指向内部缓冲，**下次收/关之前有效**，关闭后勿引用。
- **全双工时序**：`Close` 不得与同句柄「新 I/O 发起」并发；已在飞 I/O 会被安全等待。最安全：单线程内 连接→发→收→关。
- 单次接收处理控制帧上限 `KhWsMaxControlFramesPerReceive=100`（抗洪泛）。

### 边界 / 非目标

- 主路径 HTTP/1.1 Upgrade；不支持自定义 opening handshake headers（Origin/Authorization/Cookie 等需单独策略，延期）。
- 不协商扩展（permessage-deflate 等），服务端返回未请求扩展会被拒绝。
- 不支持接收分片回调式逐帧暴露、不支持 RFC 8441 WebSocket over HTTP/2、不跟随握手 redirect/401。

### 示例（高层）

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

Framing in `KernelHttp::websocket`, high-level API in `KernelHttp::kws`, client class in [Client Classes](client-classes.md). RFC 6455 over HTTP/1.1 Upgrade.

`WebSocketOpcode` Continuation/Text/Binary/Close/Ping/Pong; `WebSocketCodec` handles handshake (`GenerateClientKey`/`ComputeAcceptValue`/`ValidateServerHandshake`) and framing (`EncodeClientFrame` masked, `DecodeFrameHeader`/`DecodeFramePayload`). No close-code enum — codes are raw `USHORT`. Constants: client key 16 (base64 24), accept 28, masking key 4, max frame header 14, control payload ≤125.

High-level `kws`: `Connect`/`ConnectAsync`, `SendText`/`SendBinary`/`SendContinuation`/`SendPing`/`SendPong` (+ `*Ex` with `FinalFragment`), `Receive`/`ReceiveEx`, `Close`/`CloseEx`, `SelectedSubprotocol`. Client frames are always masked; outgoing text is UTF-8 validated; receive aggregates complete messages; `AutoReplyPing` defaults on. `Message.Data` points to an internal buffer valid until the next receive/close. Never run `Close` concurrently with new I/O on the same handle (safest: single-threaded connect→send→recv→close). Up to 100 control frames per receive (anti-flood).

Boundaries: HTTP/1.1 Upgrade only; no custom opening headers, no extension negotiation (permessage-deflate rejected), no fragment callbacks, no RFC 8441, no handshake redirect/401 following.
