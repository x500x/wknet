# WebSocket API

命名空间：`wknet::websocket`  
头文件：`wknet/websocket/WebSocket.h` · 配置类型在 `wknet/http/Types.h`（`namespace wknet::websocket`）

## 职责

在已有 `http::Session` 上建立 WebSocket，收发帧，关闭连接。

## ConnectConfig

```cpp
ConnectConfig DefaultConnectConfig() noexcept;

struct ConnectConfig final {
    const char* Url = nullptr;
    SIZE_T UrlLength = 0;
    const char* Subprotocol = nullptr;
    SIZE_T SubprotocolLength = 0;
    const Header* Headers = nullptr;
    SIZE_T HeaderCount = 0;
    wknet::http::TlsConfig Tls = {};
    wknet::http::AddressFamily Family = wknet::http::AddressFamily::Any;
    SIZE_T MaxMessageBytes = wknet::http::DefaultMaxWebSocketMessageBytes; // 1 MiB
    bool AutoReplyPing = true;
    bool AllowWebSocketOverHttp2 = false;
    wknet::http::WebSocketTransportMode TransportMode =
        wknet::http::WebSocketTransportMode::Auto;
    PerMessageDeflateOptions PerMessageDeflate = {};
    HandshakeChallengeCallback ChallengeCallback = nullptr;
    void* ChallengeContext = nullptr;
    ULONG MaxHandshakeRetries = 0;
};
```

| 字段 | 说明 |
|------|------|
| `Url` / `UrlLength` | `ws://` 或 `wss://` |
| `Subprotocol` | 可选子协议 |
| `Headers` / `HeaderCount` | 调用方握手头（`Origin` 等）；库控制头（`Upgrade`/`Connection`/`Host`/`Sec-WebSocket-*`）拒收 |
| `Tls` | `wss` TLS |
| `Family` | 地址族 |
| `MaxMessageBytes` | 单消息上限 |
| `AutoReplyPing` | 自动 Pong |
| `AllowWebSocketOverHttp2` | 允许 RFC 8441 路径（能力边界见能力矩阵） |
| `TransportMode` | `Auto` / `Http11Only` / `Http2Required` / `LegacyBoolean` |
| `PerMessageDeflate` | permessage-deflate 选项 |
| `ChallengeCallback` / `Context` | 3xx/认证挑战重试 |
| `MaxHandshakeRetries` | 握手重试上限 |

### 辅助类型

```cpp
struct Header final {
    const char* Name = nullptr; SIZE_T NameLength = 0;
    const char* Value = nullptr; SIZE_T ValueLength = 0;
};

struct PerMessageDeflateOptions final {
    bool Enable = false;
    bool ClientNoContextTakeover = false;
    bool ServerNoContextTakeover = false;
    UCHAR ClientMaxWindowBits = 15;
    UCHAR ServerMaxWindowBits = 15;
};

struct HandshakeChallenge final {
    USHORT StatusCode = 0;
    const ResponseHeader* Headers = nullptr;
    SIZE_T HeaderCount = 0;
    bool Redirect = false;
    bool AuthenticationChallenge = false;
};

struct HandshakeRetryAction final {
    const char* RedirectPath = nullptr;
    SIZE_T RedirectPathLength = 0;
    const Header* Headers = nullptr;
    SIZE_T HeaderCount = 0;
};

typedef NTSTATUS (*HandshakeChallengeCallback)(
    void* context,
    const HandshakeChallenge* challenge,
    HandshakeRetryAction* action);
```

## Connect

### 签名

```cpp
NTSTATUS Connect(
    _In_ wknet::http::Session* session,
    _In_reads_bytes_(urlLength) const char* url,
    SIZE_T urlLength,
    _Out_ WebSocket** websocket) noexcept;

NTSTATUS Connect(
    _In_ wknet::http::Session* session,
    _In_ const ConnectConfig* config,
    _Out_ WebSocket** websocket) noexcept;

NTSTATUS ConnectEx(
    _In_ wknet::http::Session* session,
    _In_ const ConnectConfig* config,
    _Out_ WebSocket** websocket) noexcept;

NTSTATUS ConnectAsync(
    _In_ wknet::http::Session* session,
    _In_reads_bytes_(urlLength) const char* url,
    SIZE_T urlLength,
    _Out_ wknet::http::AsyncOp** operation) noexcept;

NTSTATUS ConnectAsync(
    _In_ wknet::http::Session* session,
    _In_ const ConnectConfig* config,
    _Out_ wknet::http::AsyncOp** operation) noexcept;

NTSTATUS ConnectAsyncEx(
    _In_ wknet::http::Session* session,
    _In_ const ConnectConfig* config,
    _Out_ wknet::http::AsyncOp** operation) noexcept;

NTSTATUS AsyncGetWebSocket(
    _In_ wknet::http::AsyncOp* operation,
    _Out_ WebSocket** websocket) noexcept;
```

### 返回

`STATUS_SUCCESS` 或参数/握手/网络失败状态。异步路径完成后 `AsyncGetWebSocket` 取句柄。

## Send

```cpp
NTSTATUS SendText(_In_ WebSocket* websocket,
    _In_reads_bytes_(textLength) const char* text, SIZE_T textLength) noexcept;
NTSTATUS SendTextEx(..., _In_opt_ const SendOptions* options) noexcept;

NTSTATUS SendBinary(_In_ WebSocket* websocket,
    _In_reads_bytes_(dataLength) const UCHAR* data, SIZE_T dataLength) noexcept;
NTSTATUS SendBinaryEx(..., _In_opt_ const SendOptions* options) noexcept;

NTSTATUS SendContinuation(_In_ WebSocket* websocket,
    _In_reads_bytes_(dataLength) const UCHAR* data, SIZE_T dataLength) noexcept;
NTSTATUS SendContinuationEx(..., _In_opt_ const SendOptions* options) noexcept;

NTSTATUS SendPing(_In_ WebSocket* websocket,
    _In_reads_bytes_opt_(payloadLength) const UCHAR* payload, SIZE_T payloadLength) noexcept;
NTSTATUS SendPong(_In_ WebSocket* websocket,
    _In_reads_bytes_opt_(payloadLength) const UCHAR* payload, SIZE_T payloadLength) noexcept;

struct SendOptions final {
    bool FinalFragment = true;
};
```

分片：首帧 `SendText`/`SendBinary` 且 `FinalFragment=false`，后续 `SendContinuation`，最后一帧 `FinalFragment=true`。

## Receive

```cpp
struct ReceiveOptions final {
    SIZE_T MaxMessageBytes = 0;
    bool AutoAllocate = true;
    MessageCallback OnMessage = nullptr;
    void* CallbackContext = nullptr;
    bool DeliverFragments = false;
};

struct Message final {
    MsgType Type = MsgType::Binary;
    const UCHAR* Data = nullptr;
    SIZE_T DataLength = 0;
    bool Final = true;
    bool FinalFragment = true;
};

enum class MsgType : ULONG {
    Text = 0, Binary = 1, Close = 2,
    Continuation = 3, Ping = 4, Pong = 5
};

typedef NTSTATUS (*MessageCallback)(
    void* context, MsgType type,
    const UCHAR* data, SIZE_T dataLength, bool finalFragment);

NTSTATUS Receive(_In_ WebSocket* websocket, _Out_ Message* message) noexcept;
NTSTATUS ReceiveEx(
    _In_ WebSocket* websocket,
    _In_opt_ const ReceiveOptions* options,
    _Out_opt_ Message* message) noexcept;
```

| 字段 | 说明 |
|------|------|
| `MaxMessageBytes` | `0` 时用连接配置上限 |
| `AutoAllocate` | 库分配消息缓冲 |
| `OnMessage` | 可选流式回调 |
| `DeliverFragments` | 按分片交付 |

## Close / 查询

```cpp
NTSTATUS Close(_In_opt_ WebSocket* websocket) noexcept;
NTSTATUS CloseEx(
    _In_opt_ WebSocket* websocket,
    USHORT statusCode,
    _In_reads_bytes_opt_(reasonLength) const UCHAR* reason,
    SIZE_T reasonLength) noexcept;

NTSTATUS SelectedSubprotocol(
    _In_ WebSocket* websocket,
    _Outptr_result_bytebuffer_(*subprotocolLength) const char** subprotocol,
    _Out_ SIZE_T* subprotocolLength) noexcept;
```

`Close` / `CloseEx` 释放句柄；接受 `nullptr`。

## 备注

- 全部入口 `PASSIVE_LEVEL`。
- 依赖有效 `http::Session`；关闭顺序：先 `WebSocket`，再 session（或确保无并发使用）。
- 异步连接完成后用 `AsyncGetWebSocket`，再 `AsyncRelease`。

## 相关链接

- [会话与配置](session-config.md)
- [异步 HTTP](http-async.md)
- [证书与 TLS](tls-options.md)
- [Cookbook](../cookbook.md)
