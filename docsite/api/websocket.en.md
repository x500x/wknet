# WebSocket API

Namespace: `wknet::websocket`  
Headers: `wknet/websocket/WebSocket.h` · config types in `wknet/http/Types.h` (`namespace wknet::websocket`)

`Connect` / send / receive / close on an existing `http::Session`.

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

| Field | Notes |
|-------|-------|
| `Url` / `UrlLength` | `ws://` or `wss://` |
| `Subprotocol` | Optional subprotocol |
| `Headers` / `HeaderCount` | Caller handshake headers; library-controlled headers (`Upgrade`/`Connection`/`Host`/`Sec-WebSocket-*`) are rejected |
| `Tls` | TLS for `wss` |
| `Family` | Address family |
| `MaxMessageBytes` | Per-message cap |
| `AutoReplyPing` | Auto pong |
| `AllowWebSocketOverHttp2` | RFC 8441 path (see capability matrix) |
| `TransportMode` | `Auto` / `Http11Only` / `Http2Required` / `LegacyBoolean` |
| `PerMessageDeflate` | permessage-deflate options |
| `ChallengeCallback` / `Context` | 3xx / auth challenge retry |
| `MaxHandshakeRetries` | Handshake retry cap |

### Helper types

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

### Signatures

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

### Returns

`STATUS_SUCCESS` or parameter/handshake/network failure. After async completion, take the handle with `AsyncGetWebSocket`.

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

Fragmentation: first `SendText`/`SendBinary` with `FinalFragment=false`, then `SendContinuation`, last frame `FinalFragment=true`.

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

| Field | Notes |
|-------|-------|
| `MaxMessageBytes` | `0` uses connection config cap |
| `AutoAllocate` | Library allocates message buffer |
| `OnMessage` | Optional streaming callback |
| `DeliverFragments` | Deliver per fragment |

## Close / query

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

`Close` / `CloseEx` free the handle; `nullptr` is accepted.

## Notes

- All entry points at `PASSIVE_LEVEL`.
- Requires a live `http::Session`; close WebSocket before or without concurrent session teardown.
- After async connect, `AsyncGetWebSocket` then `AsyncRelease`.

## See also

- [Session & Config](session-config.en.md)
- [Async HTTP](http-async.en.md)
- [TLS options](tls-options.en.md)
- [Cookbook](../cookbook.en.md)
