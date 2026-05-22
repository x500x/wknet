# HTTP/2 客户端实现设计

**目标：** 在现有内核 HTTP/HTTPS 客户端基础上，新增完整的 HTTP/2 客户端能力。通过 TLS ALPN 协商 `h2`，实现 RFC 9113 定义的帧层、HPACK 头部压缩、stream 多路复用和流控，对外提供 `Http2Client` 入口，并让 `HttpsClient` 根据 ALPN 协商结果自动选择 HTTP/1.1 或 HTTP/2。

**协议范围：** 仅支持 h2 over TLS（不支持 h2c 明文）。客户端角色，不实现服务端。PUSH_PROMISE 按 RFC 9113 Section 8.4 拒绝（发送 SETTINGS_ENABLE_PUSH=0，收到 PUSH_PROMISE 回 PROTOCOL_ERROR）。

**参考规范：**
- [RFC 9113 HTTP/2](https://datatracker.ietf.org/doc/html/rfc9113)
- [RFC 7541 HPACK](https://datatracker.ietf.org/doc/html/rfc7541)
- [RFC 7301 TLS ALPN](https://datatracker.ietf.org/doc/html/rfc7301)

---

## 架构概览

```
HttpsClient (自动协商)
    |
    +-- ALPN 结果 == "h2" --> Http2Client
    |                            |
    |                            +-- Http2Connection (连接前导 + SETTINGS)
    |                            |       |
    |                            |       +-- Http2FrameCodec (帧编解码)
    |                            |       +-- HpackEncoder / HpackDecoder
    |                            |       +-- Http2Stream[] (状态机)
    |                            |       +-- Http2FlowControl (窗口管理)
    |                            |
    +-- ALPN 结果 == "http/1.1" 或无 ALPN --> 现有 HTTP/1.1 路径
```

新增文件全部位于 `src/KernelHttp/http2/` 目录下，与现有 `http/` 目录平行。

---

## 模块设计

### 1. TLS ALPN 扩展

**改动文件：**
- `src/KernelHttp/tls/TlsHandshake12.h` — `TlsClientHelloOptions` 增加 ALPN 字段
- `src/KernelHttp/tls/TlsHandshake12.cpp` — `EncodeClientHello` 编码 ALPN 扩展 (ext type 0x0010)
- `src/KernelHttp/tls/TlsConnection.h` — `TlsClientConnectionOptions` 增加 ALPN 字段；`TlsConnection` 暴露协商结果
- `src/KernelHttp/tls/TlsConnection.cpp` — 解析 ServerHello 扩展中的 ALPN 选中协议

**数据结构：**

```cpp
struct TlsAlpnProtocol final
{
    const char* Name = nullptr;
    SIZE_T NameLength = 0;
};

// TlsClientHelloOptions 新增：
const TlsAlpnProtocol* AlpnProtocols = nullptr;
SIZE_T AlpnProtocolCount = 0;

// TlsClientConnectionOptions 新增：
const TlsAlpnProtocol* AlpnProtocols = nullptr;
SIZE_T AlpnProtocolCount = 0;

// TlsConnection 新增查询接口：
const char* NegotiatedAlpn() const noexcept;
SIZE_T NegotiatedAlpnLength() const noexcept;
```

**编码格式（ClientHello ALPN 扩展）：**
```
Extension Type: 0x0010 (2 bytes)
Extension Length: N (2 bytes)
  Protocol List Length: N-2 (2 bytes)
    Protocol Name Length: L1 (1 byte)
    Protocol Name: "h2" (L1 bytes)
    Protocol Name Length: L2 (1 byte)
    Protocol Name: "http/1.1" (L2 bytes)
```

**解析：** 在 ServerHello 扩展遍历中识别 ext type 0x0010，提取选中的协议名存入 `TlsConnection` 内部缓冲区。

---

### 2. HPACK 编解码 (RFC 7541)

**新增文件：**
- `src/KernelHttp/http2/Hpack.h`
- `src/KernelHttp/http2/Hpack.cpp`

**核心组件：**

#### 2.1 整数编码/解码

RFC 7541 Section 5.1 的前缀整数编码。支持 5/6/7 位前缀。

```cpp
NTSTATUS HpackEncodeInteger(ULONG value, UCHAR prefix, UCHAR prefixBits,
    UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;

NTSTATUS HpackDecodeInteger(const UCHAR* src, SIZE_T length,
    UCHAR prefixBits, ULONG* value, SIZE_T* bytesConsumed) noexcept;
```

#### 2.2 Huffman 编解码

RFC 7541 Appendix B 的 Huffman 表。编码用查表，解码用状态机（256 状态 x 16 nibble 转移表，约 4KB）。

```cpp
NTSTATUS HpackHuffmanEncode(const UCHAR* src, SIZE_T srcLen,
    UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;

NTSTATUS HpackHuffmanDecode(const UCHAR* src, SIZE_T srcLen,
    UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;
```

#### 2.3 静态表

RFC 7541 Appendix A 的 61 项静态表，编译期 constexpr 数组。

#### 2.4 动态表

```cpp
class HpackDynamicTable final
{
public:
    NTSTATUS Initialize(SIZE_T maxSize) noexcept;
    void UpdateMaxSize(SIZE_T newMaxSize) noexcept;
    void Insert(const UCHAR* name, SIZE_T nameLen,
                const UCHAR* value, SIZE_T valueLen) noexcept;
    // 索引 62 起始
    bool Lookup(SIZE_T index, const UCHAR** name, SIZE_T* nameLen,
                const UCHAR** value, SIZE_T* valueLen) const noexcept;
    SIZE_T EntryCount() const noexcept;
    void Reset() noexcept;

private:
    // 环形缓冲区实现，避免频繁分配
    UCHAR* buffer_ = nullptr;
    SIZE_T bufferCapacity_ = 0;
    SIZE_T currentSize_ = 0;
    SIZE_T maxSize_ = 4096; // SETTINGS_HEADER_TABLE_SIZE 默认值
    // 条目索引数组
    struct Entry { SIZE_T nameOffset; SIZE_T nameLen; SIZE_T valueOffset; SIZE_T valueLen; SIZE_T entrySize; };
    Entry* entries_ = nullptr;
    SIZE_T entryCapacity_ = 0;
    SIZE_T entryCount_ = 0;
    SIZE_T entryHead_ = 0; // 环形头
};
```

#### 2.5 编码器/解码器

```cpp
class HpackDecoder final
{
public:
    NTSTATUS Initialize(SIZE_T maxTableSize) noexcept;
    void Reset() noexcept;

    // 解码一个完整的 header block fragment
    NTSTATUS Decode(const UCHAR* block, SIZE_T blockLen,
                    http::HttpHeader* headers, SIZE_T headerCapacity,
                    SIZE_T* headerCount) noexcept;

private:
    HpackDynamicTable table_;
};

class HpackEncoder final
{
public:
    NTSTATUS Initialize(SIZE_T maxTableSize) noexcept;
    void Reset() noexcept;

    // 编码 pseudo-headers + regular headers
    NTSTATUS Encode(const http::HttpHeader* headers, SIZE_T headerCount,
                    UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;

private:
    HpackDynamicTable table_;
};
```

---

### 3. HTTP/2 帧层 (RFC 9113 Section 4)

**新增文件：**
- `src/KernelHttp/http2/Http2Frame.h`
- `src/KernelHttp/http2/Http2Frame.cpp`

**帧头格式（9 字节）：**
```
Length (24 bits) | Type (8 bits) | Flags (8 bits) | Reserved (1 bit) | Stream ID (31 bits)
```

**帧类型枚举：**
```cpp
enum class Http2FrameType : UCHAR
{
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9
};
```

**帧标志：**
```cpp
namespace Http2FrameFlags
{
    constexpr UCHAR EndStream = 0x01;
    constexpr UCHAR Ack = 0x01;       // SETTINGS/PING
    constexpr UCHAR EndHeaders = 0x04;
    constexpr UCHAR Padded = 0x08;
    constexpr UCHAR Priority = 0x20;
}
```

**帧视图结构：**
```cpp
struct Http2FrameHeader final
{
    ULONG Length = 0;        // payload 长度 (max 16384 默认, 可协商到 16MB)
    Http2FrameType Type = Http2FrameType::Data;
    UCHAR Flags = 0;
    ULONG StreamId = 0;
};

struct Http2FrameView final
{
    Http2FrameHeader Header = {};
    const UCHAR* Payload = nullptr;
};
```

**编解码接口：**
```cpp
class Http2FrameCodec final
{
public:
    static constexpr SIZE_T FrameHeaderLength = 9;
    static constexpr ULONG DefaultMaxFrameSize = 16384;
    static constexpr ULONG MaxAllowedFrameSize = 16777215;

    static NTSTATUS EncodeFrameHeader(const Http2FrameHeader& header,
        UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;

    static NTSTATUS DecodeFrameHeader(const UCHAR* src, SIZE_T length,
        Http2FrameHeader* header) noexcept;

    // 编码完整帧（header + payload）
    static NTSTATUS EncodeFrame(const Http2FrameHeader& header,
        const UCHAR* payload, SIZE_T payloadLen,
        UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;

    // SETTINGS 帧编码
    static NTSTATUS EncodeSettings(const Http2Settings& settings,
        UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;

    // SETTINGS ACK
    static NTSTATUS EncodeSettingsAck(
        UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;

    // WINDOW_UPDATE
    static NTSTATUS EncodeWindowUpdate(ULONG streamId, ULONG increment,
        UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;

    // PING / PING ACK
    static NTSTATUS EncodePing(const UCHAR opaqueData[8], bool ack,
        UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;

    // GOAWAY
    static NTSTATUS EncodeGoAway(ULONG lastStreamId, ULONG errorCode,
        UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;

    // RST_STREAM
    static NTSTATUS EncodeRstStream(ULONG streamId, ULONG errorCode,
        UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;

    // HEADERS 帧（含 CONTINUATION 分片）
    static NTSTATUS EncodeHeaders(ULONG streamId, const UCHAR* headerBlock,
        SIZE_T headerBlockLen, bool endStream, ULONG maxFrameSize,
        UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;

    // DATA 帧（含分片）
    static NTSTATUS EncodeData(ULONG streamId, const UCHAR* data,
        SIZE_T dataLen, bool endStream, ULONG maxFrameSize,
        UCHAR* dest, SIZE_T capacity, SIZE_T* bytesWritten) noexcept;
};
```

---

### 4. HTTP/2 SETTINGS

**新增文件：** 包含在 `Http2Frame.h` 中

```cpp
enum class Http2SettingId : USHORT
{
    HeaderTableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6
};

struct Http2Settings final
{
    ULONG HeaderTableSize = 4096;
    ULONG EnablePush = 0;           // 客户端始终为 0
    ULONG MaxConcurrentStreams = 100;
    ULONG InitialWindowSize = 65535;
    ULONG MaxFrameSize = 16384;
    ULONG MaxHeaderListSize = 8192;
};
```

---

### 5. HTTP/2 Stream 状态机

**新增文件：**
- `src/KernelHttp/http2/Http2Stream.h`
- `src/KernelHttp/http2/Http2Stream.cpp`

**状态（RFC 9113 Section 5.1）：**
```cpp
enum class Http2StreamState : UCHAR
{
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed
};
```

注：客户端发起的 stream 不会进入 ReservedLocal/ReservedRemote（不使用 PUSH_PROMISE）。

```cpp
class Http2Stream final
{
public:
    ULONG StreamId() const noexcept;
    Http2StreamState State() const noexcept;

    // 状态转移
    NTSTATUS SendHeaders(bool endStream) noexcept;
    NTSTATUS SendData(bool endStream) noexcept;
    NTSTATUS ReceiveHeaders(bool endStream) noexcept;
    NTSTATUS ReceiveData(bool endStream) noexcept;
    NTSTATUS ReceiveRstStream() noexcept;
    NTSTATUS SendRstStream() noexcept;

    // 流级窗口
    LONG LocalWindow() const noexcept;
    LONG RemoteWindow() const noexcept;
    void ConsumeLocalWindow(ULONG bytes) noexcept;
    void GrantLocalWindow(ULONG increment) noexcept;
    void GrantRemoteWindow(ULONG increment) noexcept;

    // 响应数据收集
    UCHAR* ResponseHeaderBlock = nullptr;
    SIZE_T ResponseHeaderBlockLength = 0;
    SIZE_T ResponseHeaderBlockCapacity = 0;
    UCHAR* ResponseBody = nullptr;
    SIZE_T ResponseBodyLength = 0;
    SIZE_T ResponseBodyCapacity = 0;
    ULONG ErrorCode = 0;

private:
    ULONG streamId_ = 0;
    Http2StreamState state_ = Http2StreamState::Idle;
    LONG localWindow_ = 65535;
    LONG remoteWindow_ = 65535;
};
```

---

### 6. HTTP/2 连接管理

**新增文件：**
- `src/KernelHttp/http2/Http2Connection.h`
- `src/KernelHttp/http2/Http2Connection.cpp`

```cpp
class Http2Connection final
{
public:
    Http2Connection() noexcept = default;
    ~Http2Connection() noexcept;

    Http2Connection(const Http2Connection&) = delete;
    Http2Connection& operator=(const Http2Connection&) = delete;

    // 建立 HTTP/2 连接（发送连接前导 + 初始 SETTINGS，接收对端 SETTINGS 并 ACK）
    _Must_inspect_result_
    NTSTATUS Initialize(
        net::WskSocket& socket,
        tls::TlsConnection& tls) noexcept;

    // 发送请求并读取响应（同步，单 stream）
    _Must_inspect_result_
    NTSTATUS SendRequest(
        net::WskSocket& socket,
        tls::TlsConnection& tls,
        const http::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const UCHAR* body,
        SIZE_T bodyLength,
        http::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        UCHAR* responseBody,
        SIZE_T responseBodyCapacity,
        SIZE_T* responseBodyLength,
        USHORT* statusCode) noexcept;

    // 优雅关闭（发送 GOAWAY）
    NTSTATUS Shutdown(
        net::WskSocket& socket,
        tls::TlsConnection& tls) noexcept;

private:
    // 发送原始字节（通过 TLS）
    NTSTATUS SendRaw(net::WskSocket& socket, tls::TlsConnection& tls,
        const UCHAR* data, SIZE_T length) noexcept;

    // 读取并处理帧
    NTSTATUS ReadFrame(net::WskSocket& socket, tls::TlsConnection& tls,
        Http2FrameView* frame) noexcept;

    // 处理连接级帧（SETTINGS, PING, GOAWAY, WINDOW_UPDATE on stream 0）
    NTSTATUS HandleConnectionFrame(net::WskSocket& socket,
        tls::TlsConnection& tls, const Http2FrameView& frame) noexcept;

    // 分配 stream id
    ULONG AllocateStreamId() noexcept;

    Http2Settings localSettings_ = {};
    Http2Settings peerSettings_ = {};
    ULONG nextStreamId_ = 1;  // 客户端用奇数
    ULONG lastPeerStreamId_ = 0;
    LONG connectionSendWindow_ = 65535;
    LONG connectionRecvWindow_ = 65535;
    bool goAwaySent_ = false;
    bool goAwayReceived_ = false;
    ULONG goAwayLastStreamId_ = 0;

    HpackEncoder encoder_ = {};
    HpackDecoder decoder_ = {};

    // 帧读取缓冲区
    UCHAR* frameBuffer_ = nullptr;
    SIZE_T frameBufferCapacity_ = 0;
    SIZE_T frameBufferLength_ = 0;
};
```

**连接前导（Client Connection Preface）：**
```
PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
```
后跟客户端 SETTINGS 帧。

---

### 7. Http2Client 入口

**新增文件：**
- `src/KernelHttp/client/Http2Client.h`
- `src/KernelHttp/client/Http2Client.cpp`

```cpp
namespace KernelHttp::client
{
    struct Http2RequestOptions final
    {
        const SOCKADDR* RemoteAddress = nullptr;
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        http::HttpMethod Method = http::HttpMethod::Get;
        http::HttpText Path = {};
        http::HttpText Authority = {};  // :authority pseudo-header
        const http::HttpHeader* ExtraHeaders = nullptr;
        SIZE_T ExtraHeaderCount = 0;
        const char* Body = nullptr;
        SIZE_T BodyLength = 0;
        http::HttpText ContentType = {};
        const tls::CertificateStore* CertificateStore = nullptr;
    };

    struct Http2ResponseBuffers final
    {
        UCHAR* HeaderBlockBuffer = nullptr;
        SIZE_T HeaderBlockBufferLength = 0;
        http::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCapacity = 0;
        char* BodyBuffer = nullptr;
        SIZE_T BodyBufferLength = 0;
    };

    struct Http2Response final
    {
        USHORT StatusCode = 0;
        http::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        const char* Body = nullptr;
        SIZE_T BodyLength = 0;
    };

    class Http2Client final
    {
    public:
        Http2Client() noexcept = default;

        Http2Client(const Http2Client&) = delete;
        Http2Client& operator=(const Http2Client&) = delete;

        _Must_inspect_result_
        NTSTATUS SendRequest(
            net::WskClient& wskClient,
            const Http2RequestOptions& options,
            const Http2ResponseBuffers& buffers,
            Http2Response& response) noexcept;
    };
}
```

---

### 8. HttpsClient 自动协商改造

**改动文件：**
- `src/KernelHttp/client/HttpsClient.h`
- `src/KernelHttp/client/HttpsClient.cpp`

**改动逻辑：**

1. `HttpsClient::SendRequest` 在构造 `TlsClientConnectionOptions` 时，设置 ALPN 列表为 `["h2", "http/1.1"]`。
2. TLS 握手完成后，检查 `tlsConnection->NegotiatedAlpn()`：
   - 如果是 `"h2"`：构造 `Http2Connection`，通过 HTTP/2 路径发送请求。
   - 否则：走现有 HTTP/1.1 路径（不变）。
3. `HttpsRequestOptions` 新增可选字段 `bool PreferHttp2 = true`，允许调用方禁用 HTTP/2 协商。

---

### 9. 流控设计

**连接级流控：**
- 客户端初始发送窗口 = 对端 SETTINGS_INITIAL_WINDOW_SIZE（默认 65535）
- 客户端初始接收窗口 = 本地 SETTINGS_INITIAL_WINDOW_SIZE
- 收到 DATA 帧后，累计消耗接收窗口；当消耗超过一半时，发送 WINDOW_UPDATE 补充

**流级流控：**
- 每个 stream 独立维护发送/接收窗口
- 发送 DATA 前检查 min(连接窗口, 流窗口)，不足时分片等待
- 收到 WINDOW_UPDATE 更新对应窗口

**简化：** 当前实现为同步单 stream 模型（一次只有一个活跃请求），流控逻辑相对简单——发送端不会被阻塞（单请求 body 通常小于初始窗口），接收端在每次 DATA 帧后立即发送 WINDOW_UPDATE。

---

### 10. 错误处理

| 场景 | 处理 |
|------|------|
| 收到 GOAWAY | 记录 last-stream-id，当前请求若 stream-id > last-stream-id 则返回错误 |
| 收到 RST_STREAM | 标记 stream 为 Closed，返回对应 error code |
| 帧格式错误 | 发送 GOAWAY(PROTOCOL_ERROR)，关闭连接 |
| 收到 PUSH_PROMISE | 发送 GOAWAY(PROTOCOL_ERROR)（因为我们 SETTINGS_ENABLE_PUSH=0） |
| SETTINGS_INITIAL_WINDOW_SIZE 变更 | 调整所有活跃 stream 的发送窗口 |
| 帧超过 MAX_FRAME_SIZE | 发送 GOAWAY(FRAME_SIZE_ERROR) |
| HPACK 解码失败 | 发送 GOAWAY(COMPRESSION_ERROR) |

**HTTP/2 错误码：**
```cpp
enum class Http2ErrorCode : ULONG
{
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd
};
```

---

### 11. 请求/响应映射

**请求构造（客户端发送 HEADERS 帧）：**

伪头部（必须在普通头部之前）：
- `:method` — GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS
- `:scheme` — "https"
- `:path` — 请求路径
- `:authority` — host:port

普通头部：
- `user-agent`
- `content-type`（有 body 时）
- `content-length`（有 body 时）
- 其他 ExtraHeaders

**响应解析（从 HEADERS 帧解码）：**

伪头部：
- `:status` — 提取为 `Http2Response.StatusCode`

普通头部存入 `Http2Response.Headers`。

---

## 文件清单

### 新增文件

| 路径 | 说明 |
|------|------|
| `src/KernelHttp/http2/Hpack.h` | HPACK 编解码器声明 |
| `src/KernelHttp/http2/Hpack.cpp` | HPACK 实现（静态表、动态表、Huffman、整数编码） |
| `src/KernelHttp/http2/HpackHuffman.h` | Huffman 编解码表（constexpr 数据） |
| `src/KernelHttp/http2/HpackStaticTable.h` | 静态表 61 项（constexpr 数据） |
| `src/KernelHttp/http2/Http2Frame.h` | 帧类型、SETTINGS、帧编解码器声明 |
| `src/KernelHttp/http2/Http2Frame.cpp` | 帧编解码实现 |
| `src/KernelHttp/http2/Http2Stream.h` | Stream 状态机声明 |
| `src/KernelHttp/http2/Http2Stream.cpp` | Stream 状态机实现 |
| `src/KernelHttp/http2/Http2Connection.h` | 连接管理声明 |
| `src/KernelHttp/http2/Http2Connection.cpp` | 连接管理实现（前导、SETTINGS 交换、帧循环） |
| `src/KernelHttp/client/Http2Client.h` | Http2Client 入口声明 |
| `src/KernelHttp/client/Http2Client.cpp` | Http2Client 入口实现 |
| `src/KernelHttp/samples/Http2VerbSamples.h` | 内核自测样例声明 |
| `src/KernelHttp/samples/Http2VerbSamples.cpp` | 内核自测样例实现 |
| `tests/hpack_tests.cpp` | HPACK 单元测试 |
| `tests/http2_frame_tests.cpp` | 帧编解码单元测试 |

### 改动文件

| 路径 | 改动 |
|------|------|
| `src/KernelHttp/tls/TlsHandshake12.h` | TlsClientHelloOptions 增加 ALPN |
| `src/KernelHttp/tls/TlsHandshake12.cpp` | EncodeClientHello 编码 ALPN 扩展 |
| `src/KernelHttp/tls/TlsConnection.h` | TlsClientConnectionOptions 增加 ALPN；TlsConnection 暴露协商结果 |
| `src/KernelHttp/tls/TlsConnection.cpp` | 解析 ServerHello ALPN 扩展 |
| `src/KernelHttp/client/HttpsClient.h` | HttpsRequestOptions 增加 PreferHttp2 |
| `src/KernelHttp/client/HttpsClient.cpp` | 根据 ALPN 结果分派 HTTP/1.1 或 HTTP/2 |
| `src/KernelHttp/samples/HttpVerbSamples.h` | HttpVerbSampleResults 增加 HTTP/2 样例字段 |
| `src/KernelHttp/samples/HttpVerbSamples.cpp` | 调用 Http2VerbSamples |
| `src/KernelHttp/KernelHttp.vcxproj` | 添加新文件引用 |
| `src/KernelHttp/KernelHttp.vcxproj.filters` | 添加新文件筛选器 |

---

## 测试计划

### 单元测试（用户态，`KERNEL_HTTP_USER_MODE_TEST`）

**tests/hpack_tests.cpp：**
- 整数编码/解码：RFC 7541 Section 5.1 示例（C.1.1 ~ C.1.3）
- Huffman 编码/解码：RFC 7541 Appendix B 示例
- 静态表查找
- 动态表插入/驱逐/容量调整
- 完整 header block 解码：RFC 7541 Appendix C.3 ~ C.6 用例
- 编码 round-trip：编码后解码验证一致性

**tests/http2_frame_tests.cpp：**
- 帧头编码/解码 round-trip
- SETTINGS 帧编码/解码
- WINDOW_UPDATE 帧编码/解码
- PING 帧编码/解码
- GOAWAY 帧编码/解码
- RST_STREAM 帧编码/解码
- HEADERS 帧编码（含 CONTINUATION 分片验证）
- DATA 帧编码（含分片验证）
- 边界条件：最大帧大小、零长度 payload

### 内核自测样例

**samples/Http2VerbSamples：**
- HTTP/2 GET httpbin.org/get
- HTTP/2 POST httpbin.org/post（带 JSON body）
- 验证 ALPN 协商成功（打印协商结果）
- 验证响应 :status 和 body 正确解码

---

## 实现顺序

1. HPACK 编解码（纯算法，无外部依赖）
2. HTTP/2 帧层编解码（纯算法）
3. 单元测试验证 1 和 2
4. TLS ALPN 扩展
5. Http2Stream 状态机
6. Http2Connection（连接前导 + SETTINGS + 帧循环 + 流控）
7. Http2Client 入口
8. HttpsClient 自动协商改造
9. 内核自测样例