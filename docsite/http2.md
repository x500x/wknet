# HTTP/2 与 HPACK / HTTP/2 & HPACK

命名空间 `KernelHttp::http2`。RFC 9113 + HPACK RFC 7541，客户端单流串行模型。

[English](#english) | 简体中文

---

## 简体中文

### 帧（`http2/Http2Frame.h`）

```cpp
enum class Http2FrameType : UCHAR {
    Data=0x0, Headers=0x1, Priority=0x2, RstStream=0x3, Settings=0x4,
    PushPromise=0x5, Ping=0x6, GoAway=0x7, WindowUpdate=0x8, Continuation=0x9
};
namespace Http2FrameFlags { EndStream=0x01; Ack=0x01; EndHeaders=0x04; Padded=0x08; Priority=0x20; }
```
常量：帧头 9 字节、默认最大帧 16384、最大允许帧 2^24-1、初始窗口 65535、最大窗口 0x7fffffff、连接前导 `"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"`（24 字节）。

`Http2FrameCodec`（静态）：`EncodeFrameHeader`/`DecodeFrameHeader`/`EncodeFrame`、`EncodeSettings`/`EncodeSettingsAck`/`DecodeSettingsPayload`/`EncodeSettingsPayloadBase64Url`（h2c Upgrade 用）、`EncodeWindowUpdate`/`DecodeWindowUpdatePayload`、`EncodePing`、`EncodeGoAway`/`DecodeGoAwayPayload`、`EncodeRstStream`/`DecodeRstStreamPayload`、`EncodeHeaders`/`EncodeContinuation`/`EncodeData`、`StripPadding`/`StripPriority`。

### SETTINGS（`Http2SettingId`）

`HeaderTableSize`(0x1)、`EnablePush`(0x2)、`MaxConcurrentStreams`(0x3)、`InitialWindowSize`(0x4)、`MaxFrameSize`(0x5)、`MaxHeaderListSize`(0x6)。
默认：`HeaderTableSize=4096`、`EnablePush=0`（客户端恒 0）、`MaxConcurrentStreams=100`、`InitialWindowSize=65535`、`MaxFrameSize=16384`、`MaxHeaderListSize=65536`。

### 错误码（`Http2ErrorCode`）

`NoError`(0)、`ProtocolError`(1)、`InternalError`(2)、`FlowControlError`(3)、`SettingsTimeout`(4)、`StreamClosed`(5)、`FrameSizeError`(6)、`RefusedStream`(7)、`Cancel`(8)、`CompressionError`(9)、`ConnectError`(0xa)、`EnhanceYourCalm`(0xb)、`InadequateSecurity`(0xc)、`Http11Required`(0xd)。

### 流状态机（`http2/Http2Stream.h`）

```cpp
enum class Http2StreamState { Idle, Open, HalfClosedLocal, HalfClosedRemote, Closed };
```
`Http2Stream`：`Initialize(streamId, localWindow, remoteWindow)`、`SendHeaders`/`SendData`/`ReceiveHeaders`/`ReceiveData`、窗口管理 `IncreaseRemoteWindow`/`AdjustRemoteWindow`/`IncreaseLocalWindow`、`Reset`/`Close`。窗口默认 65535，按有符号 `LONG` 跟踪。

### 连接（`http2/Http2Connection.h`）

```cpp
class Http2Connection {
    NTSTATUS Initialize(core::ITransport&, SIZE_T maxHeaderBlockBytes = 32*1024);
    NTSTATUS InitializeAfterUpgrade(core::ITransport&);   // h2c Upgrade 后
    NTSTATUS SendRequest(... 缓冲式或 Http2ResponseBodySink 流式 ...);
    NTSTATUS ReceiveResponse(... ULONG streamId ...);
    NTSTATUS Shutdown(core::ITransport&);
    bool     IsReusable() const;
};
```
头块缓冲默认 32 KiB、最大 256 KiB。`nextStreamId_` 从 1 开始，连接窗口初始 65535。流式接收通过 `Http2ResponseBodySink{ Append, Context }` 回调。

### HPACK（`http2/Hpack.h`）

- 整数：`HpackEncodeInteger` / `HpackDecodeInteger`
- Huffman：`HpackHuffmanEncode` / `HpackHuffmanDecode` / `HpackHuffmanEncodedLength`
- 动态表 `HpackDynamicTable`：`Initialize(maxSize=4096)`、`Insert`、`Lookup`、`UpdateMaxSize`
- `HpackDecoder::Decode(...)`（含 `maxHeaderListSize` 重载）
- `HpackEncoder::Encode(...)`：静态表命中用 indexed 表示，否则 literal-with-incremental-indexing

静态表 61 项（`HpackStaticTableSize`），每项开销 32（`HpackEntryOverhead`）。Huffman 解码为 4-bit nibble 状态机（emit/accepted/error 标志）。

### 传输模式（见 [客户端类](client-classes.md) 的 `Http2Client`）

`TlsAlpn`（TLS ALPN `h2`）、`H2cPriorKnowledge`（明文 prior knowledge）、`H2cUpgrade`（HTTP/1.1 Upgrade）。

### 边界

- **单流串行**，无多路复用；不复用 h2 连接（每请求新建，结束发 GOAWAY）。
- 不发 PRIORITY、不主动 PING；`MAX_CONCURRENT_STREAMS` 仅广告。
- 禁用 push：收到 `PUSH_PROMISE` 视为协议错误；缺失 SETTINGS ACK 以 `SETTINGS_TIMEOUT` 关闭。
- 高层 khttp 不暴露 h2c（仅底层 `Http2Client`）；不支持 RFC 8441 WebSocket over HTTP/2。

---

## English

Namespace `KernelHttp::http2`, RFC 9113 + HPACK RFC 7541, single-stream serial client.

Frame types 0x0–0x9, flags (EndStream/Ack/EndHeaders/Padded/Priority); `Http2FrameCodec` encodes/decodes all frames incl. base64url SETTINGS for h2c upgrade. SETTINGS ids 0x1–0x6 with defaults (table 4096, push 0, max streams 100, window 65535, frame 16384, header list 65536). Error codes 0x0–0xd. Stream states Idle/Open/HalfClosed{Local,Remote}/Closed with signed-LONG flow windows. `Http2Connection` initializes (or after h2c upgrade), sends requests (buffered or streaming via `Http2ResponseBodySink`), and shuts down; header-block buffer 32 KiB default, 256 KiB max. HPACK: integer/Huffman primitives, dynamic table (default 4096), decoder (with `maxHeaderListSize`), encoder (indexed for static-table hits); static table 61 entries, per-entry overhead 32.

Transport modes (`Http2Client`): TLS-ALPN h2, h2c prior-knowledge, h2c upgrade. Boundaries: single-stream serial, no multiplexing, no h2 connection reuse (GOAWAY per request), no PRIORITY/proactive PING, push disabled (`PUSH_PROMISE` is a protocol error), no h2c at high-level khttp, no RFC 8441.
