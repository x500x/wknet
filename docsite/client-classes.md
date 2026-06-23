# 客户端类

### HttpClient（`client/HttpClient.h`）

HTTP/1.1 明文客户端。
```cpp
NTSTATUS SendRequest(net::WskClient&, const HttpRequestOptions&, const HttpResponseBuffers&, http::HttpResponse&);
```
`HttpRequestOptions{ ServerName, ServiceName=L"80", http::HttpRequestBuildOptions Request, ResponseBodyForbidden }`。
`HttpResponseBuffers` 提供请求/响应/解码体/scratch/header 各缓冲（调用方分配）。

### HttpsClient（`client/HttpsClient.h`）

TLS 上的 HTTP/1.1（按 ALPN 可走 HTTP/2）。
```cpp
NTSTATUS SendRequest(net::WskClient&, const HttpsRequestOptions&, const HttpsResponseBuffers&, http::HttpResponse&);
```
`HttpsRequestOptions` 携带远端地址、可选代理地址（`ProxyAddress` + `ProxyAuthority` + `ProxyHeaders`，用于 HTTP/1.1 CONNECT 隧道）、SNI、请求构建选项、证书库与校验开关、`PreferHttp2`、min/max `TlsProtocol`、`TlsPolicy`、TLS1.3/1.2 会话缓存、ALPN 列表、客户端凭据、Workspace、provider cache，以及会话恢复/0-RTT 控制（`EnableSessionResumption`/`EnableEarlyData`/`EarlyDataReplaySafe`/`EarlyDataBytesSent`/`EarlyDataAccepted`）。

### Http2Client（`client/Http2Client.h`）

单请求 HTTP/2 客户端；底层 `http2::Http2Connection` 另提供多活动流基础与 RFC 8441 tunnel primitive。
```cpp
enum class Http2TransportMode { TlsAlpn, H2cPriorKnowledge, H2cUpgrade };
NTSTATUS SendRequest(net::WskClient&, const Http2RequestOptions&, const Http2ResponseBuffers&, Http2Response&);
NTSTATUS BuildHttp2RequestHeaders(const Http2RequestOptions&, http::HttpHeader*, SIZE_T cap, char names[16][64], char* clBuf, SIZE_T* count);
// http2::Http2Connection 低层接口：
NTSTATUS BeginRequest(..., ULONG* streamId) noexcept;
NTSTATUS ReceiveResponse(..., ULONG streamId) noexcept;
NTSTATUS SendStreamData(..., ULONG streamId, const UCHAR* data, SIZE_T len, bool endStream) noexcept;
NTSTATUS ReceiveStreamData(..., ULONG streamId, UCHAR* out, SIZE_T cap, SIZE_T* len, bool* endStream) noexcept;
```
`Http2RequestOptions` 含传输模式、远端地址、SNI、method/path/authority/user-agent/content-type/accept-encoding、`ConnectProtocol`（RFC 8441 时为 `websocket`）、额外头、body、证书库、校验开关、`TlsPolicy`、客户端凭据。`Http2Response` 返回 status/headers/body/协商 ALPN。TLS-ALPN 模式下若 peer 不协商 `h2` 返回 `STATUS_NOT_SUPPORTED`。常量：最多 16 个请求头、头名 ≤64。

### WebSocketClient（`client/WebSocketClient.h`）

```cpp
NTSTATUS Connect(net::WskClient&, const WebSocketConnectOptions&, const WebSocketIoBuffers&, USHORT* statusCode = nullptr);
NTSTATUS SendText / SendBinary / SendContinuation(..., bool finalFragment = true);
NTSTATUS SendPing / SendPong(...);
NTSTATUS ReceiveMessage(..., websocket::WebSocketOpcode* opcode, UCHAR* out, SIZE_T cap, SIZE_T* recv, bool autoReplyPing = true);
NTSTATUS Close(...); NTSTATUS Close(USHORT statusCode, const UCHAR* reason, SIZE_T, ...);
const char* SelectedSubprotocol(SIZE_T* len = nullptr) const;
NTSTATUS SendTextAndReceiveEcho(..., WebSocketEchoResult&);   // 便捷：发文本并收回显
```
`WebSocketConnectOptions` 含 server/service name、可选 TLS server name、host/port/path、子协议、证书库、Workspace、provider cache、`WskAddressFamily`、min/max `TlsProtocol`、`TlsPolicy`、客户端凭据、握手接收超时、取消令牌、`UseTls`、`VerifyCertificate`，以及 `AllowWebSocketOverHttp2`。

### 实测行为要点

- **HttpsClient 协议选择**：握手后读协商 ALPN，`PreferHttp2 && alpn=="h2"` 走 HTTP/2；否则**静默回退普通 HTTP/1.1 over TLS**（不会因「期望 h2 却没协商到」而报错）。`PreferHttp2` 时抑制 early data。
- **HttpsClient 代理 CONNECT**：设置 `ProxyAddress` 时先连代理、发送明文 `CONNECT <authority> HTTP/1.1`，2xx 后再对目标主机做 TLS；`ProxyHeaders` 可携带代理认证等额外头。
- **TLS1.2 确认重连**：首次失败且失败被分类为 `VersionNegotiation`（或 ServerHello 前的非超时 `NetworkIo`）时，自动以 `MaximumTlsProtocol=Tls12` 重试一次；成功则成功，失败返回**原始**错误。WebSocketClient 对**每个解析地址**都做此重连。
- **Http2Client / Http2Connection**：`TlsAlpn` 下协商不到 `h2` → `STATUS_NOT_SUPPORTED`；`H2cUpgrade` **禁止请求体**，发 `Upgrade: h2c` + base64url `HTTP2-Settings`，校验 `101` 响应，重放 101 后残留字节，再 `ReceiveResponse(stream 1)`。低层连接可用 `BeginRequest` / `ReceiveResponse(streamId)` 管理多活动流；RFC 8441 tunnel 需要对端 `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`。
- **WebSocketClient**：默认握手 ALPN 为 `http/1.1`；设置 `AllowWebSocketOverHttp2` 后 `wss` 会 offer `h2,http/1.1`，协商到 h2 时走 RFC 8441 extended CONNECT，peer 未启用 `SETTINGS_ENABLE_CONNECT_PROTOCOL` 则 fail-closed；可传 `ExtraHeaders`；控制帧每次接收上限 100；拒绝 `Sec-WebSocket-Extensions`；Accept 常量时间比对。

### 与高层 API 的关系

`khttp`/`kws` + `engine` 在这些客户端类之上增加了会话、连接池、Workspace 自动管理和句柄生命周期。**多数应用应优先用 [高层 API](high-level-api.md)**；直接用 client 类适合需要完全掌控缓冲与连接的测试/特殊场景。
