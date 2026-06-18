# 客户端类 / Client Classes

`KernelHttp::client`。比 `engine` 更底层的协议客户端封装，使用调用方提供的缓冲（无内部句柄/连接池），适合精细控制与测试。高层 `khttp`/`kws` 一般已够用。

[English](#english) | 简体中文

---

## 简体中文

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
`HttpsRequestOptions` 携带远端地址、SNI、请求构建选项、证书库与校验开关、`PreferHttp2`、min/max `TlsProtocol`、`TlsPolicy`、TLS1.3/1.2 会话缓存、ALPN 列表、客户端凭据、Workspace、provider cache，以及会话恢复/0-RTT 控制（`EnableSessionResumption`/`EnableEarlyData`/`EarlyDataReplaySafe`/`EarlyDataBytesSent`/`EarlyDataAccepted`）。

### Http2Client（`client/Http2Client.h`）

单请求 HTTP/2 客户端。
```cpp
enum class Http2TransportMode { TlsAlpn, H2cPriorKnowledge, H2cUpgrade };
NTSTATUS SendRequest(net::WskClient&, const Http2RequestOptions&, const Http2ResponseBuffers&, Http2Response&);
NTSTATUS BuildHttp2RequestHeaders(const Http2RequestOptions&, http::HttpHeader*, SIZE_T cap, char names[16][64], char* clBuf, SIZE_T* count);
```
`Http2RequestOptions` 含传输模式、远端地址、SNI、method/path/authority/user-agent/content-type/accept-encoding、额外头、body、证书库、校验开关、`TlsPolicy`、客户端凭据。`Http2Response` 返回 status/headers/body/协商 ALPN。TLS-ALPN 模式下若 peer 不协商 `h2` 返回 `STATUS_NOT_SUPPORTED`。常量：最多 16 个请求头、头名 ≤64。

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
`WebSocketConnectOptions` 含 server/service name、可选 TLS server name、host/port/path、子协议、证书库、Workspace、provider cache、`WskAddressFamily`、min/max `TlsProtocol`、`TlsPolicy`、客户端凭据、握手接收超时、取消令牌、`UseTls`、`VerifyCertificate`。

### 与高层 API 的关系

`khttp`/`kws` + `engine` 在这些客户端类之上增加了会话、连接池、Workspace 自动管理和句柄生命周期。**多数应用应优先用 [高层 API](high-level-api.md)**；直接用 client 类适合需要完全掌控缓冲与连接的测试/特殊场景。

---

## English

`KernelHttp::client` — protocol client wrappers below `engine` that use caller-provided buffers (no internal handles/pool). `HttpClient::SendRequest` (plaintext HTTP/1.1), `HttpsClient::SendRequest` (TLS, HTTP/2 via ALPN; carries cert store, `TlsPolicy`, session caches, ALPN list, client credential, resumption/0-RTT controls), `Http2Client::SendRequest` (modes `TlsAlpn`/`H2cPriorKnowledge`/`H2cUpgrade`; returns `STATUS_NOT_SUPPORTED` if peer won't negotiate `h2`; helper `BuildHttp2RequestHeaders`), `WebSocketClient` (`Connect`/`SendText`/`SendBinary`/`SendContinuation`/`SendPing`/`SendPong`/`ReceiveMessage`/`Close`/`SelectedSubprotocol`/`SendTextAndReceiveEcho`). Most applications should prefer the [High-Level API](high-level-api.md); use client classes directly for tests or full buffer/connection control.
