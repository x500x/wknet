# API 总览

`#include <wknet/Wknet.h>`

命名空间：`wknet::http` · `wknet::websocket` · `wknet::sse` · `wknet::codec` · `wknet::crypto`

## 约定

| 项 | 说明 |
|----|------|
| IRQL | HTTP / WebSocket / 证书 / 异步入口在 `PASSIVE_LEVEL` |
| 返回值 | 多为 `NTSTATUS`；标 `_Must_inspect_result_` 须检查；成功用 `NT_SUCCESS` |
| 句柄 | 不透明堆对象；`Create` 取得，`Close` / `Release` 释放 |
| 选项对象 | `SendOptions` / `AsyncOptions` 经 `*Create` / `*Release` 管理 |
| 空指针 | `Close` / `Release` 接受 `nullptr` |
| 异常 | 不使用 C++ 异常 |

## 句柄

| 类型 | 命名空间 | 创建 / 取得 | 释放 | 头文件 |
|------|----------|--------------|------|--------|
| `Session` | `wknet::http` | `SessionCreate` | `SessionClose` | `http/Session.h` |
| `Request` | `wknet::http` | `RequestCreate` | `RequestRelease` | `http/Request.h` |
| `Response` | `wknet::http` | `Send*` / `AsyncGetResponse` | `ResponseRelease` | `http/Response.h` |
| `AsyncOp` | `wknet::http` | `Async*` / `ConnectAsync*` | `AsyncRelease` | `http/AsyncOp.h` |
| `Headers` | `wknet::http` | `HeadersCreate` | `HeadersRelease` | `http/Headers.h` |
| `Body` | `wknet::http` | `BodyCreate*` | `BodyRelease` | `http/Body.h` |
| `Cache` | `wknet::http` | `CacheCreate` | `CacheRelease` | `http/Cache.h` |
| `CertificateStore` | `wknet::http` | `CertificateStoreCreate` | `CertificateStoreClose` | `http/Certificate.h` |
| `WebSocket` | `wknet::websocket` | `Connect*` | `Close` / `CloseEx` | `websocket/WebSocket.h` |
| `SseClient` | `wknet::sse` | `Connect*` | `Close` | `sse/Sse.h` |

`SendOptions` / `AsyncOptions` 见 [同步 HTTP](http-sync.md) / [异步 HTTP](http-async.md)。

## 头文件

| 头文件 | 内容 |
|--------|------|
| `wknet/Wknet.h` | 公共 API 总入口 |
| `wknet/http/Types.h` | 枚举、配置结构体、回调、默认常量 |
| `wknet/http/Session.h` | `SessionCreate` / `SessionClose` |
| `wknet/http/Request.h` | `RequestCreate` / `RequestRelease` |
| `wknet/http/Headers.h` | 请求头 |
| `wknet/http/Body.h` | 请求体 |
| `wknet/http/Options.h` | `SendOptionsCreate` / `AsyncOptionsCreate` |
| `wknet/http/Http.h` | 同步 `Send` / `Get` / `Post` … |
| `wknet/http/HttpAsync.h` | 异步 `AsyncSend` / `AsyncGet` … |
| `wknet/http/AsyncOp.h` | 等待、取消、取 `Response` |
| `wknet/http/Response.h` | 状态码 / body / header / trailer |
| `wknet/http/Lifecycle.h` | `Destroy` |
| `wknet/http/Certificate.h` | `CertificateStore`、pin、mTLS 相关类型 |
| `wknet/http/Cache.h` | 内存 cache |
| `wknet/websocket/WebSocket.h` | WebSocket 连接与收发 |
| `wknet/sse/Sse.h` | Server-Sent Events 客户端 |
| `wknet/codec/Codec.h` | content-coding / EXI / Pack200 |
| `wknet/crypto/Aead.h` | AEAD |
| `wknet/crypto/TlsCredential.h` | `TlsClientCredential`（经 `Certificate.h`） |
| `wknet/Trace.h` | 诊断 |

`Wknet.h` 会包含上表中的公共头（`TlsCredential.h` 经 `Certificate.h` 引入）。细分包含时可只取所需头文件。

## 最小示例

```cpp
#include <wknet/Wknet.h>

NTSTATUS Demo()
{
    wknet::http::Response* response = nullptr;
    NTSTATUS status = wknet::http::Get("https://example.com/", &response);
    if (NT_SUCCESS(status) && response != nullptr) {
        const ULONG code = wknet::http::ResponseStatusCode(response);
        UNREFERENCED_PARAMETER(code);
    }
    wknet::http::ResponseRelease(response); // 接受 nullptr
    return status;
}
```

需要连接复用、默认头、Cookie、TLS 信任锚时使用显式 `Session`。分步说明见 [第一个请求](../first-request.md)；各页末尾有对应 API 的短示例。

## 默认配置

| 函数 | 返回 |
|------|------|
| `DefaultSessionConfig()` | `SessionConfig` |
| `DefaultTlsConfig()` | `TlsConfig` |
| `DefaultSendOptions()` | `SendOptions` 值 |
| `DefaultConnectConfig()` | `websocket::ConnectConfig` 或 `sse::DefaultConnectConfig()` |

`SendOptions` / `AsyncOptions` 作为 API 参数时使用 `SendOptionsCreate` / `AsyncOptionsCreate`（构造函数私有）。

## 分页

| 页 | 内容 |
|----|------|
| [会话与配置](session-config.md) | `Session`、`SessionConfig`、`Http3`、代理、池、cache |
| [请求与响应](request-response.md) | `Request`、`Headers`、`Body`、`Response` |
| [同步 HTTP](http-sync.md) | `Send` / 按方法发送、`SendOptions` |
| [异步 HTTP](http-async.md) | `AsyncSend`、`AsyncOp`、`Destroy` |
| [WebSocket](websocket.md) | `Connect` / 收发 / 关闭 |
| [SSE](sse.md) | `SseClient` Connect / Receive / Close |
| [证书与 TLS](tls-options.md) | `TlsConfig`、`CertificateStore`、mTLS |
| [Codec 与 Crypto](codec-crypto.md) | 解码与 AEAD |
