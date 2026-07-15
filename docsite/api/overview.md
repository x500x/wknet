# API 总览

命名空间：`wknet::http` · `wknet::websocket` · `wknet::codec` · `wknet::crypto`  
总入口：`<wknet/Wknet.h>`

## 职责

高层公开 API 的句柄表、调用约定与头文件地图。字段与签名以对应头文件为准；任务示例见 [Cookbook](../cookbook.md)。

## 调用约定

| 项 | 规则 |
|----|------|
| IRQL | 所有高层 HTTP / WebSocket / 证书 / 异步入口在 `PASSIVE_LEVEL` |
| 返回 | 多为 `NTSTATUS`；标 `_Must_inspect_result_` 必须检查；成功用 `NT_SUCCESS` |
| 句柄 | 不透明堆对象；`Create` / 发送结果取得，`Close` / `Release` 归还 |
| 选项 | `SendOptions` / `AsyncOptions` 经 `*Create` 分配，`*Release` 释放 |
| 空指针 | `Close` / `Release` 接受 `nullptr`，失败路径可无条件调用 |
| 错误 | 不抛 C++ 异常；失败返回 `NTSTATUS`，输出指针通常置空 |

## 不透明句柄

| 类型 | 命名空间 | 创建 / 取得 | 释放 | 头文件 |
|------|----------|------------|------|--------|
| `Session` | `wknet::http` | `SessionCreate` | `SessionClose` | `http/Session.h` |
| `Request` | `wknet::http` | `RequestCreate` | `RequestRelease` | `http/Request.h` |
| `Response` | `wknet::http` | `Send*` / `AsyncGetResponse` | `ResponseRelease` | `http/Response.h` |
| `AsyncOp` | `wknet::http` | `Async*` / `ConnectAsync*` | `AsyncRelease` | `http/AsyncOp.h` |
| `Headers` | `wknet::http` | `HeadersCreate` | `HeadersRelease` | `http/Headers.h` |
| `Body` | `wknet::http` | `BodyCreate*` | `BodyRelease` | `http/Body.h` |
| `Cache` | `wknet::http` | `CacheCreate` | `CacheRelease` | `http/Cache.h` |
| `CertificateStore` | `wknet::http` | `CertificateStoreCreate` | `CertificateStoreClose` | `http/Certificate.h` |
| `WebSocket` | `wknet::websocket` | `Connect*` | `Close` / `CloseEx` | `websocket/WebSocket.h` |

`SendOptions` / `AsyncOptions` 也是堆对象（Create / Release 管理），见 [同步 HTTP](http-sync.md) / [异步 HTTP](http-async.md)。

## `<wknet/Wknet.h>` 包含什么

`Wknet.h` **只**聚合高层公共头，**不含**底层 engine / 传输内部类型：

```cpp
#include <wknet/WknetConfig.h>
#include <wknet/Trace.h>
#include <wknet/http/AsyncOp.h>
#include <wknet/http/Body.h>
#include <wknet/http/Cache.h>
#include <wknet/http/Certificate.h>
#include <wknet/http/Headers.h>
#include <wknet/http/Http.h>
#include <wknet/http/HttpAsync.h>
#include <wknet/http/Lifecycle.h>
#include <wknet/http/Options.h>
#include <wknet/http/Request.h>
#include <wknet/http/Response.h>
#include <wknet/http/Session.h>
#include <wknet/http/Types.h>
#include <wknet/websocket/WebSocket.h>
#include <wknet/crypto/Aead.h>
#include <wknet/codec/Codec.h>
```

产品路径通常只 `#include <wknet/Wknet.h>`。需要细分依赖时按下列地图包含。

## 头文件地图

| 头文件 | 内容 |
|--------|------|
| `wknet/Wknet.h` | 高层总入口（见上） |
| `wknet/http/Types.h` | 枚举、配置结构体、回调、默认常量 |
| `wknet/http/Session.h` | `SessionCreate` / `SessionClose` |
| `wknet/http/Request.h` | `RequestCreate` / `RequestRelease`（部分 setter 仅测试宏） |
| `wknet/http/Headers.h` | 请求头句柄 |
| `wknet/http/Body.h` | 请求体句柄 |
| `wknet/http/Options.h` | `SendOptionsCreate` / `AsyncOptionsCreate` |
| `wknet/http/Http.h` | 同步 `Send` / `Get` / `Post` … |
| `wknet/http/HttpAsync.h` | 异步 `AsyncSend` / `AsyncGet` … |
| `wknet/http/AsyncOp.h` | 等待、取消、取 `Response`、释放 |
| `wknet/http/Response.h` | 状态码 / body / header / trailer 只读 |
| `wknet/http/Lifecycle.h` | `Destroy` 异步收尾 |
| `wknet/http/Certificate.h` | `CertificateStore*`、pin / mTLS 相关类型 |
| `wknet/http/Cache.h` | RFC 9111 内存缓存 |
| `wknet/websocket/WebSocket.h` | WebSocket 连接与收发 |
| `wknet/codec/Codec.h` | Content-coding / EXI / Pack200 解码 |
| `wknet/crypto/Aead.h` | AEAD 加解密 |
| `wknet/crypto/TlsCredential.h` | `TlsClientCredential`（经 `Certificate.h` 使用） |
| `wknet/Trace.h` | 诊断开关（非请求路径必需） |

底层 `session::` 与 WSK 传输等**不在** `Wknet.h` 公共聚合内；见 [内部边界](../internals.md)。

## 默认工厂

| 函数 | 返回 | 头文件 |
|------|------|--------|
| `DefaultSessionConfig()` | `SessionConfig{}` | `Types.h` |
| `DefaultTlsConfig()` | `TlsConfig{}` | `Types.h` |
| `DefaultSendOptions()` | 值语义默认 `SendOptions` | `Types.h` |
| `DefaultConnectConfig()` | `websocket::ConnectConfig` | `Types.h` |

堆上选项请用 `SendOptionsCreate` / `AsyncOptionsCreate`，不要在栈上放置 `SendOptions` / `AsyncOptions` 实例作为 API 参数载体（构造函数私有，经 factory / allocator 创建）。

## 相关链接

- [会话与配置](session-config.md)
- [请求与响应](request-response.md)
- [同步 HTTP](http-sync.md)
- [异步 HTTP](http-async.md)
- [WebSocket](websocket.md)
- [证书与 TLS](tls-options.md)
- [Codec 与 Crypto](codec-crypto.md)
- [第一个请求](../first-request.md)
- [Cookbook](../cookbook.md)
