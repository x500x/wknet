# 第一个请求

用最少的代码完成一次 HTTP GET / POST，并正确释放句柄。所有调用须在 `PASSIVE_LEVEL` 执行。

## 会话无关 GET

调用方不创建 `Session`。库在内部创建并使用会话（可经瞬时会话池复用）。

```cpp
#include <wknet/Wknet.h>

NTSTATUS SimpleGetWithoutSession()
{
    wknet::http::Response* response = nullptr;
    NTSTATUS status = wknet::http::Get("https://example.com/", &response);
    if (NT_SUCCESS(status) && response != nullptr) {
        const ULONG code = wknet::http::ResponseStatusCode(response);
        UNREFERENCED_PARAMETER(code);
    }
    wknet::http::ResponseRelease(response);
    return status;
}
```

需要连接复用、默认请求头、Cookie 或会话级身份验证时，应使用显式 `SessionCreate`。

## 显式会话 GET

```cpp
#include <wknet/Wknet.h>

NTSTATUS SimpleGet()
{
    wknet::http::Session* session = nullptr;
    wknet::http::Response* response = nullptr;

    NTSTATUS status = wknet::http::SessionCreate(&session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = wknet::http::Get(session, "https://example.com/", &response);
    if (NT_SUCCESS(status) && response != nullptr) {
        const ULONG code = wknet::http::ResponseStatusCode(response);
        const UCHAR* body = wknet::http::ResponseBody(response);
        const SIZE_T len = wknet::http::ResponseBodyLength(response);
        UNREFERENCED_PARAMETER(code);
        UNREFERENCED_PARAMETER(body);
        UNREFERENCED_PARAMETER(len);
    }

    wknet::http::ResponseRelease(response);  // 接受 nullptr
    wknet::http::SessionClose(session);
    return status;
}
```

## Request 对象（所属会话可选）

```cpp
wknet::http::Request* request = nullptr;
wknet::http::Response* response = nullptr;
NTSTATUS status = wknet::http::RequestCreate(&request);  // 无所属会话：Send 时使用库内部会话
if (NT_SUCCESS(status)) {
    status = wknet::http::RequestSetMethod(request, wknet::http::Method::Get);
}
if (NT_SUCCESS(status)) {
    status = wknet::http::RequestSetUrl(request, "https://example.com/");
}
if (NT_SUCCESS(status)) {
    status = wknet::http::Send(request, &response);
}
wknet::http::ResponseRelease(response);
wknet::http::RequestRelease(request);
```

## POST JSON

`BodyCreateJson*` 仅设置 `Content-Type` 并透传字节，**不**解析 JSON。

```cpp
NTSTATUS SimplePostJson()
{
    wknet::http::Body* body = nullptr;
    wknet::http::Response* response = nullptr;

    static const char kJson[] = "{\"ok\":true}";
    NTSTATUS status = wknet::http::BodyCreateJsonCopy(
        kJson, sizeof(kJson) - 1, &body);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 会话无关 Post
    status = wknet::http::Post("https://example.com/api", body, &response);

    wknet::http::BodyRelease(body);
    wknet::http::ResponseRelease(response);
    return status;
}
```

## 会话默认请求头与身份验证

```cpp
wknet::http::Session* session = nullptr;
wknet::http::SessionCreate(&session);
wknet::http::SessionSetDefaultHeader(session, "User-Agent", "my-driver/1.0");
wknet::http::SessionSetBearerAuth(session, token, tokenLen);
// 该会话上后续 Get/Post 在请求装配阶段合并默认项
wknet::http::SessionClearAuth(session);
wknet::http::SessionClearDefaultHeaders(session);
wknet::http::SessionClose(session);
```

## HTTPS 与信任锚

默认 `CertPolicy::Verify`。库**不**内置系统 CA 包；生产路径须提供 `CertificateStore`（信任锚 / pin）。`NoVerify` 仅用于测试。

```cpp
wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
config.Tls.Certificate = wknet::http::CertPolicy::Verify;
config.Tls.Store = trustStore;  // 调用方构造的 CertificateStore*
// SessionCreate(&config, &session);  // 带配置重载，见 API 参考
```

字段与构造细节见 [TLS 与信任](tls-and-trust.md) 与 [证书与 TLS 选项](api/tls-options.md)。

## 调用约定

- `Session` / `Response` / `Body` 等为堆上句柄：Create 取得，Close / Release 释放；Release / Close 接受 `nullptr`，失败路径可无条件调用。
- 返回 `NTSTATUS`；标有 `_Must_inspect_result_` 的返回值须检查。
- 同步 HTTP、WebSocket、TLS、证书路径在 `PASSIVE_LEVEL` 调用。
- 使用过异步 API 时，在驱动卸载路径调用 `wknet::http::Destroy()`，等待异步操作结束后再释放资源；纯同步路径可不调用。
- 会话无关异步：`AsyncGet(url, &op)` — 库内部会话由 `AsyncOp` 持有，直至 `AsyncRelease`。
