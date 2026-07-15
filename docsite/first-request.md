# 第一个请求

用最少的代码完成一次 HTTP GET / POST，并正确释放句柄。所有调用在 `PASSIVE_LEVEL`。

## GET

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

## POST JSON

`BodyCreateJson*` 只设置 `Content-Type` 并透传字节，**不解析 JSON**。

```cpp
NTSTATUS SimplePostJson(wknet::http::Session* session)
{
    wknet::http::Body* body = nullptr;
    wknet::http::Response* response = nullptr;

    static const char kJson[] = "{\"ok\":true}";
    NTSTATUS status = wknet::http::BodyCreateJsonCopy(
        kJson, sizeof(kJson) - 1, &body);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = wknet::http::Post(session, "https://example.com/api", body, &response);

    wknet::http::BodyRelease(body);
    wknet::http::ResponseRelease(response);
    return status;
}
```

## HTTPS 与信任锚

默认 `CertPolicy::Verify`。库**不**内置系统 CA；生产路径请提供 `CertificateStore`（信任锚 / pin）。仅测试可临时使用 `NoVerify`，样例与生产文档均不推荐。

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

## 下一步

- [集成要点](integration-checklist.md)
- [Cookbook](cookbook.md) — 异步、流式、WebSocket、证书
- [API 总览](api/overview.md)
