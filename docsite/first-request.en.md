# First request

Send a minimal HTTP GET / POST and release handles correctly. All calls run at `PASSIVE_LEVEL`.

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

    wknet::http::ResponseRelease(response);  // accepts nullptr
    wknet::http::SessionClose(session);
    return status;
}
```

## POST JSON

`BodyCreateJson*` only sets `Content-Type` and forwards bytes — it does **not** parse JSON.

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

## HTTPS and trust anchors

Default is `CertPolicy::Verify`. The library does **not** ship a system CA store; production paths should supply a `CertificateStore` (anchors / pins). `NoVerify` is for tests only.

```cpp
wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
config.Tls.Certificate = wknet::http::CertPolicy::Verify;
config.Tls.Store = trustStore;  // caller-built CertificateStore*
// SessionCreate(&config, &session);  // config overload — see API reference
```

Details: [TLS & trust](tls-and-trust.md) and [TLS options](api/tls-options.md).

## Calling conventions

- Handles such as `Session` / `Response` / `Body` are heap objects: Create to obtain, Close / Release to free. Release / Close accept `nullptr`, so failure paths can call them unconditionally.
- Returns are `NTSTATUS`; values marked `_Must_inspect_result_` must be checked.
- Sync HTTP, WebSocket, TLS, and certificate paths require `PASSIVE_LEVEL`.
- After async APIs, call `wknet::http::Destroy()` on the driver unload path and wait for async work to finish before releasing resources. Sync-only paths may omit it.

## Next

- [Integration notes](integration-checklist.md)
- [Cookbook](cookbook.md) — async, streaming, WebSocket, certificates
- [API overview](api/overview.md)
