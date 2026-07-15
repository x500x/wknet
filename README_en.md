<div align="center">

# wknet

**A pure kernel-mode HTTP/HTTPS/WebSocket client for Windows drivers**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%20Kernel-0078d4.svg)](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
[![WDK: 10+](https://img.shields.io/badge/WDK-10%2B-green.svg)](https://docs.microsoft.com/en-us/windows-hardware/drivers/develop/)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)

English | [简体中文](README.md)

</div>

---

## What it is

wknet issues outbound HTTP(S) and WebSocket from kernel drivers. Transport is **WSK**; cryptography is kernel **CNG/BCrypt**. No WinHTTP, WinINet, or SChannel.

Public API is four namespaces only: `wknet::http` · `wknet::websocket` · `wknet::crypto` · `wknet::codec`.

## Highlights

- Pure kernel client stack: HTTP/1.1 · HTTP/2 · HTTP/3 (QUIC v1) · WebSocket · TLS 1.2/1.3
- One product API; Session owns pool, redirects, proxy, async, and protocol selection
- Secure defaults: certificate verification, no CN hostname fallback, HTTPS→HTTP redirects refused, Trace Off
- Trust anchors / CA bundles / pins / revocation evidence are **caller-supplied**
- Heap handles and Workspace; sync paths require `PASSIVE_LEVEL`

## Capability summary

Full four-bucket ledger: [Capability matrix](https://x500x.github.io/wknet/en/capability-matrix/) (implemented / default-off / refused / non-goals).

| Bucket | Summary |
|--------|---------|
| Implemented | HTTP/1.1–3, WebSocket, TLS 1.2/1.3, cert verify & pin, pool, async, content encodings |
| Default-off | pipeline, h2c, H2 PING keepalive, 0-RTT, permessage-deflate, TLS compatibility suites, hard revocation, … |
| Refused | caller request TE, H2 server push, unnegotiated WS extensions, HTTPS→HTTP downgrade, … |
| Non-goals | HTTP server role, online OCSP fetch, QUIC v2 / migration / WebTransport / WS over H3, … |

HTTP/3 defaults to **Auto**: first HTTPS on TCP, learn exact `h3` Alt-Svc only from **authenticated** responses, then prefer H3.

## Minimal example

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
        ULONG code = wknet::http::ResponseStatusCode(response);
        const UCHAR* body = wknet::http::ResponseBody(response);
        SIZE_T len = wknet::http::ResponseBodyLength(response);
        UNREFERENCED_PARAMETER(code);
        UNREFERENCED_PARAMETER(body);
        UNREFERENCED_PARAMETER(len);
        wknet::http::ResponseRelease(response);
    }

    wknet::http::SessionClose(session);
    return status;
}
```

## Build

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64
```

Output: `src/wknetlib/<Platform>/<Configuration>/wknetlib.lib`. Details: [Build](https://x500x.github.io/wknet/en/build/).

## Documentation

| Entry | Link |
|-------|------|
| Docs (English) | https://x500x.github.io/wknet/en/ |
| Docs (中文) | https://x500x.github.io/wknet/ |
| First request | https://x500x.github.io/wknet/en/first-request/ |
| Capability matrix | https://x500x.github.io/wknet/en/capability-matrix/ |
| API overview | https://x500x.github.io/wknet/en/api/overview/ |
| GitHub Wiki | https://github.com/x500x/wknet/wiki |

**docsite** is the single source of truth; Wiki syncs one-way from `docsite:` commits.

## License

[MIT](LICENSE)

## Acknowledgements

Special thanks to [sheep-programmer](https://github.com/sheep-programmer) for contributions to this library.
