<div align="center">

# wknet

**面向 Windows 内核驱动的纯内核态 HTTP/HTTPS/WebSocket 客户端库**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%20Kernel-0078d4.svg)](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
[![WDK: 10+](https://img.shields.io/badge/WDK-10%2B-green.svg)](https://docs.microsoft.com/en-us/windows-hardware/drivers/develop/)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)

[English](README_en.md) | 简体中文

</div>

---

## 定位

wknet 在内核里发起出站 HTTP(S) 与 WebSocket。传输主路径是 **WSK**，密码学主路径是内核态 **CNG/BCrypt**；不依赖 WinHTTP、WinINet 或 SChannel。

公共 API 仅四个命名空间：`wknet::http` · `wknet::websocket` · `wknet::crypto` · `wknet::codec`。

## 特点

- 纯内核态客户端协议栈：HTTP/1.1 · HTTP/2 · HTTP/3（QUIC v1）· WebSocket · TLS 1.2/1.3
- 单一产品 API；Session 统一编排连接池、重定向、代理、异步与协议选择
- 默认安全：证书校验、主机名不回退 CN、HTTPS→HTTP redirect 默认拒绝、Trace 默认 Off
- 信任锚 / CA 包 / pin / 撤销证据由**调用方**提供；库不内置系统 CA
- 堆句柄与 Workspace；同步路径要求 `PASSIVE_LEVEL`

## 能力摘要

完整四类账本见文档站 [能力边界](https://x500x.github.io/wknet/capability-matrix/)（已实现 / 默认关 / 安全拒绝 / 非目标）。

| 类别 | 摘要 |
|------|------|
| 已实现 | HTTP/1.1–3、WebSocket、TLS 1.2/1.3、证书校验与 pin、连接池、异步、多种 Content-Encoding |
| 默认关 | pipeline、h2c、H2 PING 保活、0-RTT、permessage-deflate、TLS 兼容套件、强撤销等 |
| 安全拒绝 | 手写请求 TE、H2 server push、未协商 WS 扩展、HTTPS→HTTP 降级等 |
| 非目标 | HTTP 服务端、在线 OCSP 抓取、QUIC v2 / 迁移 / WebTransport / WS over H3 等 |

HTTP/3 默认 **Auto**：首次 HTTPS 走 TCP，从**已认证**响应学习精确 `h3` Alt-Svc，后续优先 H3。

## 最小示例

```cpp
#include <wknet/Wknet.h>

NTSTATUS SimpleGet()
{
    wknet::http::Response* response = nullptr;

    // 会话无关入口：库内部创建并管理会话
    NTSTATUS status = wknet::http::Get("https://example.com/", &response);
    if (NT_SUCCESS(status) && response != nullptr) {
        ULONG code = wknet::http::ResponseStatusCode(response);
        const UCHAR* body = wknet::http::ResponseBody(response);
        SIZE_T len = wknet::http::ResponseBodyLength(response);
        UNREFERENCED_PARAMETER(code);
        UNREFERENCED_PARAMETER(body);
        UNREFERENCED_PARAMETER(len);
        wknet::http::ResponseRelease(response);
    }

    return status;
}
```

## 构建

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Release -Platform x64
```

产物：`src/wknetlib/<Platform>/<Configuration>/wknetlib.lib`。环境与集成步骤见 [构建](https://x500x.github.io/wknet/build/)。

## 文档

| 入口 | 链接 |
|------|------|
| 文档站（中文） | https://x500x.github.io/wknet/ |
| 文档站（English） | https://x500x.github.io/wknet/en/ |
| 第一个请求 | https://x500x.github.io/wknet/first-request/ |
| 能力边界 | https://x500x.github.io/wknet/capability-matrix/ |
| API 总览 | https://x500x.github.io/wknet/api/overview/ |
| GitHub Wiki | https://github.com/x500x/wknet/wiki |

完整文档以 **docsite** 为唯一源；Wiki 由 `docsite:` 提交单向同步。

## 许可

[MIT](LICENSE)

## 致谢

特别感谢[sheep-programmer](https://github.com/sheep-programmer)为这个库的发展做出的贡献
