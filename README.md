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

## 📖 项目简介

wknet 是一个纯内核态的 HTTP/HTTPS 客户端库，专为 Windows 内核驱动开发设计。项目从底层开始构建，实现了内核可用的客户端协议栈：HTTP/1.1、HTTP/2、WebSocket，以及 TLS 1.2/1.3 握手、记录保护和证书验证；默认安全策略和显式兼容能力在下文明确列出。

### ✨ 核心特点

- **🔒 纯内核态实现**：不依赖 WinHTTP、WinINet、SChannel 等用户态组件
- **🌐 WSK 网络传输**：使用 Windows Sockets Kernel (WSK)，通过 opaque `transport::Transport*` 服务统一明文与 TLS 字节流
- **🔐 CNG/BCrypt 密码学**：使用内核态 CNG (Cryptography Next Generation) 进行加密操作，支持 TLS 1.2/1.3 握手
- **📡 明确的能力矩阵**：支持 HTTP/1.1、HTTP/2（含 h2c 明文升级）、WebSocket、TLS 1.2/1.3 的客户端主路径，并把默认启用能力与显式兼容能力分开记录
- **🔄 连接池管理**：内置连接池，支持连接复用、空闲超时、并发保护和自动管理
- **⚡ 异步操作**：支持异步请求，带并发保护和 Workspace 隔离，避免阻塞内核线程
- **🎯 单一产品 API**：公开面仅包含 `wknet::http` / `wknet::websocket` / `wknet::crypto` / `wknet::codec`
- **🛡️ 证书验证**：支持证书锁定（Certificate Pinning）、信任锚（Trust Anchor）、SPKI 哈希验证和 TLS 1.3 签名方案校验
- **📦 响应编码**：支持 `Content-Encoding: gzip/deflate/br/compress/zstd/dcz/aes128gcm/exi/pack200-gzip/identity`；EXI 覆盖无外部 Schema 的 EXI 1.0，Pack200 覆盖 Java 5–8 稳定格式；HTTP/1.1 `Transfer-Encoding` 支持 `chunked/gzip/deflate/compress` 链式解码
- **🧱 堆内存管理**：响应聚合默认不设低位总量硬顶（`MaxResponseBytes=0`），按需使用堆内存增长；使用 `HeapObject<T>` / `HeapArray<T>` 统一管理堆内存，高频缓冲常驻 Workspace

### 协议能力账本

wknet 的公开能力按类别列账，避免把“没有实现”“默认关闭”“安全拒绝”和“实现策略”混在一起。

**已实现 / 已验证能力**

| 协议 | 当前可用能力 |
|------|--------------|
| HTTP/1.1 | `Content-Length`、库生成 chunked、`BodyCreateStream`/`HttpRequestSetBodySource` 真流式请求体、请求 trailer（chunked 路径）、`Expect: 100-continue`、TRACE 显式 opt-in、Range/条件请求 typed helper、响应 `Transfer-Encoding` 链（`chunked`/`gzip`/`deflate`/`compress`）、close-delimited 响应、HEAD/101/无 body 状态码、中间 1xx 跳过、chunked trailer 校验与只读 API、`206`/`Content-Range` 只读解析、RFC 3986 相对 redirect、CONNECT 方法构建、HTTPS CONNECT 代理、明文 HTTP over proxy absolute-form、session 显式开启的 HTTP/1.1 pipeline（默认关闭，FIFO 响应绑定） |
| HTTP/2 | TLS ALPN、h2c prior knowledge / Upgrade、SETTINGS（含 `ENABLE_CONNECT_PROTOCOL`）、HEADERS/CONTINUATION、DATA body source、请求/响应 trailers、显式 per-request PRIORITY、显式 `SendPing`、session 显式开启的后台 PING 保活（默认关闭）、GOAWAY/RST 可重试语义、WINDOW_UPDATE、HPACK、header block 语义校验、HPACK header-list/table-size 限制、活动 stream 表、`BeginRequest`/`ReceiveResponse(streamId)` 两阶段接口、RFC 8441 extended CONNECT DATA tunnel、高层连接池 HTTP/2 多活动流复用 |
| WebSocket | ws/wss 握手、Accept 常量时间校验、自定义 opening handshake headers、文本/二进制发送、空消息、分片发送（`wknet::websocket::SendContinuation`）、接收分片回调（`ReceiveOptions.OnMessage`）、控制帧校验、自动 Pong、Ping/Pong/CloseEx、selected subprotocol 查询、跨片 UTF-8 校验、默认聚合完整消息、默认自动选择 RFC 8441 WebSocket over HTTP/2（`wss` offer `h2,http/1.1`，可用 `Http11Only` 强制 HTTP/1.1） |
| TLS 与证书 | TLS 1.2/1.3、TLS 1.3 标准 cipher suite、TLS 1.2 ECDHE/DHE 与兼容档 RSA key exchange、AES-GCM/AES-CBC/ChaCha20-Poly1305、X25519/X448/NIST P curves/FFDHE、RSA-PSS/RSA-PKCS1/ECDSA/Ed25519/Ed448 signature scheme、SNI、ALPN、PSK/session ticket、0-RTT、被动 KeyUpdate、record padding、客户端证书（mTLS）、OCSP stapling 解析、证书链重排和校验、Name Constraints、certificatePolicies、IDNA、OCSP/CRL DER 撤销证据校验、撤销 provider callback、SPKI pin |
| Pack200 | Java 5–8 稳定格式 `150.7`/`160.1`/`170.1`/`171.0`；支持裸/gzip、多 segment、class/file/bytecode、自定义 attribute layout（class/field/method/code）、overflow index、常量池与 BCI relocation；输出语义等价 JAR；真实语料带 SHA-256/provenance |
| EXI | W3C EXI 1.0 Second Edition 无外部 Schema 流；支持四种 alignment、Options、保真项、内建 XML Schema 类型、`xsi:type`/`xsi:nil`；输出 Infoset 等价 XML；外部 Schema/strict grammar 返回 `STATUS_NOT_SUPPORTED` |

**默认关闭 / 需显式开启**

这些能力已经实现，但默认不开启；它们不是“未实现”。

| 能力 | 开启方式 / 说明 |
|------|-----------------|
| `Expect: 100-continue` | 通过 `SendFlagExpectContinue` 显式开启 |
| TRACE 方法 | 通过 `SendFlagAllowTrace` 显式开启；body、trailer 与敏感头仍拒绝 |
| HTTP/1.1 pipeline | 通过 `SessionConfig.EnableHttp11Pipeline=true` 显式开启；`Http11PipelineMaxDepth`/`Http11PipelineMethodMask` 控制深度与方法，默认仅 `GET`/`HEAD`/`OPTIONS` |
| h2c prior knowledge / Upgrade | 通过 `SendOptions.Http2CleartextMode` 显式开启；默认不走明文 HTTP/2 |
| HTTP/2 后台 PING 保活 | 通过 session `Http2KeepAlive.Enabled=true` 显式开启；idle、interval、ACK timeout 可配置 |
| HTTP/2 per-request priority | 通过 `SendOptions.Http2Priority` / `HttpSendOptions.Http2Priority` 指向 priority 描述 |
| WebSocket permessage-deflate | 通过 `ConnectConfig.PerMessageDeflate.Enable=true` 显式开启；默认不协商 |
| TLS 1.2 RSA key exchange / CBC / SHA-1 签名 | 已实现但默认关闭；必须使用 `CompatibilityExplicit` policy 并分别开启对应兼容开关 |
| TLS 1.2 真重协商 | 通过 `CompatibilityExplicit` + `EnableTls12Renegotiation` 显式开启；次数由 `MaxTls12Renegotiations` 限制 |
| TLS 1.3 0-RTT | 已实现但默认关闭；必须启用 early data，且调用方显式声明请求 replay-safe |
| TLS 1.3 post-handshake client auth | 默认关闭；开启后走 mTLS 回调，私钥不进入库 |
| 强撤销要求 | 通过 `RequireRevocationCheck` 开启；查不到调用方提供或 provider 返回的可验证 OCSP/CRL DER 证据时 fail-closed |

**安全拒绝 / 策略约束**

这些是有意的安全或协议策略，不表示缺少实现。

| 行为 | 处理 |
|------|------|
| 用户手写请求 `Transfer-Encoding` / `TE` | 拒绝；请求 framing 由库生成和校验 |
| HTTP/1.1 request trailer | 仅允许 chunked 请求路径 |
| HTTP `br` Transfer-Encoding | 拒绝；`br` 仅作为 `Content-Encoding` 支持 |
| HTTP/2 `PUSH_PROMISE` | server push 禁用，收到后视为协议错误 |
| WebSocket 服务端返回未请求扩展 | 拒绝；permessage-deflate 仅在显式启用并成功协商时使用 |
| WebSocket 握手 redirect / 401 / 407 | 不自动跟随或认证，返回 `STATUS_NOT_SUPPORTED` |
| TLS 1.3 到 TLS 1.2 | 不做握手内自动降级；只有可验证的版本协商证据才允许上层显式重连 1.2 |
| 证书主机名 | IP literal 只匹配 iPAddress SAN；域名不回退 CN |
| HTTPS redirect 到 HTTP | 默认拒绝降级 |
| RFC 9111 cache | 提供显式内存内内核缓存 API；支持 fresh hit、验证、`Vary`、private/shared 规则、unsafe method 失效、Range/206 partial 合并 |

**明确未实现 / 非目标**

这些能力当前不提供；已经实现但默认关闭的能力只记录在上一节，不放在这里。

| 能力 | 当前结论 |
|------|----------|
| HTTP 入站 request parser / server role | 非目标；当前项目定位为客户端协议栈 |
| 磁盘持久化 HTTP cache | 非目标；RFC 9111 cache 为显式内存内 NonPaged 对象，不跨重启持久化 |
| HTTP/2 复杂本地 priority tree 调度 | 非目标；不维护本地依赖树，不实现带宽调度器 |
| 除 `permessage-deflate` 外的 WebSocket extensions | 非目标；不协商其它扩展 |
| 在线 OCSP/CRL 抓取 | 非目标；调用方通过外部 trust/cert/revocation 数据或已缓存条目驱动强撤销判定 |
| HTTP/3 / QUIC | 规划中；在完整门禁通过前 `Auto` 不启用 |

**实现策略和信任模型**

- 传输层主路径使用 WSK；TLS/HTTP/证书校验按内核自实现路线推进。
- 密码学优先使用内核态 CNG/BCrypt；ChaCha20-Poly1305、AES-CCM、X25519、X448、FFDHE、Ed25519/Ed448 验签等能力由内核内软件实现补齐。
- 不把 WinHTTP、WinINet、SChannel 作为内核主路径。
- 库层不硬编码系统 CA；信任锚、CA 包、撤销缓存和 pin 由调用方显式提供。

自动 redirect 默认拒绝 HTTPS 到 HTTP 降级；跨 scheme/host/port redirect 会清理 `Authorization`、`Cookie` 和 `Proxy-Authorization`；301/302 仅默认把 POST 改写为 GET，303 除 HEAD 外改写为 GET，307/308 保留方法和 body。reused stale 连接失败只对 `GET`、`HEAD`、`OPTIONS` 等安全/幂等请求自动 fresh retry，不会自动重放 POST/PUT/PATCH/DELETE。

close-delimited HTTP/1.x 响应和 `101 Switching Protocols` 升级响应不会回到普通 HTTP 连接池。同步 HTTP、WebSocket、TLS 和证书验证路径要求在 `PASSIVE_LEVEL` 调用。TLS ALPN 结果必须来自客户端 offer 列表；TLS1.2 选择只有在 TLS1.3 路径取得可验证的版本协商证据后才允许进行，不能把证书错误、ALPN mismatch、网络超时或解密失败当作 TLS1.2-only 结论。TLS 1.3 0-RTT 默认关闭；即使启用，也必须由调用方显式标记 replay-safe，否则返回 `STATUS_NOT_SUPPORTED` 且不发送 early data。
证书主机校验中，IP literal 只匹配 iPAddress SAN，不回退到 dNSName 或 CN。

---

## 🚀 快速开始

### 📋 环境要求

| 组件 | 版本要求 |
|------|---------|
| 操作系统 | Windows 10/11 或 Windows Server 2016+ |
| Visual Studio | 2022 或更高版本 |
| Windows SDK | 10.0.19041.0 或更高 |
| Windows Driver Kit (WDK) | 与 SDK 版本匹配 |

### 📦 安装与构建

#### step1：编译成静态库

1. **克隆仓库**
   ```bash
   git clone https://github.com/x500x/wknet.git
   cd wknet
   ```

2. **使用 Visual Studio 构建**
   
   打开 `wknet.sln`，选择配置和平台：
   
   | 配置 | 说明 |
   |------|------|
   | Debug | 调试版本，包含调试符号 |
   | Release | 发布版本，优化性能 |
   
   | 平台 | 说明 |
   |------|------|
   | x64 | 64 位 Intel/AMD 处理器 |
   | ARM64 | ARM 64 位处理器 |
   
   然后按 `Ctrl+Shift+B` 构建解决方案。

3. **使用命令行构建**
   ```powershell
   # 构建 wknetlib 的全部内核 ABI（x64、ARM64）
   pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1
   
   # 只构建单个 ABI
   pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
   
   # 脚本会在构建前检查对应 ABI 的 MSVC/WDK 工具链
   
   # Debug 版本
   msbuild wknet.sln /p:Configuration=Debug /p:Platform=x64
   
   # Release 版本
   msbuild wknet.sln /p:Configuration=Release /p:Platform=x64
   ```

4. **获取库文件**
   
   构建完成后，库文件位于：
   ```
   <Platform>/<Configuration>/wknetlib.lib
   ```

#### step2：集成到你的项目

1. **包含头文件**
   ```cpp
   // 总头文件入口（推荐）
   #include <wknet/Wknet.h>
   ```

2. **链接库文件**
   在项目属性中添加：
   - 附加包含目录：`$(SolutionDir)include`
   - 附加库目录：`$(SolutionDir)src\wknetlib\$(Platform)\$(Configuration)\`
   - 附加依赖项：`wknetlib.lib`

3. **配置项目依赖**
   - 将 `wknetlib` 项目添加到你的解决方案
   - 设置项目依赖关系，确保先编译 `wknetlib`

---

## 📚 API 概览

wknet 常用入口命名空间：

| 命名空间 | 用途 | 适用场景 |
|--------|---------|---------|
| `wknet::http` | HTTP 客户端 API | 大多数应用场景，快速开发 |
| `wknet::websocket` | WebSocket 客户端 API | ws/wss 收发（头文件 `websocket/WebSocket.h`） |
| `wknet::crypto` / `wknet::codec` | 公共密码学与编解码 API | 协议外复用与直接编解码 |

> ⚠️ WebSocket 的所有调用在 `wknet::websocket` 命名空间（如 `wknet::websocket::Connect`/`wknet::websocket::SendText`/`wknet::websocket::Receive`/`wknet::websocket::Close`），但会话仍是 `wknet::http::Session`。

### 架构层次

```
┌─────────────────────────────────────────────────────────────┐
│                      产品 API (wknet::http)                        │
│  简洁接口、自动资源管理、适合大多数应用场景                      │
├─────────────────────────────────────────────────────────────┤
│                      内部会话层 (wknet::session)                       │
│  精细控制、性能优化、支持自定义测试                              │
├─────────────────────────────────────────────────────────────┤
│                    传输适配层 (wknet::transport)              │
│  opaque Transport services | WSK/TLS | ProxyConnect         │
├─────────────────────────────────────────────────────────────┤
│                    协议实现层                                 │
│  HTTP/1.1 | HTTP/2 (HPACK) | WebSocket | TLS 1.2/1.3        │
├─────────────────────────────────────────────────────────────┤
│                    基础设施层                                 │
│  WSK 网络传输 | CNG/BCrypt 密码学 | 连接池                    │
└─────────────────────────────────────────────────────────────┘
```

详细 API 参考见 **[项目 Wiki](https://github.com/x500x/wknet/wiki)** 与 **[在线文档站](https://x500x.github.io/wknet/)**。

### 🔥 高层 API 示例

```cpp
#include <wknet/Wknet.h>

// 简单的 HTTP GET 请求
NTSTATUS SimpleHttpGet() {
    // 创建会话
    wknet::http::Session* session = nullptr;
    NTSTATUS status = wknet::http::SessionCreate(&session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 发送 GET 请求
    wknet::http::Response* response = nullptr;
    status = wknet::http::GetEx(session, "http://example.com/api", 22, nullptr, nullptr, &response);
    
    if (NT_SUCCESS(status)) {
        // 获取状态码
        ULONG statusCode = wknet::http::ResponseStatusCode(response);
        
        // 获取响应体
        const UCHAR* body = wknet::http::ResponseBody(response);
        SIZE_T bodyLength = wknet::http::ResponseBodyLength(response);
        
        // 处理响应...
        
        // 释放响应
        wknet::http::ResponseRelease(response);
    }

    // 关闭会话
    wknet::http::SessionClose(session);
    return status;
}
```

### 🔧 底层 API 示例

```cpp
#include <wknet/Wknet.h>

// 精细控制的 HTTPS 请求
NTSTATUS AdvancedHttpsRequest(net::WskClient& wskClient) {
    // 创建会话（带 TLS 配置）
    SessionHandle session = nullptr;
    SessionOptions sessionOptions = {};
    sessionOptions.Tls.CertificatePolicy = CertificatePolicy::Verify;
    sessionOptions.Tls.MinVersion = TlsVersion::Tls13;
    
    NTSTATUS status = SessionCreate(&wskClient, &sessionOptions, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 创建请求
    RequestHandle request = nullptr;
    status = HttpRequestCreate(session, &request);
    if (!NT_SUCCESS(status)) {
        SessionClose(session);
        return status;
    }

    // 配置请求
    const char* url = "https://api.example.com/data";
    HttpRequestSetUrl(request, url, strlen(url));
    HttpRequestSetMethod(request, HttpMethod::Get);
    HttpRequestSetHeader(request, "User-Agent", 10, "wknet/1.0", 14);

    // 发送请求
    ResponseHandle response = nullptr;
    status = HttpSendSync(session, request, nullptr, &response);
    
    if (NT_SUCCESS(status)) {
        // 获取响应视图
        ResponseView view = {};
        ResponseGetView(response, &view);
        
        // 处理响应...
        
        ResponseRelease(response);
    }

    // 清理资源
    HttpRequestRelease(request);
    SessionClose(session);
    return status;
}
```

### 🔌 WebSocket 示例（`wknet::websocket`）

```cpp
#include <wknet/Wknet.h>

NTSTATUS WebSocketEcho() {
    wknet::http::Session* session = nullptr;
    NTSTATUS status = wknet::http::SessionCreate(&session);
    if (!NT_SUCCESS(status)) return status;

    wknet::websocket::WebSocket* ws = nullptr;             // 注意：WebSocket 句柄在 `wknet::websocket` 命名空间
    status = wknet::websocket::Connect(session, "wss://echo.example/ws", 21, &ws);
    if (NT_SUCCESS(status)) {
        wknet::websocket::SendText(ws, "hello", 5);

        wknet::websocket::Message msg = {};
        if (NT_SUCCESS(wknet::websocket::Receive(ws, &msg)) && msg.Type == wknet::websocket::MsgType::Text) {
            // 使用 msg.Data / msg.DataLength（在下次收/关之前有效）
        }
        wknet::websocket::Close(ws);                        // 全双工时序：勿与同句柄新 I/O 并发
    }
    wknet::http::SessionClose(session);
    return status;
}
```

> 分片发送用 `wknet::websocket::SendContinuation`；接收分片回调用 `wknet::websocket::ReceiveOptions.OnMessage`。

---

## 🏗️ 项目结构

```
wknet/
├── include/wknet/                    # 仅稳定公共 API
│   ├── Wknet.h                       # 伞头
│   ├── http/                         # wknet::http
│   ├── websocket/                    # wknet::websocket
│   ├── crypto/                       # wknet::crypto
│   ├── codec/                        # wknet::codec
│   └── test/                         # WKNET_USER_MODE_TEST 窄测试钩子
├── src/wknetlib/                     # 内核静态库实现
│   ├── rtl/                          # 堆、Trace、文本、URL
│   ├── net/                          # WSK 生命周期与套接字
│   ├── crypto/                       # CNG 与软件密码学
│   ├── tls/                          # TLS 1.2/1.3 与证书校验
│   ├── codec/                        # Content-Encoding、EXI、Pack200
│   ├── transport/                    # opaque Transport、WSK/TLS、代理 CONNECT
│   ├── http1/ / http2/ / ws/        # 协议层
│   ├── session/                      # 会话、连接池、HTTP/WS 编排
│   └── http_api/                     # 公共 API 薄桥
├── src/wknettest/                    # 内核测试驱动与公共 API 样例
├── tests/                            # 用户态协议与 API 测试
└── tools/                            # pwsh 构建脚本
│       └── samples/                 # 示例代码
├── tests/                            # 测试代码
├── docs/                             # 计划与审计文档
├── docsite/                          # MkDocs 在线文档源
├── certs/                            # 证书相关
└── tools/                            # 工具脚本
```

---

## 📖 文档

完整文档已迁移到 **GitHub Wiki** 与**在线文档站**（中英双语，依据实际代码编写）：

- 📚 **[项目 Wiki](https://github.com/x500x/wknet/wiki)** — 能力账本、架构、HTTP/1.1、HTTP/2 & HPACK、WebSocket、TLS 与证书、密码学、产品 API、传输层、连接池、异步、内存、NTSTATUS、Cookbook、FAQ、路线图、术语表等。
- 🌐 **[在线文档站](https://x500x.github.io/wknet/)** — 同源 MkDocs Material 站，支持全文搜索与暗色模式。

| 主题 | 链接 |
|------|------|
| 能力账本 | [Capability Matrix](https://github.com/x500x/wknet/wiki/Capability-Matrix) |
| 产品 API（http/websocket/crypto/codec） | [High-Level API](https://github.com/x500x/wknet/wiki/High-Level-API) |
| 内部层（session/http1/http2/tls/net） | [Low-Level API](https://github.com/x500x/wknet/wiki/Low-Level-API) |
| TLS 与证书 | [TLS & Certificates](https://github.com/x500x/wknet/wiki/TLS-and-Certificates) |
| NTSTATUS 错误码 | [NTSTATUS Reference](https://github.com/x500x/wknet/wiki/NTSTATUS-Reference) |

---

## 🔧 配置选项

### 会话配置

```cpp
wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();

// 响应缓冲区大小（默认 0 表示不限制，按需使用堆内存增长）
config.MaxResponseBytes = 2 * 1024 * 1024;  // 2 MiB

// 请求构造缓冲区（默认 16 KiB；大请求体可按需增大）
config.RequestBufferBytes = 96 * 1024;

// 连接池容量（默认 8）
config.PoolCapacity = 16;

// 每主机最大连接数（默认 2）
config.MaxConnsPerHost = 4;

// 空闲超时（默认 30 秒）
config.IdleTimeoutMs = 60000;  // 60 秒

// HTTP 代理（显式配置；HTTPS 走 CONNECT，明文 HTTP 走 absolute-form）
SOCKADDR_STORAGE proxyAddress = {};
// 填充 proxyAddress 为代理地址...
config.Proxy.Enabled = true;
config.Proxy.Address = proxyAddress;
config.Proxy.Authority = "proxy.example:8080";
config.Proxy.AuthorityLength = sizeof("proxy.example:8080") - 1;
config.Proxy.AuthHeader = "Basic ...";      // 可选，仅发给代理
config.Proxy.AuthHeaderLength = sizeof("Basic ...") - 1;

// 响应缓冲池类型（默认 NonPaged；内核路径当前要求 NonPaged）
config.ResponsePool = wknet::http::PoolType::NonPaged;

// TLS 配置
config.Tls.MinVersion = wknet::http::TlsVersion::Tls13;
config.Tls.MaxVersion = wknet::http::TlsVersion::Tls13;
config.Tls.Certificate = wknet::http::CertPolicy::Verify;
config.Tls.HandshakeTimeoutMs = 120000;  // TLS 握手超时（默认 120 秒）
```

### 连接策略

```cpp
wknet::http::SendOptions* options = nullptr;
wknet::http::SendOptionsCreate(&options);

// 连接策略
options->ConnectionPolicy = wknet::http::ConnPolicy::ReuseOrCreate;  // 复用或新建（默认）
options->ConnectionPolicy = wknet::http::ConnPolicy::ForceNew;       // 强制新建
options->ConnectionPolicy = wknet::http::ConnPolicy::NoPool;         // 不进连接池

// 地址族
options->Family = wknet::http::AddressFamily::Any;                   // 系统默认
options->Family = wknet::http::AddressFamily::Ipv4;                  // 仅 IPv4
options->Family = wknet::http::AddressFamily::Ipv6;                  // 仅 IPv6
wknet::http::SendOptionsRelease(options);
```

---

## 🧪 测试

### 运行测试

```powershell
# 运行已构建的用户态协议测试
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_frame_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_frame_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\hpack_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_crypto_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_interop_matrix_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_api_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'

# 本地 TLS 互通矩阵：只使用 127.0.0.1；OpenSSL/BoringSSL 缺失时会明确 SKIP
pwsh -NoLogo -NoProfile -File .\tests\integration\tls_matrix.ps1 -Configuration Debug -Platform x64

# 构建库和示例驱动
msbuild wknet.sln /m /restore /p:Configuration=Debug /p:Platform=x64
```

### 测试文件

| 测试文件 | 测试内容 |
|---------|---------|
| `http_parser_tests.cpp` | HTTP 解析器 |
| `hpack_tests.cpp` | HTTP/2 HPACK 编解码 |
| `http2_frame_tests.cpp` | HTTP/2 帧处理 |
| `http2_client_tests.cpp` | HTTP/2 客户端测试 |
| `tls_crypto_tests.cpp` | TLS 密码学向量和 key exchange |
| `tls_handshake_tests.cpp` | TLS ClientHello/握手编码解析 |
| `tls_record_tests.cpp` | TLS 记录协议 |
| `tls_interop_matrix_tests.cpp` | TLS 能力/策略/互通矩阵声明 |
| `tests/integration/tls_matrix.ps1` | 本地 OpenSSL/BoringSSL 回环互通矩阵 |
| `websocket_frame_tests.cpp` | WebSocket 帧处理 |
| `http_api_tests.cpp` | 产品 HTTP API 测试 |
| `high_level_api_tests.cpp` | 高层 API 集成测试 |
| `websocket_client_tests.cpp` | WebSocket 客户端测试 |

---

## ⚠️ 错误处理

项目使用 Windows NTSTATUS 错误码。详细说明请参考 [NTSTATUS 错误码参考](docsite/ntstatus-reference.md)。

### 常见错误码

| NTSTATUS | 描述 | 处理建议 |
|----------|------|----------|
| `STATUS_SUCCESS` | 操作成功 | - |
| `STATUS_INVALID_PARAMETER` | 参数无效 | 检查输入参数 |
| `STATUS_INSUFFICIENT_RESOURCES` | 资源不足 | 减少并发请求或增加资源 |
| `STATUS_IO_TIMEOUT` | 操作超时 | 增加超时时间或检查网络 |
| `STATUS_CONNECTION_DISCONNECTED` | 连接断开 | 重试请求 |
| `STATUS_TRUST_FAILURE` | 证书信任失败 | 检查证书配置 |

### 错误处理示例

```cpp
NTSTATUS status = wknet::http::GetEx(session, url, urlLength, nullptr, nullptr, &response);
if (!NT_SUCCESS(status)) {
    switch (status) {
    case STATUS_IO_TIMEOUT:
        // 超时处理：重试或报告错误
        DbgPrint("Request timed out\n");
        break;
    case STATUS_TRUST_FAILURE:
        // 证书错误：检查证书配置
        DbgPrint("Certificate verification failed\n");
        break;
    case STATUS_CONNECTION_DISCONNECTED:
        // 连接断开：重新连接
        DbgPrint("Connection lost, retrying...\n");
        break;
    default:
        // 其他错误：记录日志
        DbgPrint("Request failed: 0x%08X\n", status);
        break;
    }
}
```

---

## 🎯 最佳实践

### 1. 资源管理

```cpp
// ✅ 正确：确保在所有路径上释放资源
NTSTATUS DoRequest(wknet::http::Session* session) {
    wknet::http::Response* response = nullptr;
    NTSTATUS status = wknet::http::GetEx(session, url, urlLen, nullptr, nullptr, &response);
    
    // 即使失败也要释放可能已分配的响应
    if (NT_SUCCESS(status)) {
        // 处理响应...
    }
    
    wknet::http::ResponseRelease(response);  // 接受 nullptr，可无条件调用
    return status;
}

// ❌ 错误：失败时未释放响应
NTSTATUS DoRequestWrong(wknet::http::Session* session) {
    wknet::http::Response* response = nullptr;
    NTSTATUS status = wknet::http::GetEx(session, url, urlLen, nullptr, nullptr, &response);
    if (!NT_SUCCESS(status)) {
        return status;  // 泄漏！response 可能非空
    }
    // ...
    wknet::http::ResponseRelease(response);
    return status;
}
```

### 2. 连接复用

```cpp
// ✅ 正确：使用连接池复用连接
wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
config.PoolCapacity = 16;        // 增加池容量
config.MaxConnsPerHost = 4;      // 增加每主机连接数
config.IdleTimeoutMs = 120000;   // 延长空闲超时

// ❌ 避免：在所有请求上强制新建连接
wknet::http::SendOptions* options = nullptr;
wknet::http::SendOptionsCreate(&options);
options->ConnectionPolicy = wknet::http::ConnPolicy::ForceNew;
wknet::http::SendOptionsRelease(options);
```

### 3. 异步操作

```cpp
// ✅ 正确：使用异步避免阻塞
wknet::http::AsyncOp* op = nullptr;
wknet::http::AsyncGetEx(session, url, urlLen, nullptr, nullptr, &op);
wknet::http::AsyncWait(op, 30000);  // 等待 30 秒

// 处理响应...
wknet::http::AsyncRelease(op);
// 驱动卸载路径：wknet::http::Destroy();

// ❌ 避免：在内核线程中长时间同步等待
wknet::http::GetEx(session, url, urlLen, nullptr, nullptr, &response);  // 可能阻塞很久
```

---

## 📊 性能优化

### 连接池配置

```cpp
// 根据应用需求调整连接池参数
config.PoolCapacity = 32;           // 增加池容量
config.MaxConnsPerHost = 8;         // 增加每主机连接数
config.IdleTimeoutMs = 120000;      // 延长空闲超时
```

### 缓冲区管理

```cpp
// 响应缓冲区（0 表示不限制）
config.MaxResponseBytes = 4 * 1024 * 1024;  // 4 MiB

// 请求构造缓冲区，需容纳 HTTP/1.1 请求行、请求头和请求体
config.RequestBufferBytes = 96 * 1024;

// 单次发送覆盖响应上限
wknet::http::SendOptions* options = nullptr;
wknet::http::SendOptionsCreate(&options);
options->MaxResponseBytes = 0;  // 0 表示不设置调用方响应体上限
wknet::http::SendOptionsRelease(options);
```

---

## 🔐 安全考虑

### TLS 配置

```cpp
// 推荐：使用 TLS 1.3
config.Tls.MinVersion = wknet::http::TlsVersion::Tls13;
config.Tls.MaxVersion = wknet::http::TlsVersion::Tls13;

// 证书验证
config.Tls.Certificate = wknet::http::CertPolicy::Verify;

// TLS 握手超时（默认 120 秒）
config.Tls.HandshakeTimeoutMs = 120000;

// 自定义证书存储
wknet::http::CertificateStore* store = nullptr;
NTSTATUS status = wknet::http::CertificateStoreCreate(nullptr, &store);
config.Tls.Store = store;
```

### TLS 1.3 安全增强

项目已实现以下 TLS 1.3 安全加固：

- **签名方案校验**：严格校验服务器证书签名算法，拒绝弱签名方案
- **降级保护**：防止 TLS 1.3 到 TLS 1.2 的协议降级攻击
- **PSK/HRR 校验**：TLS 1.3 ticket 绑定签发时间、SNI、ALPN、cipher 和版本；HelloRetryRequest 后重新计算 PSK binder
- **0-RTT 策略**：默认关闭；启用时必须由调用方声明请求 replay-safe
- **密钥清零**：会话结束后安全清零所有密钥材料
- **信任锚校验**：验证证书链到可信根的完整性

### 证书锁定

```cpp
// 使用证书锁定增强安全性
wknet::http::CertificateTrustAnchor anchor = {};
anchor.SubjectName = rootCertSubject;
anchor.SubjectNameLength = rootCertSubjectLen;
RtlCopyMemory(anchor.SubjectPublicKeySha256, rootSpkiHash, 32);
anchor.MatchSubjectPublicKey = true;

wknet::http::CertificatePin pin = {};
pin.HostName = "example.com";
pin.HostNameLength = 11;
RtlCopyMemory(pin.LeafSubjectPublicKeySha256, leafSpkiHash, 32);

// 创建证书存储
wknet::http::CertificateStoreOptions storeOptions = {};
storeOptions.TrustAnchors = &anchor;
storeOptions.TrustAnchorCount = 1;
storeOptions.Pins = &pin;
storeOptions.PinCount = 1;

wknet::http::CertificateStore* store = nullptr;
NTSTATUS status = wknet::http::CertificateStoreCreate(&storeOptions, &store);

// 应用到会话
config.Tls.Store = store;

// SessionClose 后释放调用方持有的证书库
wknet::http::CertificateStoreClose(store);
```

### ALPN 协议协商

```cpp
// 设置 ALPN 协议（用于 HTTP/2 协商）
config.Tls.Alpn = "h2";
config.Tls.AlpnLength = 2;

// 或者同时支持 HTTP/1.1 和 HTTP/2
// session 会根据 PreferHttp2 与显式 Alpn 生成内部协商列表
```

---

## 🛠️ 开发规范

### 代码风格

- 使用 C++17 特性，但遵循内核限制
- **无异常**、**无 RTTI**，避免直接 `new/delete`，优先使用项目内堆对象封装或 API 释放函数
- 使用 `namespace`、类、RAII、轻量模板
- 所有函数标记 `noexcept`
- 使用 SAL 注解（`_In_`、`_Out_`、`_Must_inspect_result_` 等）

### 提交规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

```
feat: 添加新功能
fix: 修复 bug
docs: 文档更新
style: 代码格式调整
refactor: 代码重构
test: 测试相关
chore: 构建/工具相关
```

---

## 🤝 贡献指南

欢迎贡献代码！请遵循以下步骤：

1. **Fork** 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'feat: Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 **Pull Request**

### 贡献要求

- 遵循项目代码风格
- 添加必要的测试
- 更新相关文档
- 确保所有测试通过

---

## 📄 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

---

## 🔗 相关资源

- [Windows Driver Kit (WDK)](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [Windows Sockets Kernel (WSK)](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/windows-sockets-kernel)
- [Cryptography Next Generation (CNG)](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-features)

---

## 📞 联系方式

如有问题或建议，请通过以下方式联系：

- 提交 [Issue](https://github.com/x500x/http/issues) 到项目仓库
- 查看项目文档和示例代码
- 参考相关技术文档

---

## 🙏 致谢

感谢所有为项目做出贡献的开发者！

---

<div align="center">

**[⬆ 回到顶部](#wknet)**

</div>
